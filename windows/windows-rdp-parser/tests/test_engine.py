"""
Сценарии Detection Engine на синтетических событиях.
Значения полей повторяют реальные события из логов.
"""
import unittest

import helpers
from helpers import event, run
from models import RDP_DISCONNECT, RDP_FAILED, RDP_LOGIN, RDP_LOGOFF, RDP_RECONNECT


ZERO_GUID = "{00000000-0000-0000-0000-000000000000}"
USER = dict(TargetUserName="user01", TargetDomainName="EXAMPLE")


def nla_logon(time="2026-10-08 10:00:00", **fields):
    return event(4624, time=time, **{
        **USER, "LogonType": "3", "IpAddress": "192.0.2.10", "IpPort": "0",
        "WorkstationName": "PC-01", "AuthenticationPackageName": "NTLM",
        "TargetLogonId": "0x100", **fields})


def rdp_logon(logon_id, linked="0x0", elevated="%%1843", guid="{11111111-0000-0000-0000-000000000000}",
              time="2026-10-08 10:00:03", **fields):
    return event(4624, time=time, **{
        **USER, "LogonType": "10", "IpAddress": "192.0.2.10", "IpPort": "0",
        "WorkstationName": "TS1", "TargetLogonId": logon_id, "TargetLinkedLogonId": linked,
        "ElevatedToken": elevated, "LogonGuid": guid, **fields})


def session_event(event_id, logon_id, session="RDP-Tcp#5", address="192.0.2.10",
                  time="2026-10-08 11:00:00", host="TS1.example.local"):
    return event(event_id, host=host, time=time, AccountName="user01", AccountDomain="EXAMPLE",
                 LogonID=logon_id, SessionName=session, ClientName="PC-01", ClientAddress=address)


def logoff(logon_id, host="TS1.example.local", time="2026-10-08 18:00:00"):
    return event(4647, host=host, time=time, TargetLogonId=logon_id, **USER)


def failure(logon_type="3", port="0", ip="192.0.2.10", host="TS1.example.local", **fields):
    return event(4625, host=host, **{
        **USER, "LogonType": logon_type, "IpAddress": ip, "IpPort": port,
        "WorkstationName": "PC-01", "AuthenticationPackageName": "NTLM",
        "Status": "0xc000006d", "SubStatus": "0xc000006a", **fields})


class LoginTest(unittest.TestCase):

    def setUp(self):
        self.engine = helpers.make_engine()

    def test_admin_linked_pair_gives_one_login_with_session_id(self):
        # Повышенный токен первым: в сообщении LogonId неповышенного,
        # на который потом ссылаются 4778/4779/4647.
        out = run(self.engine,
                  nla_logon(),
                  rdp_logon("0x200", linked="0x201", elevated="%%1842"),
                  rdp_logon("0x201", linked="0x200", elevated="%%1843", guid=ZERO_GUID))

        self.assertEqual([e.event_type for e in out], [RDP_LOGIN])
        self.assertEqual(out[0].logon_id, "0x201")
        self.assertEqual(out[0].client_workstation, "PC-01")

    def test_linked_pair_in_reverse_order(self):
        out = run(self.engine,
                  rdp_logon("0x201", linked="0x200", elevated="%%1843", guid=ZERO_GUID),
                  rdp_logon("0x200", linked="0x201", elevated="%%1842"))

        self.assertEqual([(e.event_type, e.logon_id) for e in out], [(RDP_LOGIN, "0x201")])

    def test_zero_guid_login_is_not_dropped(self):
        # Раньше отбрасывался; NTLM / локальные учётки дают нулевой GUID.
        out = run(self.engine, rdp_logon("0x300", guid=ZERO_GUID))

        self.assertEqual([e.event_type for e in out], [RDP_LOGIN])

    def test_client_from_nla_within_30_seconds(self):
        out = run(self.engine, nla_logon(time="2026-10-08 10:00:00"),
                  rdp_logon("0x300", time="2026-10-08 10:00:27"))

        self.assertEqual(out[0].client_workstation, "PC-01")

    def test_no_client_from_old_nla(self):
        out = run(self.engine, nla_logon(time="2026-10-08 10:00:00"),
                  rdp_logon("0x300", time="2026-10-08 10:00:45"))

        self.assertIsNone(out[0].client_workstation)

    def test_no_client_from_other_user(self):
        out = run(self.engine, nla_logon(TargetUserName="user02"), rdp_logon("0x300"))

        self.assertIsNone(out[0].client_workstation)

    def test_unlock_or_reconnect_logon_type_7_is_silent(self):
        out = run(self.engine, rdp_logon("0x400", LogonType="7"))

        self.assertEqual(out, [])


class SessionTest(unittest.TestCase):

    def setUp(self):
        self.engine = helpers.make_engine()

    def test_reconnect_and_disconnect(self):
        out = run(self.engine,
                  rdp_logon("0x201", linked="0x200"),
                  session_event(4779, "0x201"),
                  session_event(4778, "0x201"),
                  event(4624, LogonType="7", TargetLogonId="0x500", IpAddress="192.0.2.10", **USER))

        self.assertEqual([e.event_type for e in out], [RDP_LOGIN, RDP_DISCONNECT, RDP_RECONNECT])
        self.assertEqual(out[1].client_name, "PC-01")

    def test_reconnect_via_temporary_logon(self):
        # Переподключение к отключённой сессии 0x80c через временный
        # вход 0x813 (4624/10), который закрывается через секунду.
        out = run(self.engine,
                  nla_logon(time="2026-10-08 19:10:35"),
                  rdp_logon("0x813", time="2026-10-08 19:10:37"),
                  session_event(4778, "0x80c", time="2026-10-08 19:10:38"),
                  event(4634, LogonType="10", TargetLogonId="0x813", time="2026-10-08 19:10:38", **USER))

        self.assertEqual([(e.event_type, e.logon_id) for e in out], [(RDP_RECONNECT, "0x80c")])
        self.assertEqual(out[0].client_name, "PC-01")
        self.assertIsNone(self.engine.sessions.find("ts1.example.local", "0x813"))

    def test_reconnect_4_seconds_after_temporary_logon(self):
        out = run(self.engine,
                  rdp_logon("0x813", time="2026-10-08 19:10:37"),
                  session_event(4778, "0x80c", time="2026-10-08 19:10:41"))

        self.assertEqual([e.event_type for e in out], [RDP_RECONNECT])

    def test_login_followed_by_late_reconnect_is_kept(self):
        out = run(self.engine,
                  rdp_logon("0x813", time="2026-10-08 19:10:37"),
                  session_event(4778, "0x80c", time="2026-10-08 19:10:50"))

        self.assertEqual([e.event_type for e in out], [RDP_LOGIN, RDP_RECONNECT])

    def test_reconnect_of_other_user_keeps_login(self):
        out = run(self.engine,
                  rdp_logon("0x813", time="2026-10-08 19:10:37"),
                  {**session_event(4778, "0x80c", time="2026-10-08 19:10:38"), "AccountName": "user02"})

        self.assertEqual([e.event_type for e in out], [RDP_RECONNECT, RDP_LOGIN])

    def test_login_is_held_until_tick(self):
        # Живой режим: LOGIN уходит только после LOGIN_HOLD секунд
        from helpers import normalize_event
        from engine import LOGIN_HOLD

        self.assertEqual(self.engine.process(normalize_event(rdp_logon("0x813")), now=100.0), [])
        self.assertEqual(self.engine.tick(100.0 + LOGIN_HOLD - 1), [])
        self.assertEqual([e.event_type for e in self.engine.tick(100.0 + LOGIN_HOLD)], [RDP_LOGIN])
        self.assertEqual(self.engine.tick(1000.0), [])

    def test_console_session_events_are_ignored(self):
        out = run(self.engine,
                  session_event(4778, "0x600", session="Console", address="LOCAL"),
                  session_event(4779, "0x600", session="Console", address="LOCAL"))

        self.assertEqual(out, [])


class LogoffTest(unittest.TestCase):

    def setUp(self):
        self.engine = helpers.make_engine()

    def test_logoff_of_known_session_by_any_linked_id(self):
        run(self.engine, rdp_logon("0x200", linked="0x201", elevated="%%1842"))
        out = run(self.engine, logoff("0x201"))

        self.assertEqual([(e.event_type, e.confidence) for e in out], [(RDP_LOGOFF, "confirmed")])

    def test_session_learned_from_disconnect(self):
        # Сессия открыта до рестарта: о ней узнаём из 4779.
        run(self.engine, session_event(4779, "0x700", host="DC1.example.local"))
        out = run(self.engine, logoff("0x700", host="DC1.example.local"))

        self.assertEqual([(e.event_type, e.confidence) for e in out], [(RDP_LOGOFF, "confirmed")])

    def test_unknown_session_on_user_server_is_probable(self):
        out = run(self.engine, logoff("0x800", host="TS1.example.local"))

        self.assertEqual([(e.event_type, e.confidence) for e in out], [(RDP_LOGOFF, "probable")])

    def test_unknown_session_on_admin_server_is_dropped(self):
        self.assertEqual(run(self.engine, logoff("0x800", host="DC1.example.local")), [])

    def test_unknown_session_on_unknown_server_is_dropped(self):
        self.assertEqual(run(self.engine, logoff("0x800", host="PC-99.example.local")), [])

    def test_4634_of_elevated_token_keeps_session(self):
        run(self.engine, rdp_logon("0x200", linked="0x201", elevated="%%1842"))
        run(self.engine, event(4634, LogonType="10", TargetLogonId="0x200", **USER))
        out = run(self.engine, logoff("0x201"))

        self.assertEqual([(e.event_type, e.confidence) for e in out], [(RDP_LOGOFF, "confirmed")])

    def test_4634_of_session_id_removes_session(self):
        run(self.engine, rdp_logon("0x200", linked="0x201", elevated="%%1842"))
        run(self.engine, event(4634, LogonType="10", TargetLogonId="0x201", **USER))
        out = run(self.engine, logoff("0x201"))

        self.assertEqual([e.confidence for e in out], ["probable"])


class FailureTest(unittest.TestCase):

    def setUp(self):
        self.engine = helpers.make_engine()

    def assertRdpFailed(self, *events):
        out = run(self.engine, *events)
        self.assertEqual([e.event_type for e in out], [RDP_FAILED])
        return out[0]

    def assertSilent(self, *events):
        self.assertEqual(run(self.engine, *events), [])

    def test_nla_failure(self):
        out = self.assertRdpFailed(failure())

        self.assertEqual(out.client_workstation, "PC-01")
        self.assertEqual(out.source_ip, "192.0.2.10")

    def test_nla_failure_on_admin_server(self):
        # DC тоже RDP-цель: IpPort=0 -> RDP, в тему admin.
        self.assertRdpFailed(failure(host="DC1.example.local"))

    def test_smb_failure_with_real_port(self):
        self.assertSilent(failure(port="50134", host="DC1.example.local"))

    def test_service_failure_without_address(self):
        # Сервер 1С ходит на сервер лицензирования под локальной
        # учёткой: 0xC000015B, IpAddress/IpPort "-"
        self.assertSilent(failure(ip="-", port="-", host="APP1.example.local",
                                  TargetUserName="user17", TargetDomainName="SQL1",
                                  WorkstationName="SQL1", Status="0xc000015b", SubStatus="0x0"))

    def test_missing_port_is_not_zero(self):
        self.assertSilent(failure(port="-"))

    def test_local_address(self):
        self.assertSilent(failure(ip="::1"))

    def test_connection_broker_noise(self):
        # tssdis.exe на TS: учётка = имя сервера, ::1
        self.assertSilent(failure(ip="::1", port="58888", TargetUserName="TS1",
                                  TargetDomainName="EXAMPLE", WorkstationName="TS1"))

    def test_machine_account(self):
        self.assertSilent(failure(TargetUserName="PC-01$"))

    def test_unknown_server(self):
        self.assertSilent(failure(host="PC-99.example.local"))

    def test_heuristic_disabled_for_server(self):
        self.assertSilent(failure(host="WEB1.example.local"))

    def test_logon_type_10_always_rdp(self):
        self.assertRdpFailed(failure(logon_type="10", host="WEB1.example.local"))
        self.assertRdpFailed(failure(logon_type="10", host="PC-99.example.local"))

    def test_other_logon_types_ignored(self):
        self.assertSilent(failure(logon_type="2"))



class FailureAggregationTest(unittest.TestCase):

    def setUp(self):
        self.engine = helpers.make_engine()

    def attempt(self, time, user="user01", ip="192.0.2.10", host="TS1.example.local"):
        return failure(time=time, ip=ip, host=host, TargetUserName=user)

    def test_first_failure_is_immediate(self):
        out = run(self.engine, self.attempt("2026-10-08 10:00:00"), flush=False)

        self.assertEqual([e.failure_count for e in out], [1])

    def test_brute_force_is_summarized(self):
        attempts = [self.attempt(f"2026-10-08 10:00:{s:02d}", user=f"user{s:02d}") for s in range(0, 50, 5)]
        out = run(self.engine, *attempts)

        self.assertEqual([e.failure_count for e in out], [1, 9])
        summary = out[1]
        self.assertEqual(summary.first_event_time, "2026-10-08 10:00:05")
        self.assertEqual(summary.event_time, "2026-10-08 10:00:45")
        self.assertEqual(len(summary.usernames), 9)
        self.assertIn("aggregated", summary.evidence)

    def test_summary_sent_when_window_expires(self):
        run(self.engine, self.attempt("2026-10-08 10:00:00"), self.attempt("2026-10-08 10:00:10"),
            self.attempt("2026-10-08 10:00:20"), flush=False)
        out = self.engine.tick(helpers.normalize_event(self.attempt("2026-10-08 10:01:00")).event_time.timestamp())

        self.assertEqual([(e.failure_count, e.usernames) for e in out], [(2, ["EXAMPLE\\user01"])])

    def test_continuous_attack_gives_summary_per_minute(self):
        attempts = [self.attempt(f"2026-10-08 10:{m:02d}:{s:02d}") for m in range(3) for s in range(0, 60, 10)]
        out = run(self.engine, *attempts)

        self.assertEqual(sum(e.failure_count for e in out), len(attempts))
        self.assertLessEqual(len(out), 4)

    def test_single_retry_is_not_a_summary(self):
        out = run(self.engine, self.attempt("2026-10-08 10:00:00"), self.attempt("2026-10-08 10:00:09"))

        self.assertEqual([e.failure_count for e in out], [1, 1])

    def test_different_sources_are_separate(self):
        out = run(self.engine,
                  self.attempt("2026-10-08 10:00:00", ip="192.0.2.10"),
                  self.attempt("2026-10-08 10:00:01", ip="192.0.2.11"),
                  self.attempt("2026-10-08 10:00:02", ip="192.0.2.10", host="DC1.example.local"),
                  flush=False)

        self.assertEqual(len(out), 3)

    def test_new_window_after_quiet_period(self):
        out = run(self.engine, self.attempt("2026-10-08 10:00:00"), self.attempt("2026-10-08 10:05:00"))

        self.assertEqual([e.failure_count for e in out], [1, 1])
        self.assertEqual(out[1].event_time, "2026-10-08 10:05:00")

if __name__ == "__main__":
    unittest.main()
