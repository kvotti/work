"""
Нормализация, Router, SessionStore, Formatter.
"""
import os
import tempfile
import unittest
from unittest import mock

import helpers
from helpers import event
import formatter
from formatter import format_rdp_event
from models import RDP_FAILED, RDP_LOGIN, RDP_LOGOFF, RDPEvent
from normalize import normalize_event
from state import SessionStore


class NormalizeTest(unittest.TestCase):

    def test_port(self):
        self.assertEqual(normalize_event(event(4625, IpPort="0")).port, 0)
        self.assertEqual(normalize_event(event(4625, IpPort="51234")).port, 51234)
        self.assertIsNone(normalize_event(event(4625, IpPort="-")).port)
        self.assertIsNone(normalize_event(event(4625)).port)

    def test_user_key(self):
        for name in ("user01", "USER01", "user01@example.local", "EXAMPLE\\user01"):
            ev = normalize_event(event(4624, TargetUserName=name, TargetDomainName="EXAMPLE"))
            self.assertEqual(ev.user_key, "user01", name)

    def test_linked_logon_id(self):
        self.assertIsNone(normalize_event(event(4624, TargetLinkedLogonId="0x0")).linked_logon_id)
        self.assertEqual(
            normalize_event(event(4624, TargetLinkedLogonId="0x7C09BC037")).linked_logon_id,
            "0x7c09bc037",
        )

    def test_elevated_token(self):
        self.assertTrue(normalize_event(event(4624, ElevatedToken="%%1842")).elevated_token)
        self.assertFalse(normalize_event(event(4624, ElevatedToken="%%1843")).elevated_token)
        self.assertIsNone(normalize_event(event(4624)).elevated_token)

    def test_session_events_use_account_fields(self):
        ev = normalize_event(event(4778, AccountName="user01", AccountDomain="EXAMPLE",
                                   LogonID="0x1", ClientAddress="LOCAL"))

        self.assertEqual(ev.user, "EXAMPLE\\user01")
        self.assertEqual(ev.logon_id, "0x1")
        self.assertIsNone(ev.ip)
        self.assertTrue(ev.ip_is_local)

    def test_bad_event_id(self):
        self.assertIsNone(normalize_event({"EventID": "abc"}))
        self.assertIsNone(normalize_event({}))


class RouterTest(unittest.TestCase):

    def setUp(self):
        self.router = helpers.make_router(default_thread_id=999)

    def route(self, host):
        return self.router.route(RDPEvent(RDP_LOGIN, host, "u", "t"))

    def test_topics_by_server_type(self):
        self.assertEqual(self.route("TS1.example.local").thread_id, 111)
        self.assertEqual(self.route("DC1.example.local").thread_id, 222)

    def test_server_thread_overrides_topic(self):
        self.assertEqual(self.route("VIP1.example.local").thread_id, 333)

    def test_case_and_short_name(self):
        self.assertEqual(self.route("ts1.EXAMPLE.local").thread_id, 111)
        self.assertEqual(self.route("TS1").thread_id, 111)

    def test_unknown_host_default(self):
        self.assertEqual(self.route("PC-99.example.local").thread_id, 999)

    def test_unknown_host_drop(self):
        router = helpers.make_router(default_thread_id=999, unknown_host_mode="drop")

        self.assertIsNone(router.route(RDPEvent(RDP_LOGIN, "PC-99", "u", "t")))

    def test_missing_config(self):
        from router import Router

        router = Router.from_file("/nonexistent/rdp_servers.json", default_thread_id=999)

        self.assertEqual(router.route(RDPEvent(RDP_LOGIN, "TS1", "u", "t")).thread_id, 999)

    def test_host_info(self):
        self.assertEqual(self.router.host_info("WEB1"),
                         {"type": "admin", "nla_failure_heuristic": False})
        self.assertEqual(self.router.host_info("TS1")["nla_failure_heuristic"], True)
        self.assertIsNone(self.router.host_info("PC-99"))

    def test_examples_are_ignored(self):
        # Ключи с "_" в боевом конфиге - примеры
        self.assertIsNone(self.router.host_info("_comment"))


class SessionStoreTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "sessions.json")

    def tearDown(self):
        self.dir.cleanup()

    def test_survives_restart(self):
        store = SessionStore(self.path)
        store.register("ts1", "0x201", ["0x200"], user="EXAMPLE\\user01", client="PC-01")

        restored = SessionStore(self.path)
        session = restored.find("ts1", "0x200")

        self.assertEqual(session["session_id"], "0x201")
        self.assertEqual(session["client"], "PC-01")

    def test_remove_drops_all_linked_ids(self):
        store = SessionStore(self.path)
        session = store.register("ts1", "0x201", ["0x200"])
        store.remove(session)

        self.assertIsNone(SessionStore(self.path).find("ts1", "0x200"))
        self.assertIsNone(store.find("ts1", "0x201"))

    def test_hosts_are_separate(self):
        store = SessionStore(None)
        store.register("ts1", "0x1", [])

        self.assertIsNone(store.find("dc1", "0x1"))

    def test_ttl_and_limit(self):
        store = SessionStore(None, ttl=-1)
        store.register("ts1", "0x1", [])
        store.register("ts1", "0x2", [])
        self.assertIsNone(store.find("ts1", "0x1"))

        store = SessionStore(None, max_sessions=2)
        for i in range(5):
            store.register("ts1", f"0x{i}", [])

        self.assertEqual(len(store.sessions), 2)
        self.assertIsNotNone(store.find("ts1", "0x4"))
        self.assertIsNone(store.find("ts1", "0x0"))

    def test_corrupted_file(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("{not json")

        self.assertEqual(SessionStore(self.path).sessions, {})


class FormatterTest(unittest.TestCase):

    def test_client_line(self):
        text = format_rdp_event(RDPEvent(RDP_LOGIN, "TS1", "EXAMPLE\\user01", "t",
                                         source_ip="192.0.2.10", client_workstation="PC-01"))

        self.assertIn("💻 Client: PC-01", text)

    def test_no_client_line_without_client(self):
        text = format_rdp_event(RDPEvent(RDP_LOGIN, "TS1", "EXAMPLE\\user01", "t"))

        self.assertNotIn("Client", text)

    def test_probable_logoff_is_marked(self):
        text = format_rdp_event(RDPEvent(RDP_LOGOFF, "TS1", "u", "t", confidence="probable"))

        self.assertIn("Не подтверждено", text)

    def test_failed_mention_on_separate_line(self):
        event = RDPEvent(RDP_FAILED, "TS1", "u", "2026-10-08 10:00:00")

        with mock.patch.object(formatter, "FAILED_MENTION", "@admin"):
            self.assertTrue(format_rdp_event(event).endswith("🕐 Time: 2026-10-08 10:00:00\n@admin"))

        with mock.patch.object(formatter, "FAILED_MENTION", ""):
            self.assertTrue(format_rdp_event(event).endswith("🕐 Time: 2026-10-08 10:00:00"))


if __name__ == "__main__":
    unittest.main()
