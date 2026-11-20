import time
from collections import deque
from datetime import timedelta

from models import (
    RDP_DISCONNECT,
    RDP_FAILED,
    RDP_LOGIN,
    RDP_LOGOFF,
    RDP_RECONNECT,
    NormalizedEvent,
    RDPEvent,
)
from state import SESSION_ACTIVE, SESSION_DISCONNECTED, SessionStore


# Окна подобраны по реальным логам терминального сервера и DC (tools/rdp_stats.py):
# NLA 4624/3 -> 4624/10: медиана 2-3 с, 95% <= 6 с, максимум 27 с.
NLA_LOOKBACK = timedelta(seconds=30)
NLA_LOOKAHEAD = timedelta(seconds=2)    # точность EventTime - 1 с
CONTEXT_TTL = timedelta(seconds=60)
CONTEXT_SWEEP_EVERY = 1000

# Переподключение к отключённой сессии бывает в двух видах:
#   4778 + 4624/7                       - LOGIN не возникает;
#   4624/10 (временный вход) + 4778     - через ~1 с, временный вход
#                                         закрывается 4634/10.
# Поэтому RDP_LOGIN удерживается LOGIN_HOLD секунд: если за это время
# пришёл 4778 того же пользователя на том же сервере - это RECONNECT.
# Терминальный сервер, сутки: 25 из 51 4624/10 - временные, 4778 через
# 0-4 с (максимум 4 с); остальные 26 - настоящие, 4778 за ними нет.
LOGIN_HOLD = 10.0

# Подбор пароля: первая RDP-неудача с адреса на сервер отправляется
# сразу, повторные в течение FAIL_AGG_WINDOW секунд копятся и уходят
# одной сводкой; при продолжающейся атаке - одна сводка в минуту.
FAIL_AGG_WINDOW = 60.0


# ------------------------------------------------------------
# ContextWindow: недавние NLA-логоны (4624/3) для обогащения
# ------------------------------------------------------------

class NlaContext:

    def __init__(self, ttl=CONTEXT_TTL):
        self.ttl = ttl
        self.items = {}      # (host, user_key) -> deque[NormalizedEvent]
        self.latest = None
        self.added = 0

    def add(self, ev: NormalizedEvent):
        key = (ev.host_key, ev.user_key)
        items = self.items.setdefault(key, deque())
        items.append(ev)

        if self.latest is None or ev.event_time > self.latest:
            self.latest = ev.event_time

        self.evict(items)

        self.added += 1

        if self.added % CONTEXT_SWEEP_EVERY == 0:
            self.sweep()

    def find(self, host_key, user_key, event_time):
        """
        Последний NLA-логон того же host+user в окне
        [event_time - NLA_LOOKBACK, event_time + NLA_LOOKAHEAD].
        """

        items = self.items.get((host_key, user_key))

        if not items or event_time is None:
            return None

        for ev in reversed(items):
            if event_time - NLA_LOOKBACK <= ev.event_time <= event_time + NLA_LOOKAHEAD:
                return ev

        return None

    def evict(self, items):
        while items and self.latest - items[0].event_time > self.ttl:
            items.popleft()

    def sweep(self):
        for key in list(self.items):
            items = self.items[key]
            self.evict(items)

            if not items:
                del self.items[key]


# ------------------------------------------------------------
# Correlation Engine
# ------------------------------------------------------------

class CorrelationEngine:

    def __init__(self, sessions=None, host_info=None):
        """
        sessions  - SessionStore (по умолчанию только в памяти).
        host_info - функция host -> {"type", "nla_failure_heuristic"} | None
                    (Router.host_info). Engine знает факты о сервере,
                    но не Telegram-тему.
        """

        self.sessions = sessions or SessionStore()
        self.host_info = host_info or (lambda host: None)
        self.nla = NlaContext()
        self.pending = []    # удерживаемые RDP_LOGIN (см. LOGIN_HOLD)
        self.failures = {}   # (host, ip) -> окно агрегации RDP_FAILED

    def process(self, ev: NormalizedEvent, now=None) -> list[RDPEvent]:
        """
        now - текущее время в секундах (по умолчанию time.monotonic()).
        Сначала отдаёт удерживаемые LOGIN с истёкшим сроком, затем
        результат обработки события.
        """

        if now is None:
            now = time.monotonic()

        results = self.tick(now)
        results.extend(self.handle(ev, now))

        return results

    def tick(self, now=None) -> list[RDPEvent]:
        """
        Отдаёт удерживаемые RDP_LOGIN, срок которых истёк.
        Вызывать периодически, даже если новых событий нет.
        """

        if now is None:
            now = time.monotonic()

        due = [p for p in self.pending if p["deadline"] <= now]
        self.pending = [p for p in self.pending if p["deadline"] > now]
        results = [p["event"] for p in due]

        for key, window in list(self.failures.items()):
            if window["deadline"] > now:
                continue

            if window["events"]:
                results.append(failure_summary(window["events"]))

                # Атака продолжается: следующее окно начинается сразу
                self.failures[key] = new_failure_window(now)
            else:
                del self.failures[key]

        return results

    def flush(self) -> list[RDPEvent]:
        """
        Отдаёт все удерживаемые события (конец replay, остановка).
        """

        results = [p["event"] for p in self.pending]
        self.pending = []

        for window in self.failures.values():
            if window["events"]:
                results.append(failure_summary(window["events"]))

        self.failures = {}

        return results

    def handle(self, ev: NormalizedEvent, now) -> list[RDPEvent]:

        if ev.event_id == 4624:

            if ev.logon_type == "3":
                if is_nla_logon(ev):
                    self.nla.add(ev)

                return []

            if ev.logon_type == "10":
                return self.on_rdp_logon(ev, now)

            return []

        if ev.event_id == 4625:
            return self.on_logon_failure(ev, now)

        if ev.event_id in (4778, 4779):
            return self.on_session_change(ev)

        if ev.event_id == 4647:
            return self.on_logoff(ev)

        if ev.event_id == 4634:
            self.on_logon_end(ev)

        return []

    # --------------------------------------------------------
    # 4624/10: новый RDP login
    # --------------------------------------------------------

    def on_rdp_logon(self, ev, now):

        # Второе событие linked-пары (UAC split token):
        # его LogonId уже зарегистрирован первым событием.
        if self.sessions.find(ev.host_key, ev.logon_id):
            return []

        # Сессия рабочего стола работает под неповышенным токеном,
        # и 4778/4779/4647 ссылаются именно на его LogonId.
        if ev.elevated_token and ev.linked_logon_id:
            session_id = ev.linked_logon_id
        else:
            session_id = ev.logon_id

        nla = self.nla.find(ev.host_key, ev.user_key, ev.event_time)
        client = nla.workstation if nla else None

        if session_id:
            self.sessions.register(
                ev.host_key,
                session_id,
                [ev.logon_id, ev.linked_logon_id],
                user=ev.user,
                ip=ev.ip,
                client=client,
                state=SESSION_ACTIVE,
            )

        evidence = ["4624/10"]

        if ev.linked_logon_id:
            evidence.append("linked")

        if nla:
            evidence.insert(0, "4624/3")

        self.pending.append({
            "key": (ev.host_key, ev.user_key),
            "session_id": session_id,
            "deadline": now + LOGIN_HOLD,
            "event": RDPEvent(
                event_type=RDP_LOGIN,
                target_host=ev.host,
                username=ev.user,
                event_time=ev.event_time_raw,
                source_ip=ev.ip,
                logon_id=session_id,
                client_workstation=client,
                auth_package=nla.auth_package if nla else ev.auth_package,
                evidence=evidence,
            ),
        })

        return []

    def take_pending_login(self, ev):
        """
        Забирает удерживаемый LOGIN того же пользователя на том же
        сервере: это был временный вход перед переподключением.
        Его сессия не настоящая и удаляется из списка.
        """

        key = (ev.host_key, ev.user_key)
        taken = [p for p in self.pending if p["key"] == key]

        if not taken:
            return None

        self.pending = [p for p in self.pending if p["key"] != key]

        for p in taken:
            session = self.sessions.find(ev.host_key, p["session_id"])

            if session and p["session_id"] != ev.logon_id:
                self.sessions.remove(session)

        return taken[-1]["event"]

    # --------------------------------------------------------
    # 4778 / 4779: reconnect / disconnect
    # --------------------------------------------------------

    def on_session_change(self, ev):

        if not is_rdp_session(ev):
            return []

        reconnect = ev.event_id == 4778
        session_id = ev.logon_id
        login = self.take_pending_login(ev) if reconnect else None

        if ev.logon_id:
            session = self.sessions.find(ev.host_key, ev.logon_id)

            if session:
                session_id = session["session_id"]

            # Регистрируем и неизвестные сессии (открытые до рестарта),
            # чтобы последующий 4647 был подтверждён.
            self.sessions.register(
                ev.host_key,
                session_id,
                [ev.logon_id],
                user=ev.user,
                ip=ev.ip,
                client=ev.client_name,
                state=SESSION_ACTIVE if reconnect else SESSION_DISCONNECTED,
            )

        return [RDPEvent(
            event_type=RDP_RECONNECT if reconnect else RDP_DISCONNECT,
            target_host=ev.host,
            username=ev.user,
            event_time=ev.event_time_raw,
            source_ip=ev.ip,
            logon_id=ev.logon_id,
            client_name=ev.client_name,
            client_workstation=login.client_workstation if login else None,
            session_name=ev.session_name,
            evidence=(["4624/10"] if login else []) + [str(ev.event_id)],
        )]

    # --------------------------------------------------------
    # 4647: user initiated logoff
    # --------------------------------------------------------

    def on_logoff(self, ev):

        session = self.sessions.find(ev.host_key, ev.logon_id)

        if session:
            self.sessions.remove(session)

            return [RDPEvent(
                event_type=RDP_LOGOFF,
                target_host=ev.host,
                username=ev.user,
                event_time=ev.event_time_raw,
                logon_id=ev.logon_id,
                source_ip=session.get("ip"),
                client_name=session.get("client"),
                evidence=["4647", "session"],
            )]

        # Сессия неизвестна (например, открыта до рестарта контейнера).
        # На пользовательских TS консольные входы практически
        # отсутствуют, поэтому отправляем с пометкой.
        host = self.host_info(ev.host)

        if host and host["type"] == "user":
            return [RDPEvent(
                event_type=RDP_LOGOFF,
                target_host=ev.host,
                username=ev.user,
                event_time=ev.event_time_raw,
                logon_id=ev.logon_id,
                confidence="probable",
                evidence=["4647"],
            )]

        return []

    # --------------------------------------------------------
    # 4634: logon session destroyed (только очистка Registry)
    # --------------------------------------------------------

    def on_logon_end(self, ev):

        session = self.sessions.find(ev.host_key, ev.logon_id)

        # Повышенный токен linked-пары может закрыться раньше,
        # чем сама сессия, поэтому удаляем только по session_id.
        if session and session["session_id"] == ev.logon_id:
            self.sessions.remove(session)

    # --------------------------------------------------------
    # 4625: failed logon
    #
    # 4625/10 - однозначно RDP (NLA выключен).
    # 4625/3  - RDP только по NLA-эвристике (is_nla_failure)
    #           и только на серверах из rdp_servers.json,
    #           где она не отключена. Остальное - обычные
    #           сетевые неудачи (SMB, службы, 1С и т.п.).
    # --------------------------------------------------------

    def on_logon_failure(self, ev, now):

        if ev.logon_type == "10":
            evidence = ["4625/10"]

        elif ev.logon_type == "3":
            host = self.host_info(ev.host)

            if not host or not host["nla_failure_heuristic"]:
                return []

            if not is_nla_failure(ev):
                return []

            evidence = ["4625/3", "IpPort=0"]

        else:
            return []

        if is_noise_logon_failure(ev):
            return []

        failure = RDPEvent(
            event_type=RDP_FAILED,
            target_host=ev.host,
            username=ev.user,
            event_time=ev.event_time_raw,
            source_ip=ev.ip,
            client_workstation=ev.workstation,
            auth_package=ev.auth_package,
            status=ev.status,
            substatus=ev.substatus,
            evidence=evidence,
        )

        key = (ev.host_key, ev.ip or ev.user_key)
        window = self.failures.get(key)

        if window and window["deadline"] > now:
            window["events"].append(failure)
            return []

        self.failures[key] = new_failure_window(now)

        return [failure]


def new_failure_window(now):
    return {"deadline": now + FAIL_AGG_WINDOW, "events": []}


def failure_summary(events):
    """
    Одна RDP_FAILED на несколько неудач с одного адреса на один сервер.
    Одиночная неудача отдаётся как есть.
    """

    if len(events) == 1:
        return events[0]

    last = events[-1]
    usernames = list(dict.fromkeys(e.username for e in events))

    return RDPEvent(
        event_type=RDP_FAILED,
        target_host=last.target_host,
        username=usernames[0] if len(usernames) == 1 else f"учётных записей: {len(usernames)}",
        event_time=last.event_time,
        source_ip=last.source_ip,
        client_workstation=last.client_workstation,
        auth_package=last.auth_package,
        status=last.status,
        substatus=last.substatus,
        evidence=last.evidence + ["aggregated"],
        failure_count=len(events),
        usernames=usernames,
        first_event_time=events[0].event_time,
    )


# ------------------------------------------------------------
# Rules
# ------------------------------------------------------------

def is_nla_logon(ev: NormalizedEvent) -> bool:
    """
    Эмпирический признак NLA перед RDP-сессией для текущей
    инфраструктуры: 4624/3 с IpPort=0 с удалённого адреса
    (на терминальном сервере 243 из 244 таких логонов заканчиваются
    4624/10 или /7).
    Используется только для обогащения, не для детекции.
    """

    return (
        ev.event_time is not None
        and ev.port == 0
        and ev.ip is not None
        and not ev.ip_is_local
        and not ev.target_user_name.endswith("$")
    )


def is_nla_failure(ev: NormalizedEvent) -> bool:
    """
    Эмпирическая RDP-NLA эвристика для текущей инфраструктуры:
    4625/3 + удалённый IP + IpPort=0.

    При NLA аутентификацию выполняет TermService, и порт клиента
    не передаётся; у SMB/WMI/служб он настоящий или отсутствует.
    Данные (tools/rdp_stats.py, терминальный сервер + DC, 6 дней):
    14 из 14 RDP-неудач с IpPort=0, 0 из 9 SMB-неудач.
    Сервер лицензирования 1С: 1582 неудачи служебной учётки 1С
    с IpAddress/IpPort "-" - не RDP.

    Не универсальное свойство Windows: перепроверять rdp_stats.py
    при появлении новых серверов и NTLM-через-HTTP (IIS, RD Web);
    при ложных срабатываниях отключать на сервере флагом
    nla_failure_heuristic=false в rdp_servers.json.
    """

    return (
        ev.port == 0
        and ev.ip is not None
        and not ev.ip_is_local
        and not ev.target_user_name.endswith("$")
    )


def is_rdp_session(ev: NormalizedEvent) -> bool:
    """
    4778/4779 пишутся и при Fast User Switching на консоли
    (SessionName=Console, ClientAddress=LOCAL).
    """

    if ev.session_name:
        return ev.session_name.lower().startswith("rdp-tcp")

    return ev.ip is not None and not ev.ip_is_local


def is_noise_logon_failure(ev: NormalizedEvent) -> bool:
    """
    Фильтры 4625, перенесённые из прежнего format_event().
    """

    # Локальная попытка от имени самого компьютера
    if (
        ev.ip == "::1"
        and ev.user.upper().endswith(f"\\{ev.host_short.upper()}")
    ):
        return True

    # Компьютерные аккаунты
    if ev.user.endswith("$"):
        return True

    # Попытка от имени компьютера:
    # имя учётки совпадает с именем рабочей станции
    # и указан исходный TCP-порт
    if (
        ev.target_user_name
        and ev.workstation
        and ev.target_user_name.upper() == ev.workstation.upper()
        and ev.port not in (None, 0)
    ):
        return True

    return False
