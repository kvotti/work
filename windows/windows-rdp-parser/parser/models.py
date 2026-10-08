from dataclasses import dataclass, field
from datetime import datetime


# ------------------------------------------------------------
# Нормализованное событие Windows Security (вход Detection Engine)
# ------------------------------------------------------------

@dataclass
class NormalizedEvent:
    event_id: int
    host: str                       # как пришло в Hostname (для отображения)
    host_key: str                   # lower FQDN (для сопоставления)
    host_short: str                 # lower короткое имя
    event_time_raw: str             # EventTime как есть (для отображения)
    event_time: datetime | None

    user: str                       # DOMAIN\user или "Unknown"
    user_key: str                   # lower sAMAccountName без домена / UPN-суффикса
    target_user_name: str           # TargetUserName / AccountName как есть

    logon_type: str | None = None
    logon_id: str | None = None     # TargetLogonId (4624/4634/4647) или LogonID (4778/4779)
    linked_logon_id: str | None = None
    logon_guid: str | None = None
    elevated_token: bool | None = None   # 4624: %%1842 = Yes, %%1843 = No

    ip: str | None = None           # IpAddress / ClientAddress как есть, без "-"
    ip_is_local: bool = False       # ::1, 127.0.0.1, LOCAL
    port: int | None = None         # None - порт не указан ("-")
    workstation: str | None = None  # WorkstationName

    auth_package: str | None = None
    logon_process: str | None = None
    process_name: str | None = None
    status: str | None = None
    substatus: str | None = None

    session_name: str | None = None  # 4778/4779: RDP-Tcp#N / Console
    client_name: str | None = None   # 4778/4779

    raw: dict = field(default_factory=dict, repr=False)


# ------------------------------------------------------------
# Результат Detection Engine (вход Formatter / Router)
# ------------------------------------------------------------

RDP_LOGIN = "RDP_LOGIN"
RDP_RECONNECT = "RDP_RECONNECT"
RDP_DISCONNECT = "RDP_DISCONNECT"
RDP_LOGOFF = "RDP_LOGOFF"
RDP_FAILED = "RDP_FAILED"


@dataclass
class RDPEvent:
    event_type: str
    target_host: str
    username: str
    event_time: str

    source_ip: str | None = None
    logon_id: str | None = None
    client_workstation: str | None = None
    client_name: str | None = None
    session_name: str | None = None
    auth_package: str | None = None
    status: str | None = None
    substatus: str | None = None

    confidence: str = "confirmed"   # confirmed | probable
    evidence: list[str] = field(default_factory=list)
