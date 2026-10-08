import re
from datetime import datetime

from models import NormalizedEvent


LOCAL_ADDRESSES = {"::1", "127.0.0.1", "LOCAL"}
SESSION_EVENTS = (4778, 4779)


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def get_source_ip(message):
    """
    Пытаемся достать IP источника из Message события 4624/4625.
    """

    patterns = [
        r"Сетевой адрес источника:\s*([^\r\n]+)",
        r"Адрес источника сети:\s*([^\r\n]+)",
        r"Source Network Address:\s*([^\r\n]+)",
        r"Source Network Address\s*:\s*([^\r\n]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)

        if match:
            value = match.group(1).strip()

            if value and value != "-":
                return value

    return None

def get_client_address(event):
    """
    Получает IP клиента для событий 4778/4779.
    """

    address = event.get("ClientAddress")

    if address:
        address = str(address).strip()

        if address and address not in ("-", "LOCAL"):
            return address

    return None

def get_rdp_user(event):
    username = event.get("AccountName")
    domain = event.get("AccountDomain")

    if username:
        if domain:
            return f"{domain}\\{username}"

        return username

    return "Unknown"

def get_workstation(message):
    patterns = [
        r"Имя рабочей станции:\s*([^\r\n]+)",
        r"Workstation Name:\s*([^\r\n]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)

        if match:
            value = match.group(1).strip()

            if value and value != "-":
                return value

    return None


def user_name(event):
    domain = event.get("TargetDomainName")
    username = event.get("TargetUserName")

    if username and domain:
        return f"{domain}\\{username}"

    if username:
        return username

    return "Unknown"



def get_rdp_session_id(event):
    return event.get("LogonID") or event.get("LogonId")


def clean(value):
    """
    Пустые значения и "-" из NXLog считаем отсутствующими.
    """

    if value is None:
        return None

    value = str(value).strip()

    if not value or value == "-":
        return None

    return value


def make_user_key(name):
    """
    EXAMPLE\\user01, user01@example.local, USER01 -> user01
    """

    name = clean(name) or ""
    name = name.rsplit("\\", 1)[-1]
    name = name.split("@", 1)[0]

    return name.lower()


def is_zero_hex(value):
    """
    "0x0" в TargetLinkedLogonId означает отсутствие связанной сессии.
    """

    try:
        return value is not None and int(value, 16) == 0
    except ValueError:
        return False


def parse_yes_no(value):
    """
    NXLog отдаёт Yes/No из 4624 как ссылки на сообщения:
    %%1842 = Yes, %%1843 = No.
    """

    value = (clean(value) or "").lower()

    if value in ("%%1842", "yes", "да"):
        return True

    if value in ("%%1843", "no", "нет"):
        return False

    return None


def parse_event_time(value):
    try:
        return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def parse_port(value):
    """
    None, если порт не указан ("-", пусто): отсутствующий порт
    нельзя путать с IpPort=0, на котором построена NLA-эвристика.
    """

    value = clean(value)

    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


# ------------------------------------------------------------
# Normalization
# ------------------------------------------------------------

def normalize_event(event):
    """
    Приводит JSON от NXLog к NormalizedEvent.
    Возвращает None, если EventID отсутствует или некорректен.
    """

    try:
        event_id = int(event.get("EventID", 0))
    except (TypeError, ValueError):
        return None

    if not event_id:
        return None

    hostname = event.get("Hostname", "Unknown")
    host_key = str(hostname).strip().lower()
    message = event.get("Message", "")

    if event_id in SESSION_EVENTS:
        user = get_rdp_user(event)
        target_user_name = clean(event.get("AccountName")) or ""
        logon_id = clean(get_rdp_session_id(event))
        raw_address = clean(event.get("ClientAddress"))
        ip = get_client_address(event)
    else:
        user = user_name(event)
        target_user_name = clean(event.get("TargetUserName")) or ""
        logon_id = clean(event.get("TargetLogonId"))
        raw_address = clean(event.get("IpAddress"))
        ip = raw_address or get_source_ip(message)

    linked_logon_id = clean(event.get("TargetLinkedLogonId"))

    if is_zero_hex(linked_logon_id):
        linked_logon_id = None

    logon_type = event.get("LogonType")

    return NormalizedEvent(
        event_id=event_id,
        host=hostname,
        host_key=host_key,
        host_short=host_key.split(".", 1)[0],
        event_time_raw=event.get("EventTime", "Unknown"),
        event_time=parse_event_time(event.get("EventTime")),

        user=user,
        user_key=make_user_key(target_user_name),
        target_user_name=target_user_name,

        logon_type=str(logon_type) if logon_type is not None else None,
        logon_id=logon_id.lower() if logon_id else None,
        linked_logon_id=linked_logon_id.lower() if linked_logon_id else None,
        logon_guid=(clean(event.get("LogonGuid")) or "").lower() or None,
        elevated_token=parse_yes_no(event.get("ElevatedToken")),

        ip=ip,
        ip_is_local=(raw_address or "").upper() in LOCAL_ADDRESSES,
        port=parse_port(event.get("IpPort")),
        workstation=clean(event.get("WorkstationName")) or get_workstation(message),

        auth_package=clean(event.get("AuthenticationPackageName")),
        logon_process=clean(event.get("LogonProcessName")),
        process_name=clean(event.get("ProcessName")),
        status=clean(event.get("Status") or event.get("StatusCode")),
        substatus=clean(event.get("SubStatus") or event.get("SubStatusCode")),

        session_name=clean(event.get("SessionName")),
        client_name=clean(event.get("ClientName")),

        raw=event,
    )
