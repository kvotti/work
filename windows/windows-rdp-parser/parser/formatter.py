import os

from models import (
    RDP_DISCONNECT,
    RDP_FAILED,
    RDP_LOGIN,
    RDP_LOGOFF,
    RDP_RECONNECT,
    RDPEvent,
)


# Кого упоминать в сообщениях о неудачном входе
FAILED_MENTION = os.getenv("TELEGRAM_FAILED_MENTION", "")


# ------------------------------------------------------------
# Event formatting
# ------------------------------------------------------------

def format_rdp_event(event: RDPEvent) -> str | None:

    # --------------------------------------------------------
    # Successful RDP login
    # --------------------------------------------------------

    if event.event_type == RDP_LOGIN:

        return (
            "🟢 RDP LOGIN\n\n"
            f"🖥 Host: {event.target_host}\n"
            f"👤 User: {event.username}\n"
            f"🌐 Source: {event.source_ip or 'Unknown'}\n"
            f"{client_line(event)}"
            f"🆔 Logon ID: {event.logon_id or 'Unknown'}\n"
            f"🕐 Time: {event.event_time}"
        )

    # --------------------------------------------------------
    # Failed RDP login
    # --------------------------------------------------------

    if event.event_type == RDP_FAILED:

        text = (
            "🔴 RDP LOGIN FAILED\n\n"
            f"🖥 Host: {event.target_host}\n"
            f"👤 User: {event.username}\n"
            f"🌐 Source: {event.source_ip or 'Unknown'}\n"
            f"{client_line(event)}"
        )

        if event.status:
            text += f"❗ Status: {event.status}\n"

        if event.substatus:
            text += f"❗ Substatus: {event.substatus}\n"

        text += f"🕐 Time: {event.event_time}"

        if FAILED_MENTION:
            text += f"\n{FAILED_MENTION}"

        return text

    # --------------------------------------------------------
    # User initiated logoff
    # --------------------------------------------------------

    if event.event_type == RDP_LOGOFF:

        text = (
            "🔵 RDP LOGOFF\n\n"
            f"{probable_line(event)}"
            f"🖥 Host: {event.target_host}\n"
            f"👤 User: {event.username}\n"
        )

        if event.source_ip:
            text += f"🌐 Source: {event.source_ip}\n"

        text += (
            f"{client_line(event)}"
            f"🆔 Logon ID: {event.logon_id or 'Unknown'}\n"
            f"🕐 Time: {event.event_time}"
        )

        return text

    # --------------------------------------------------------
    # RDP reconnect / disconnect
    # --------------------------------------------------------

    if event.event_type in (RDP_RECONNECT, RDP_DISCONNECT):

        if event.event_type == RDP_RECONNECT:
            title = "🟡 RDP RECONNECT"
        else:
            title = "🟠 RDP DISCONNECT"

        text = (
            f"{title}\n\n"
            f"🖥 Host: {event.target_host}\n"
            f"👤 User: {event.username}\n"
        )

        if event.source_ip:
            text += f"🌐 Source: {event.source_ip}\n"

        text += client_line(event)

        if event.logon_id:
            text += f"🆔 Logon ID: {event.logon_id}\n"

        text += f"🕐 Time: {event.event_time}"

        return text

    return None


def client_line(event: RDPEvent) -> str:
    """
    Имя клиентской машины. IP за NAT / RD Gateway не идентифицирует
    клиента, поэтому показываем ClientName (4778/4779) или
    WorkstationName из NLA-логона (4624/3).
    """

    client = event.client_name or event.client_workstation

    return f"💻 Client: {client}\n" if client else ""


def probable_line(event: RDPEvent) -> str:
    if event.confidence == "confirmed":
        return ""

    return "⚠️ Не подтверждено: RDP-сессия неизвестна\n"
