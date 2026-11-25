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

        repeated = event.failure_count > 1

        if repeated:
            text = (
                f"🔴 RDP LOGIN FAILED ×{event.failure_count}\n\n"
                f"🖥 Host: {event.target_host}\n"
                f"👤 Users: {users_text(event.usernames)}\n"
            )
        else:
            text = (
                "🔴 RDP LOGIN FAILED\n\n"
                f"🖥 Host: {event.target_host}\n"
                f"👤 User: {event.username}\n"
            )

        text += (
            f"🌐 Source: {event.source_ip or 'Unknown'}\n"
            f"{client_line(event)}"
        )

        if event.status:
            text += f"❗ Status: {event.status}\n"

        if event.substatus:
            text += f"❗ Substatus: {event.substatus}\n"

        if repeated:
            text += f"🕐 Time: {event.first_event_time} – {event.event_time}"
        else:
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


def users_text(usernames, limit=5):
    shown = ", ".join(usernames[:limit])

    if len(usernames) > limit:
        shown += f" и ещё {len(usernames) - limit}"

    return shown


def probable_line(event: RDPEvent) -> str:
    if event.confidence == "confirmed":
        return ""

    return "⚠️ Не подтверждено: RDP-сессия неизвестна\n"


# ------------------------------------------------------------
# Служебные сообщения
# ------------------------------------------------------------

def format_startup(servers: int, sessions: int) -> str:
    """
    Сообщение о запуске парсера (после перезапуска контейнера тоже).
    Времени в тексте нет: в контейнере UTC, а время отправки и так
    видно в Telegram.
    """

    return (
        "✅ RDP-парсер запущен\n\n"
        f"🖥 Серверов в конфиге: {servers}\n"
        f"📋 Восстановлено сессий: {sessions}"
    )
