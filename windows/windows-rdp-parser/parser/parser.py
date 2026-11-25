import json
import os
import re
import socket
import time

from engine import CorrelationEngine
from formatter import format_rdp_event, format_startup
from normalize import normalize_event
from router import router_from_env
from state import SessionStore
from telegram_client import TelegramSender


LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 1516

# Как часто проверять удерживаемые RDP_LOGIN, когда событий нет
TICK_INTERVAL = 1.0


# ------------------------------------------------------------
# Parser
# ------------------------------------------------------------

def parse_line(raw):
    raw = raw.strip()

    if not raw:
        return None

    # NXLog добавляет #015 в конец сообщения
    raw = re.sub(r"#015\s*$", "", raw)

    json_start = raw.find("{")

    if json_start == -1:
        print("[!] JSON не найден")
        print(raw)
        return None

    json_data = raw[json_start:].strip()

    try:
        return json.loads(json_data)

    except json.JSONDecodeError as e:
        print(f"[!] JSON parse error: {e}")
        print(f"[!] Position: {e.pos}")
        print(f"[!] Tail: {repr(json_data[-100:])}")
        return None


router = None
engine = None
sender = None


def process_event(event):

    normalized = normalize_event(event)

    if normalized is None:
        return

    deliver(engine.process(normalized, time.monotonic()))


def process_tick():
    deliver(engine.tick(time.monotonic()))


def deliver(rdp_events):

    for rdp_event in rdp_events:

        text = format_rdp_event(rdp_event)

        if text is None:
            continue

        route = router.route(rdp_event)

        if route is None:
            continue

        sender.submit(text, route.thread_id)


# ------------------------------------------------------------
# TCP server
# ------------------------------------------------------------

def handle_connection(conn, addr):

    buffer = b""
    conn.settimeout(TICK_INTERVAL)

    try:

        while True:

            try:
                data = conn.recv(65535)
            except socket.timeout:
                process_tick()
                continue

            if not data:
                break

            buffer += data

            while b"\n" in buffer:

                line, buffer = buffer.split(b"\n", 1)

                raw = line.decode(
                    "utf-8",
                    errors="replace"
                )

                event = parse_line(raw)

                if not event:
                    continue

                # Ошибка в одном событии не должна рвать соединение
                try:
                    process_event(event)
                except Exception as e:
                    print(f"[!] Event processing error: {e!r}")
                    print(f"[!] Event: {raw[:500]}")

    except Exception as e:
        print(f"[!] Connection error: {e}")

    finally:

        conn.close()


def main():

    global router, engine, sender
    router = router_from_env()
    sender = TelegramSender(notice_thread_id=router.default_thread_id)
    sender.start()
    sessions = SessionStore(os.getenv("SESSIONS_PATH", "/state/sessions.json"))
    engine = CorrelationEngine(
        sessions=sessions,
        host_info=router.host_info,
    )

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(
        (LISTEN_HOST, LISTEN_PORT)
    )

    server.listen(10)
    server.settimeout(TICK_INTERVAL)

    print(
        f"[*] Listening on "
        f"{LISTEN_HOST}:{LISTEN_PORT}"
    )

    # Порт занят, парсер готов принимать события: сообщаем в тему
    # по умолчанию (TELEGRAM_THREAD_ID), что он работает.
    sender.submit(
        format_startup(
            servers=len(router.servers),
            sessions=len(sessions.sessions),
        ),
        router.default_thread_id,
    )

    while True:

        try:
            conn, addr = server.accept()
        except socket.timeout:
            process_tick()
            continue

        handle_connection(
            conn,
            addr
        )


if __name__ == "__main__":
    main()
