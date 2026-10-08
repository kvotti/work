import json
import os
import re
import socket
import time
import urllib.parse
import urllib.request

from engine import CorrelationEngine
from formatter import format_rdp_event
from normalize import normalize_event
from router import router_from_env
from state import SessionStore


LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 1516

# Как часто проверять удерживаемые RDP_LOGIN, когда событий нет
TICK_INTERVAL = 1.0

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
TELEGRAM_PROXY = os.getenv("TELEGRAM_PROXY")

if TELEGRAM_PROXY:
    proxy_handler = urllib.request.ProxyHandler({
        "http": TELEGRAM_PROXY,
        "https": TELEGRAM_PROXY,
    })
    telegram_opener = urllib.request.build_opener(proxy_handler)
else:
    telegram_opener = urllib.request.build_opener()


def send_telegram(text, thread_id=None):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] Telegram не настроен: TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID")
        return False

    url = (
        f"https://api.telegram.org/bot"
        f"{TELEGRAM_BOT_TOKEN}/sendMessage"
    )

    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "disable_web_page_preview": True,
    }

    if thread_id:
        data["message_thread_id"] = int(thread_id)

    encoded = urllib.parse.urlencode(data).encode()

    try:
        request = urllib.request.Request(url, data=encoded)

        with telegram_opener.open(request, timeout=10) as response:
            result_json = json.loads(response.read().decode())

        if not result_json.get("ok"):
            print(f"[!] Telegram error: {result_json}")
            return False

        return True

    except Exception as e:
        print(f"[!] Telegram connection error: {e}")
        return False


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

        send_telegram(text, route.thread_id)


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

    global router, engine
    router = router_from_env()
    engine = CorrelationEngine(
        sessions=SessionStore(os.getenv("SESSIONS_PATH", "/state/sessions.json")),
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
