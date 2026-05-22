import socket
import re
import requests
import threading

TOKEN="your_bot_token"
CHAT="your_chat_id"
PROXY = 'your_proxi_or_NULL'

TOPICS={
 "access":1,
 "security":2
}

LOGIN=re.compile(r'login failure|logged in|logged out', re.IGNORECASE)
FIREWALL=re.compile(r'filter rule changed|filter rule added|filter rule removed', re.IGNORECASE)
CRITICAL=re.compile(r'critical|error', re.IGNORECASE)


def send(msg,topic):

    try:

        print("sending telegram:", msg, flush=True)

        r = requests.post(
            f"https://api.telegram.org/{TOKEN}/sendMessage",
            json={
                "chat_id":CHAT,
                "message_thread_id":topic,
                "text":msg
            },
            proxies={
                "http": PROXY,
                "https": PROXY
            },
            timeout=5
        )

        print("telegram response:", r.status_code, r.text, flush=True)

    except Exception as e:
        print("telegram error:", e, flush=True)


def handle_client(conn, addr):

    print("connection from", addr, flush=True)

    buffer=""

    try:

        while True:

            data = conn.recv(4096)

            if not data:
                break

            buffer += data.decode(errors="ignore")

            buffer = buffer.replace("\r", "")

            while "\n" in buffer:

                line, buffer = buffer.split("\n",1)

                print("LOG:", line, flush=True)

                if LOGIN.search(line):
                    send(line, TOPICS["access"])

                elif FIREWALL.search(line) or CRITICAL.search(line):
                    send(line, TOPICS["security"])

    except Exception as e:
        print("connection error:", e, flush=True)

    finally:
        conn.close()
        print("connection closed", addr, flush=True)


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

sock.bind(("0.0.0.0",1514))
sock.listen(10)

print("parser listening on 1514", flush=True)


while True:

    conn, addr = sock.accept()

    thread = threading.Thread(
        target=handle_client,
        args=(conn, addr),
        daemon=True
    )

    thread.start()
