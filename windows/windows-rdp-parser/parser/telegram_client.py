import os
import threading
import time
from collections import deque
from dataclasses import dataclass

import requests


TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
TELEGRAM_PROXY = os.getenv("TELEGRAM_PROXY")

# Telegram: не больше ~20 сообщений в минуту в одну группу
# (темы группы считаются вместе) -> пауза 3 с между сообщениями.
MIN_INTERVAL = float(os.getenv("TELEGRAM_MIN_INTERVAL", "3"))
QUEUE_SIZE = int(os.getenv("TELEGRAM_QUEUE_SIZE", "500"))

MAX_RETRIES = 3          # сетевые ошибки и 5xx
MAX_RATE_LIMITS = 10     # подряд полученные 429 на одно сообщение
BACKOFF = 5.0            # сек, удваивается с каждой попыткой

# Прокси: http://host:port или https://host:port (TLS до самого прокси).
# urllib.request не умеет TLS до прокси (схему https:// игнорирует и шлёт
# CONNECT открытым текстом), поэтому используется requests/urllib3 2.x.
# trust_env=False: переменные HTTP(S)_PROXY окружения не подмешиваются.
telegram_session = requests.Session()
telegram_session.trust_env = False

if TELEGRAM_PROXY:
    telegram_session.proxies = {
        "http": TELEGRAM_PROXY,
        "https": TELEGRAM_PROXY,
    }


@dataclass
class SendResult:
    ok: bool
    retry_after: float | None = None    # 429: через сколько повторить
    retryable: bool = False             # сеть / 5xx: можно повторить
    error: str = ""


# ------------------------------------------------------------
# Один запрос sendMessage
# ------------------------------------------------------------

_not_configured_reported = False


def send_telegram(text, thread_id=None) -> SendResult:
    global _not_configured_reported

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        if not _not_configured_reported:
            print("[!] Telegram не настроен: TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID")
            _not_configured_reported = True

        return SendResult(ok=False, error="not configured")

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

    try:
        response = telegram_session.post(url, data=data, timeout=10)
    except requests.exceptions.ProxyError as e:
        return SendResult(ok=False, retryable=True, error=f"proxy: {_strip_token(e)}")
    except requests.exceptions.RequestException as e:
        return SendResult(ok=False, retryable=True, error=f"connection: {_strip_token(e)}")

    try:
        body = response.json()
    except ValueError:
        body = {}

    if response.status_code == 429:
        retry_after = body.get("parameters", {}).get("retry_after", 30)
        return SendResult(ok=False, retry_after=float(retry_after), error=f"429 {body}")

    if response.status_code != 200:
        error = body or response.text[:200]
        return SendResult(ok=False, retryable=response.status_code >= 500,
                          error=f"{response.status_code} {error}")

    if not body.get("ok"):
        return SendResult(ok=False, error=str(body))

    return SendResult(ok=True)


def _strip_token(e):
    # В тексте исключений requests есть URL с токеном бота
    text = str(e)
    if TELEGRAM_BOT_TOKEN:
        text = text.replace(TELEGRAM_BOT_TOKEN, "***")
    return text


# ------------------------------------------------------------
# Очередь отправки
#
# Detection Engine не ждёт Telegram: сообщения кладутся в очередь,
# отдельный поток отправляет их не чаще MIN_INTERVAL, при 429 ждёт
# retry_after, при сетевых ошибках повторяет. При переполнении
# очереди отбрасываются самые старые сообщения, после разгрузки
# отправляется одно уведомление о потерях.
# ------------------------------------------------------------

class TelegramSender:

    def __init__(self, send=send_telegram, min_interval=MIN_INTERVAL,
                 queue_size=QUEUE_SIZE, notice_thread_id=None,
                 sleep=time.sleep, clock=time.monotonic):
        self.send = send
        self.min_interval = min_interval
        self.queue_size = queue_size
        self.notice_thread_id = notice_thread_id
        self.sleep = sleep
        self.clock = clock

        self.queue = deque()
        self.cond = threading.Condition()
        self.last_sent = None
        self.dropped = 0     # вытеснены из переполненной очереди
        self.failed = 0      # не отправлены после всех повторов

    def submit(self, text, thread_id=None):
        with self.cond:
            if len(self.queue) >= self.queue_size:
                self.queue.popleft()
                self.dropped += 1

            self.queue.append((text, thread_id))
            self.cond.notify()

    def start(self):
        threading.Thread(target=self.run_forever, name="telegram-sender", daemon=True).start()

    def run_forever(self):
        while True:
            with self.cond:
                while not self.queue and not self.lost():
                    self.cond.wait()

            try:
                self.run_once()
            except Exception as e:
                print(f"[!] Telegram sender error: {e!r}")
                self.sleep(BACKOFF)

    def lost(self):
        return self.dropped + self.failed

    def next_message(self):
        with self.cond:
            if self.queue:
                text, thread_id = self.queue.popleft()
                return text, thread_id, 0

            lost = self.lost()

            if not lost:
                return None

            self.dropped = self.failed = 0

        return (
            f"⚠️ Пропущено уведомлений: {lost}\n"
            "Превышен лимит Telegram или очередь отправки переполнена. "
            "События сохранены в logs/raw.",
            self.notice_thread_id,
            lost,
        )

    def run_once(self):
        """
        Отправляет одно сообщение из очереди (с паузой и повторами).
        Возвращает False, если отправлять нечего.
        """

        message = self.next_message()

        if message is None:
            return False

        text, thread_id, notice_lost = message
        retries = rate_limits = 0

        while True:
            self.wait_interval()
            result = self.send(text, thread_id)
            self.last_sent = self.clock()

            if result.ok:
                return True

            if result.retry_after is not None and rate_limits < MAX_RATE_LIMITS:
                rate_limits += 1
                print(f"[!] Telegram 429: повтор через {result.retry_after:.0f} с")
                self.sleep(result.retry_after + 1)
                continue

            if result.retryable and retries < MAX_RETRIES:
                retries += 1
                print(f"[!] Telegram: {result.error}; повтор {retries}/{MAX_RETRIES}")
                self.sleep(BACKOFF * 2 ** (retries - 1))
                continue

            if result.error != "not configured":
                print(f"[!] Telegram: сообщение не отправлено: {result.error}")

                # Неотправленное уведомление о потерях не плодит
                # новых: его счётчик возвращается для следующей попытки.
                with self.cond:
                    self.failed += notice_lost or 1

            return True

    def wait_interval(self):
        if self.last_sent is None:
            return

        delay = self.last_sent + self.min_interval - self.clock()

        if delay > 0:
            self.sleep(delay)
