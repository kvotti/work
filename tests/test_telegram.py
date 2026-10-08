"""
Очередь отправки в Telegram: пауза между сообщениями, 429, повторы,
переполнение. Сеть и реальные паузы заменены подставными функциями.
"""
import unittest

import helpers  # noqa: F401  (sys.path к parser/)
from telegram_client import MAX_RETRIES, SendResult, TelegramSender


class FakeTelegram:
    """
    Отвечает заранее заданными результатами; время идёт только через sleep().
    """

    def __init__(self, *results):
        self.results = list(results)
        self.sent = []
        self.now = 0.0
        self.sleeps = []

    def send(self, text, thread_id=None):
        self.sent.append((self.now, text, thread_id))
        return self.results.pop(0) if self.results else SendResult(ok=True)

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def clock(self):
        return self.now

    def sender(self, **kwargs):
        return TelegramSender(send=self.send, sleep=self.sleep, clock=self.clock,
                              min_interval=3.0, **kwargs)


def drain(sender):
    while sender.run_once():
        pass


class TelegramSenderTest(unittest.TestCase):

    def test_messages_are_paced(self):
        tg = FakeTelegram()
        sender = tg.sender()

        for i in range(5):
            sender.submit(f"msg{i}", 111)

        drain(sender)

        times = [t for t, _, _ in tg.sent]
        self.assertEqual([text for _, text, _ in tg.sent], [f"msg{i}" for i in range(5)])
        self.assertTrue(all(b - a >= 3.0 for a, b in zip(times, times[1:])))

    def test_rate_limit_waits_and_resends(self):
        tg = FakeTelegram(SendResult(ok=False, retry_after=17.0), SendResult(ok=True))
        sender = tg.sender()
        sender.submit("msg", 111)

        drain(sender)

        self.assertEqual([text for _, text, _ in tg.sent], ["msg", "msg"])
        self.assertIn(18.0, tg.sleeps)
        self.assertEqual(sender.lost(), 0)

    def test_network_errors_are_retried(self):
        tg = FakeTelegram(SendResult(ok=False, retryable=True, error="timeout"), SendResult(ok=True))
        sender = tg.sender()
        sender.submit("msg")

        drain(sender)

        self.assertEqual(len(tg.sent), 2)
        self.assertEqual(sender.lost(), 0)

    def test_permanent_error_is_counted_and_reported(self):
        tg = FakeTelegram(SendResult(ok=False, error="400 thread not found"))
        sender = tg.sender(notice_thread_id=999)
        sender.submit("msg", 111)

        drain(sender)

        self.assertEqual(len(tg.sent), 2)
        notice = tg.sent[-1]
        self.assertIn("Пропущено уведомлений: 1", notice[1])
        self.assertEqual(notice[2], 999)

    def test_retries_are_limited(self):
        tg = FakeTelegram(*[SendResult(ok=False, retryable=True, error="down")] * (MAX_RETRIES + 1))
        sender = tg.sender()
        sender.submit("msg")

        sender.run_once()

        self.assertEqual(len(tg.sent), MAX_RETRIES + 1)
        self.assertEqual(sender.failed, 1)

    def test_overflow_drops_oldest_and_reports(self):
        tg = FakeTelegram()
        sender = tg.sender(queue_size=3)

        for i in range(5):
            sender.submit(f"msg{i}")

        drain(sender)

        texts = [text for _, text, _ in tg.sent]
        self.assertEqual(texts[:3], ["msg2", "msg3", "msg4"])
        self.assertIn("Пропущено уведомлений: 2", texts[3])
        self.assertEqual(len(texts), 4)

    def test_failed_notice_does_not_multiply(self):
        down = SendResult(ok=False, error="400")
        tg = FakeTelegram(down, down, SendResult(ok=True))
        sender = tg.sender()
        sender.submit("msg")

        drain(sender)

        # msg (не ушло) -> уведомление (не ушло) -> уведомление (ушло)
        self.assertEqual(len(tg.sent), 3)
        self.assertIn("Пропущено уведомлений: 1", tg.sent[-1][1])
        self.assertEqual(sender.lost(), 0)

    def test_not_configured_is_silent(self):
        tg = FakeTelegram(SendResult(ok=False, error="not configured"))
        sender = tg.sender()
        sender.submit("msg")

        drain(sender)

        self.assertEqual(len(tg.sent), 1)
        self.assertEqual(sender.lost(), 0)


if __name__ == "__main__":
    unittest.main()
