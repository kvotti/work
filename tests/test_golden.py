"""
Golden-тест: полный прогон обезличенной фикстуры (реальные события
терминального сервера, DC и сервера приложений) через Engine и Router.

Если поведение изменено намеренно, пересоздать эталон:
  UPDATE_GOLDEN=1 python -m unittest discover -s tests
и просмотреть diff tests/fixtures/expected_events.json перед коммитом.
"""
import json
import os
import unittest

import helpers


EXPECTED = os.path.join(helpers.FIXTURES, "expected_events.json")


def actual_events():
    router = helpers.make_router()
    engine = helpers.make_engine(router)
    events = helpers.run(engine, *helpers.load_fixture())

    return [
        {
            "event_time": e.event_time,
            "event_type": e.event_type,
            "target_host": e.target_host,
            "username": e.username,
            "source_ip": e.source_ip,
            "client": e.client_name or e.client_workstation,
            "logon_id": e.logon_id,
            "confidence": e.confidence,
            "failure_count": e.failure_count,
            "thread_id": router.route(e).thread_id,
        }
        for e in events
    ]


class GoldenTest(unittest.TestCase):

    def test_fixture_matches_expected(self):
        actual = actual_events()

        if os.getenv("UPDATE_GOLDEN"):
            with open(EXPECTED, "w", encoding="utf-8", newline="\n") as f:
                json.dump(actual, f, ensure_ascii=False, indent=1)
                f.write("\n")

        with open(EXPECTED, encoding="utf-8") as f:
            expected = json.load(f)

        self.assertEqual(len(actual), len(expected))

        for i, (a, e) in enumerate(zip(actual, expected)):
            self.assertEqual(a, e, f"событие #{i}")


if __name__ == "__main__":
    unittest.main()
