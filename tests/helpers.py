"""
Общие функции для тестов.

Запуск из корня проекта:
  python -m unittest discover -s tests

В контейнере (модули парсера лежат в /app):
  docker compose run --rm -v "$PWD/tests:/app/tests:ro" parser \
    python -m unittest discover -s tests
"""
import json
import os
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(TESTS_DIR, "fixtures")
PARSER_DIR = os.path.join(TESTS_DIR, "..", "parser")

if os.path.isdir(PARSER_DIR):
    sys.path.insert(0, os.path.abspath(PARSER_DIR))

from engine import CorrelationEngine  # noqa: E402
from normalize import normalize_event  # noqa: E402
from router import Router  # noqa: E402
from state import SessionStore  # noqa: E402


SERVERS_CONFIG = os.path.join(FIXTURES, "rdp_servers.json")


def load_fixture(name="events.jsonl"):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def make_router(**kwargs):
    return Router.from_file(SERVERS_CONFIG, **kwargs)


def make_engine(router=None, sessions=None):
    router = router or make_router()

    return CorrelationEngine(
        sessions=sessions or SessionStore(path=None),
        host_info=router.host_info,
    )


def run(engine, *events):
    """
    Прогоняет сырые события (dict) через engine, возвращает RDPEvent'ы.
    """

    results = []

    for event in events:
        normalized = normalize_event(dict(event))

        if normalized is not None:
            results.extend(engine.process(normalized))

    return results


def event(event_id, host="TS1.example.local", time="2026-10-08 10:00:00", **fields):
    """
    Синтетическое событие в формате NXLog.
    """

    return {"EventID": event_id, "Hostname": host, "EventTime": time, **fields}
