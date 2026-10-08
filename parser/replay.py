"""
Офлайн-прогон сырых логов через Detection Engine (dry-run, без Telegram).

Запуск:
  python replay.py /logs/raw                 # текст сообщений
  python replay.py /logs/raw --json          # RDPEvent в JSON
  python replay.py logs/samples.jsonl --config ../config/rdp_servers.json
"""
import argparse
import json
import os
from dataclasses import asdict

from engine import CorrelationEngine
from formatter import format_rdp_event
from normalize import normalize_event
from parser import parse_line
from router import Router, parse_thread_id
from state import SessionStore


def iter_files(paths):
    for path in paths:
        if os.path.isdir(path):
            for dirpath, _, files in os.walk(path):
                for name in sorted(files):
                    yield os.path.join(dirpath, name)
        else:
            yield path


def iter_events(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line)

            if event:
                yield event


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("paths", nargs="+", help="файлы или каталоги с сырыми логами")
    args.add_argument("--json", action="store_true", help="печатать RDPEvent в JSON")
    args.add_argument("--config", default=os.getenv("RDP_SERVERS_PATH", "/config/rdp_servers.json"),
                      help="rdp_servers.json для показа маршрутизации")
    args.add_argument("--unknown-host-mode", default=os.getenv("UNKNOWN_HOST_MODE", "default"))
    opts = args.parse_args()

    router = Router.from_file(
        opts.config,
        default_thread_id=parse_thread_id(os.getenv("TELEGRAM_THREAD_ID")),
        unknown_host_mode=opts.unknown_host_mode,
    )

    # Список сессий только в памяти: replay не трогает /state
    engine = CorrelationEngine(
        sessions=SessionStore(path=None),
        host_info=router.host_info,
    )

    # Часы replay - время события, а не реальное время. Каждый файл
    # rsyslog - один хост за сутки, поэтому часы сбрасываются, а
    # удерживаемые RDP_LOGIN отдаются в конце каждого файла.
    for path in iter_files(opts.paths):
        now = 0.0

        for event in iter_events(path):
            normalized = normalize_event(event)

            if normalized is None:
                continue

            if normalized.event_time:
                now = max(now, normalized.event_time.timestamp())

            for rdp_event in engine.process(normalized, now):
                print_event(rdp_event, router, opts.json)

        for rdp_event in engine.flush():
            print_event(rdp_event, router, opts.json)


def print_event(rdp_event, router, as_json):

    route = router.route(rdp_event)
    target = "DROP" if route is None else f"thread={route.thread_id} type={route.server_type}"

    if as_json:
        record = asdict(rdp_event)
        record["route"] = target
        print(json.dumps(record, ensure_ascii=False))
    else:
        print(f"[route] {target}")
        print(format_rdp_event(rdp_event))
        print("-" * 40)


if __name__ == "__main__":
    main()
