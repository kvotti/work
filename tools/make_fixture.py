"""
Собирает обезличенную фикстуру для tests/ из сырых логов NXLog.

Имена пользователей, машин, домен и IP заменяются условными
(user01, PC-01, example.local, 192.0.2.x) с сохранением связей
между событиями. Реальные имена серверов и домен передаются через
файл соответствий, который не должен попадать в git (держите его в logs/):

  {
    "domain": "corp.local",
    "hosts": {"TERMSRV1": "TS1", "DC01": "DC1", "LIC01": "APP1"}
  }

Запуск из корня проекта:
  python tools/make_fixture.py tests/fixtures/events.jsonl \
      --map logs/fixture_map.json \
      --sample logs/samples.jsonl \
      --rdp logs/raw/<ip>/<дата>.log --since "2026-10-08 17:11:00" --until "2026-10-08 17:16:00"

  --sample  все события файла (например, выборка extract_samples)
  --rdp     только RDP-значимые события в окне --since/--until
            + первые --max-failures 4625 на (host, user) за весь файл

После пересборки: UPDATE_GOLDEN=1 python -m unittest discover -s tests
и просмотреть diff tests/fixtures/expected_events.json.
"""
import argparse
import ipaddress
import json
import re
from collections import Counter

KEEP = ["EventID", "Hostname", "EventTime", "LogonType", "TargetUserName",
        "TargetDomainName", "TargetLogonId", "TargetLinkedLogonId", "LogonGuid",
        "ElevatedToken", "IpAddress", "IpPort", "WorkstationName",
        "AuthenticationPackageName", "LogonProcessName", "ProcessName",
        "SubjectUserName", "Status", "SubStatus", "AccountName", "AccountDomain",
        "LogonID", "SessionName", "ClientName", "ClientAddress"]

SYSTEM = re.compile(r"^(UMFD-\d+|DWM-\d+|-)$", re.I)


def load(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            i = line.find("{")
            if i < 0:
                continue
            try:
                yield json.loads(re.sub(r"#015\s*$", "", line[i:].strip()))
            except ValueError:
                pass


def is_rdp_relevant(e):
    eid, lt = e.get("EventID"), str(e.get("LogonType"))

    return (
        eid in (4778, 4779, 4647)
        or (eid == 4624 and lt in ("10", "7"))
        or (eid == 4624 and lt == "3" and e.get("IpPort") == "0")
        or (eid == 4634 and lt == "10")
    )


def select_rdp(path, since, until, max_failures):
    failures = Counter()

    for e in load(path):
        if e.get("EventID") == 4625:
            key = (e.get("Hostname"), e.get("TargetUserName"))

            if failures[key] < max_failures:
                failures[key] += 1
                yield e

            continue

        if since <= e.get("EventTime", "") <= until and is_rdp_relevant(e):
            yield e


class Anonymizer:

    def __init__(self, domain, hosts, events):
        self.domain = domain
        self.hosts = hosts
        host_names = {h.upper() for h in hosts}
        users, clients = {}, {}

        for e in events:
            for f in ("TargetUserName", "AccountName", "SubjectUserName"):
                v = e.get(f, "").split("@")[0].split("\\")[-1]

                if v and not SYSTEM.match(v) and not v.endswith("$") and v.upper() not in host_names:
                    users.setdefault(v.lower(), f"user{len(users) + 1:02d}")

            for f in ("WorkstationName", "ClientName"):
                v = e.get(f)

                if v and v != "-" and v.upper() not in host_names:
                    clients.setdefault(v.lower(), f"PC-{len(clients) + 1:02d}")

        repl = [*hosts.items(), *users.items(), *clients.items(),
                (domain.split(".")[0], "EXAMPLE")]
        repl.sort(key=lambda kv: -len(kv[0]))

        self.pattern = re.compile(
            "|".join(r"(?<![\w.-])" + re.escape(k) + r"(?![\w-])" for k, _ in repl),
            re.I,
        )
        self.lookup = {k.lower(): v for k, v in repl}
        self.ips = {}
        self.counts = (len(users), len(clients))

    def map_ip(self, v):
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return None

        if ip.is_loopback:
            return v

        return self.ips.setdefault(v, f"192.0.2.{len(self.ips) + 1}")

    def __call__(self, v):
        if not isinstance(v, str):
            return v

        ip = self.map_ip(v)

        if ip is not None:
            return ip

        v = re.sub(re.escape(self.domain), "example.local", v, flags=re.I)

        return self.pattern.sub(lambda m: self.lookup[m.group(0).lower()], v)


def main():
    args = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    args.add_argument("out")
    args.add_argument("--map", required=True, help="JSON: domain и hosts (реальное имя -> условное)")
    args.add_argument("--sample", action="append", default=[], help="включить все события файла")
    args.add_argument("--rdp", action="append", default=[], help="включить RDP-значимые события")
    args.add_argument("--since", default="")
    args.add_argument("--until", default="9999")
    args.add_argument("--max-failures", type=int, default=3)
    opts = args.parse_args()

    with open(opts.map, encoding="utf-8") as f:
        mapping = json.load(f)

    events = []

    for path in opts.sample:
        events.extend(load(path))

    for path in opts.rdp:
        events.extend(select_rdp(path, opts.since, opts.until, opts.max_failures))

    events.sort(key=lambda e: (e["EventTime"], e.get("RecordNumber", 0)))
    events = [{k: e[k] for k in KEEP if k in e} for e in events]

    anon = Anonymizer(mapping["domain"], mapping["hosts"], events)
    out = [{k: anon(v) for k, v in e.items()} for e in events]

    with open(opts.out, "w", encoding="utf-8", newline="\n") as f:
        for e in out:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    users, clients = anon.counts
    print(f"{len(out)} events; {users} users; {clients} clients; {len(anon.ips)} ips")


if __name__ == "__main__":
    main()
