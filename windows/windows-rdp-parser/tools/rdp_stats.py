"""
Офлайн-статистика по сырым логам для проверки правил RDP-корреляции.

Запуск:
  python rdp_stats.py /logs/raw > rdp_stats.txt
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

ROOT = sys.argv[1] if len(sys.argv) > 1 else "/logs/raw"
LOCAL_IPS = {"", "-", "::1", "127.0.0.1"}
FOLLOW_WINDOW = 60  # сек: ищем 4624/10 или 4624/7 после 4624/3


def ts(e):
    try:
        return datetime.strptime(e["EventTime"], "%Y-%m-%d %H:%M:%S").timestamp()
    except (KeyError, ValueError):
        return None


def user_key(e):
    return str(e.get("TargetUserName", "")).split("@")[0].lower()


def events():
    for dirpath, _, files in os.walk(ROOT):
        for name in sorted(files):
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    i = line.find("{")
                    if i < 0:
                        continue
                    try:
                        e = json.loads(re.sub(r"#015\s*$", "", line[i:].strip()))
                    except ValueError:
                        continue
                    try:
                        eid = int(e.get("EventID", 0))
                    except (TypeError, ValueError):
                        continue
                    if eid in (4624, 4625, 4634, 4647):
                        e["EventID"] = eid
                        yield e


fail_stats = Counter()
fail_port0_ips = Counter()
fail_portN_ips = Counter()
net_logons = defaultdict(list)   # (host, user) -> [(t, port0, ip)]
interactive = defaultdict(list)  # (host, user) -> [(t, logon_type)]
logoff_4647 = {}                 # (host, logon_id) -> t
logoff_4634_10 = {}              # (host, logon_id) -> t

for e in events():
    host = str(e.get("Hostname", "")).lower()
    eid = e["EventID"]
    lt = str(e.get("LogonType", ""))
    user = user_key(e)
    ip = str(e.get("IpAddress", "") or "")
    port0 = str(e.get("IpPort", "")) in ("0", "")
    t = ts(e)

    if eid == 4625 and lt == "3":
        machine = user.endswith("$")
        local = ip in LOCAL_IPS
        fail_stats[(host, "port0" if port0 else "portN",
                    e.get("AuthenticationPackageName"),
                    "machine$" if machine else "user",
                    "local" if local else "remote")] += 1
        if not machine and not local:
            (fail_port0_ips if port0 else fail_portN_ips)[(host, ip)] += 1

    elif eid == 4624 and lt == "3" and t is not None:
        if not user.endswith("$") and ip not in LOCAL_IPS:
            net_logons[(host, user)].append((t, port0, ip))

    elif eid == 4624 and lt in ("10", "7") and t is not None:
        interactive[(host, user)].append((t, lt))

    elif eid == 4647 and t is not None:
        logoff_4647[(host, str(e.get("TargetLogonId", "")).lower())] = t

    elif eid == 4634 and lt == "10" and t is not None:
        logoff_4634_10[(host, str(e.get("TargetLogonId", "")).lower())] = t

# --- 4624/3 (port0 vs portN): followed by 4624/10 or 4624/7 of the same user? ---
follow = Counter()
gaps = Counter()
for key, items in net_logons.items():
    inter = sorted(interactive.get(key, []))
    for t, port0, ip in items:
        hit = next((it for it in inter if 0 <= it[0] - t <= FOLLOW_WINDOW), None)
        label = "port0" if port0 else "portN"
        follow[(key[0], label, hit[1] if hit else "none")] += 1
        if hit and port0:
            gaps[int(hit[0] - t)] += 1

# --- 4647 -> 4634/10 delay ---
logoff_delay = Counter()
for k, t in logoff_4647.items():
    t2 = logoff_4634_10.get(k)
    logoff_delay["no 4634/10" if t2 is None else min(int(t2 - t), 999)] += 1
only_4634 = sum(1 for k in logoff_4634_10 if k not in logoff_4647)

print("=== 4625/3: (host, ipport, authpkg, account, ip) -> count ===")
for k, n in fail_stats.most_common():
    print(n, k)

print("\n=== 4625/3 user+remote, IpPort=0: top source IPs ===")
for k, n in fail_port0_ips.most_common(15):
    print(n, k)

print("\n=== 4625/3 user+remote, IpPort!=0: top source IPs ===")
for k, n in fail_portN_ips.most_common(15):
    print(n, k)

print(f"\n=== 4624/3 user+remote: followed by 4624/10|7 same user within {FOLLOW_WINDOW}s ===")
for k, n in sorted(follow.items()):
    print(n, k)

print("\n=== gap seconds 4624/3(port0) -> 4624/10|7 ===")
for k, n in sorted(gaps.items()):
    print(f"{k:>3}s: {n}")

print("\n=== delay seconds 4647 -> 4634/10 (same LogonId) ===")
for k, n in sorted(logoff_delay.items(), key=lambda x: str(x[0])):
    print(k, n)
print("4634/10 without 4647:", only_4634)
