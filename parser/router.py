import json
import os
from dataclasses import dataclass

from models import RDPEvent


# ------------------------------------------------------------
# Routing: target_host -> Telegram thread
#
# Router знает только конфигурацию серверов и темы Telegram.
# На определение RDP-события он не влияет.
# ------------------------------------------------------------

UNKNOWN_HOST_DEFAULT = "default"   # отправить в тему по умолчанию
UNKNOWN_HOST_DROP = "drop"         # не отправлять


@dataclass
class Route:
    thread_id: int | None
    server_type: str | None = None


def parse_thread_id(value):
    if value is None or value == "":
        return None

    return int(value)


class Router:

    def __init__(self, servers, topics, default_thread_id=None,
                 unknown_host_mode=UNKNOWN_HOST_DEFAULT):
        self.topics = topics
        self.default_thread_id = default_thread_id
        self.unknown_host_mode = unknown_host_mode
        self.servers = {}
        self.short_names = {}
        self.reported_unknown = set()

        for host, info in servers.items():
            key = host.strip().lower()
            self.servers[key] = info
            self.short_names.setdefault(key.split(".", 1)[0], info)

    @classmethod
    def from_file(cls, path, default_thread_id=None,
                  unknown_host_mode=UNKNOWN_HOST_DEFAULT):
        """
        Загружает rdp_servers.json. Если файла нет - все события
        идут в тему по умолчанию (поведение до появления Router).
        """

        try:
            with open(path, encoding="utf-8") as f:
                config = json.load(f)
        except FileNotFoundError:
            print(f"[!] Router: {path} не найден, все события -> тема по умолчанию")
            return cls({}, {}, default_thread_id, UNKNOWN_HOST_DEFAULT)

        topics = {
            name: parse_thread_id(thread_id)
            for name, thread_id in config.get("topics", {}).items()
            if not name.startswith("_")
        }

        servers = {}

        for host, info in config.get("servers", {}).items():
            if host.startswith("_"):
                continue

            server_type = info.get("type")

            if server_type not in topics:
                print(f"[!] Router: {host}: тип {server_type!r} отсутствует в topics")

            servers[host] = {
                "type": server_type,
                "thread_id": parse_thread_id(info.get("thread_id")),
                "nla_failure_heuristic": bool(info.get("nla_failure_heuristic", True)),
            }

        print(
            f"[*] Router: {len(servers)} серверов, "
            f"topics={topics}, unknown_host_mode={unknown_host_mode}"
        )

        return cls(servers, topics, default_thread_id, unknown_host_mode)

    def find_server(self, host):
        key = str(host).strip().lower()

        if key in self.servers:
            return self.servers[key]

        return self.short_names.get(key.split(".", 1)[0])

    def host_info(self, host):
        """
        Факты о сервере для Detection Engine:
        {"type": user | admin, "nla_failure_heuristic": bool} или None.
        Темы Telegram наружу не отдаются.
        """

        server = self.find_server(host)

        if server is None:
            return None

        return {
            "type": server["type"],
            "nla_failure_heuristic": server["nla_failure_heuristic"],
        }

    def route(self, event: RDPEvent) -> Route | None:
        """
        Возвращает Route или None, если событие отправлять не нужно.
        """

        server = self.find_server(event.target_host)

        if server is None:
            if self.unknown_host_mode == UNKNOWN_HOST_DROP:
                self.report_unknown(event.target_host, "drop")
                return None

            self.report_unknown(event.target_host, "default")
            return Route(self.default_thread_id)

        thread_id = (
            server["thread_id"]
            or self.topics.get(server["type"])
            or self.default_thread_id
        )

        return Route(thread_id, server["type"])

    def report_unknown(self, host, action):
        if host in self.reported_unknown:
            return

        self.reported_unknown.add(host)
        print(f"[!] Router: хост {host} нет в rdp_servers.json -> {action}")


def router_from_env():
    return Router.from_file(
        os.getenv("RDP_SERVERS_PATH", "/config/rdp_servers.json"),
        default_thread_id=parse_thread_id(os.getenv("TELEGRAM_THREAD_ID")),
        unknown_host_mode=os.getenv("UNKNOWN_HOST_MODE", UNKNOWN_HOST_DEFAULT),
    )
