import json
import os
import time


# ------------------------------------------------------------
# SessionRegistry: известные RDP-сессии
#
# Ключ сессии: (host, session_logon_id).
# Для linked-пары 4624/10 (UAC split token) оба LogonId
# указывают на одну сессию, поэтому 4778/4779/4647 находят её
# по любому из них.
# ------------------------------------------------------------

SESSION_ACTIVE = "ACTIVE"
SESSION_DISCONNECTED = "DISCONNECTED"

SESSION_TTL = 7 * 24 * 3600
MAX_SESSIONS = 5000


class SessionStore:

    def __init__(self, path=None, ttl=SESSION_TTL, max_sessions=MAX_SESSIONS):
        """
        path=None - только в памяти (replay, тесты).
        """

        self.path = path
        self.ttl = ttl
        self.max_sessions = max_sessions
        self.sessions = {}   # "host|session_id" -> dict
        self.index = {}      # "host|logon_id"   -> "host|session_id"

        if path:
            self.load()

    # --------------------------------------------------------
    # Lookup / update
    # --------------------------------------------------------

    def find(self, host, logon_id):
        if not logon_id:
            return None

        key = self.index.get(make_key(host, logon_id))

        return self.sessions.get(key) if key else None

    def register(self, host, session_id, logon_ids, **fields):
        """
        Создаёт или обновляет сессию и привязывает к ней logon_ids.
        """

        key = make_key(host, session_id)
        session = self.sessions.get(key)

        if session is None:
            session = {
                "host": host,
                "session_id": session_id,
                "logon_ids": [],
                "created": time.time(),
            }
            self.sessions[key] = session

        for logon_id in [session_id, *logon_ids]:
            if logon_id and logon_id not in session["logon_ids"]:
                session["logon_ids"].append(logon_id)
                self.index[make_key(host, logon_id)] = key

        session.update({k: v for k, v in fields.items() if v is not None})
        session["last_seen"] = time.time()

        self.expire()
        self.save()

        return session

    def remove(self, session):
        key = make_key(session["host"], session["session_id"])

        if self.sessions.pop(key, None) is None:
            return

        for logon_id in session["logon_ids"]:
            self.index.pop(make_key(session["host"], logon_id), None)

        self.save()

    def expire(self):
        now = time.time()
        stale = [
            s for s in self.sessions.values()
            if now - s.get("last_seen", 0) > self.ttl
        ]

        overflow = len(self.sessions) - len(stale) - self.max_sessions

        if overflow > 0:
            stale_ids = {id(s) for s in stale}
            alive = sorted(
                (s for s in self.sessions.values() if id(s) not in stale_ids),
                key=lambda s: s.get("last_seen", 0),
            )
            stale += alive[:overflow]

        for session in stale:
            key = make_key(session["host"], session["session_id"])
            self.sessions.pop(key, None)

            for logon_id in session["logon_ids"]:
                self.index.pop(make_key(session["host"], logon_id), None)

    # --------------------------------------------------------
    # Persistence
    # --------------------------------------------------------

    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                sessions = json.load(f)
        except FileNotFoundError:
            print(f"[*] SessionStore: {self.path} не найден, начинаем с пустого списка")
            return
        except (OSError, ValueError) as e:
            print(f"[!] SessionStore: не удалось прочитать {self.path}: {e}")
            return

        for session in sessions:
            key = make_key(session["host"], session["session_id"])
            self.sessions[key] = session

            for logon_id in session["logon_ids"]:
                self.index[make_key(session["host"], logon_id)] = key

        self.expire()
        print(f"[*] SessionStore: загружено {len(self.sessions)} сессий")

    def save(self):
        if not self.path:
            return

        tmp_path = f"{self.path}.tmp"

        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(list(self.sessions.values()), f, ensure_ascii=False)

            os.replace(tmp_path, self.path)

        except OSError as e:
            print(f"[!] SessionStore: не удалось сохранить {self.path}: {e}")


def make_key(host, logon_id):
    return f"{host}|{logon_id}"
