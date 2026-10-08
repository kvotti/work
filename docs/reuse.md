# Использование кода в другом проекте

Ядро определения RDP-событий не привязано ни к Telegram, ни к rsyslog, ни к Docker. Его можно встроить в другой сервис: SIEM-коннектор, бота для другого мессенджера, пакетный анализ логов.

## Что переносить

| Модуль | Переносить | Привязка к этому проекту |
|---|---|---|
| `models.py` | всегда | нет |
| `normalize.py` | если вход — JSON от NXLog `im_msvistalog` | имена полей NXLog, формат `EventTime` |
| `engine.py` | всегда | нет; данные о серверах получает через `host_info` |
| `state.py` | всегда | нет; путь к файлу передаётся параметром, `None` — только в памяти |
| `formatter.py` | если нужен тот же текст | эмодзи, упоминание из `TELEGRAM_FAILED_MENTION` |
| `router.py` | если нужна маршрутизация по серверам | формат `rdp_servers.json`, понятие `thread_id` |
| `parser.py` | нет, это сборка конкретного сервиса | TCP 1516, rsyslog, Telegram, переменные окружения |

Модули импортируют друг друга без пакета (`from models import ...`), поэтому каталог `parser/` нужно скопировать целиком (или только нужные модули) и добавить его в `sys.path`. Чтобы встроить его как пакет, замените импорты на относительные (`from .models import ...`) в `engine.py`, `formatter.py`, `normalize.py`, `router.py`, `replay.py`, `parser.py`.

Внешних зависимостей нет, нужен Python 3.10 или новее (синтаксис `str | None`).

## Минимальный пример

```python
from engine import CorrelationEngine
from normalize import normalize_event
from state import SessionStore

SERVERS = {
    "ts1.example.local": {"type": "user", "nla_failure_heuristic": True},
    "dc1.example.local": {"type": "admin", "nla_failure_heuristic": True},
}

engine = CorrelationEngine(
    sessions=SessionStore("/var/lib/myapp/rdp_sessions.json"),
    host_info=lambda host: SERVERS.get(host.lower()),
)

for raw in read_events():                 # dict в формате NXLog JSON
    ev = normalize_event(raw)
    if ev is None:
        continue
    for rdp in engine.process(ev):         # list[RDPEvent], обычно 0 или 1
        handle(rdp)                        # ваша отправка или запись
```

С готовым конфигом этого проекта:

```python
from router import Router

router = Router.from_file("config/rdp_servers.json", default_thread_id=None)  # формат: config/rdp_servers.example.json
engine = CorrelationEngine(sessions=SessionStore(None), host_info=router.host_info)
```

## Контракты

### `CorrelationEngine(sessions, host_info)`

- `sessions`: `SessionStore`. При `SessionStore(path)` список сессий загружается при старте и сохраняется при каждом изменении (атомарно, через `.tmp` и `os.replace`).
- `host_info(host: str) -> dict | None`: факты о сервере по `Hostname` из события. Возвращает `None` для неизвестного сервера, иначе словарь:
  - `type`: `"user"` или `"admin"`. Влияет только на неподтверждённый logoff;
  - `nla_failure_heuristic`: `bool`. Включает правило 4625/3.

  Если `host_info` не передан, ни один сервер не считается известным: 4625/3 никогда не даёт RDP_FAILED, а неподтверждённый 4647 не отправляется.
- `process(ev: NormalizedEvent) -> list[RDPEvent]`: синхронный вызов без ожиданий и таймеров.

Порядок событий важен в пределах одного хоста: 4624/3 должен прийти до 4624/10, а 4624/10 до 4647. NXLog и rsyslog по TCP этот порядок сохраняют. При пакетной обработке сортируйте события по `EventTime` и `RecordNumber`.

Engine **не потокобезопасен**. Вызывайте его из одного потока или под блокировкой.

### `RDPEvent`

| Поле | Тип | Заполнено для |
|---|---|---|
| `event_type` | `RDP_LOGIN`, `RDP_FAILED`, `RDP_RECONNECT`, `RDP_DISCONNECT`, `RDP_LOGOFF` | всех |
| `target_host` | `Hostname` как в событии | всех |
| `username` | `DOMAIN\user`; для FAILED — как ввёл пользователь (`user@domain`, `local\user`) | всех |
| `event_time` | строка `EventTime` как в событии | всех |
| `source_ip` | IP источника, `None` если нет | LOGIN, FAILED, RECONNECT, DISCONNECT; LOGOFF при известной сессии |
| `logon_id` | LogonId сессии (неповышенного токена) | LOGIN, RECONNECT, DISCONNECT, LOGOFF |
| `client_workstation` | `WorkstationName` из NLA 4624/3 или 4625 | LOGIN (кроме Kerberos), FAILED |
| `client_name` | `ClientName` из 4778/4779 или из сессии | RECONNECT, DISCONNECT, LOGOFF |
| `session_name` | `RDP-Tcp#N` | RECONNECT, DISCONNECT |
| `auth_package` | пакет аутентификации | LOGIN, FAILED |
| `status`, `substatus` | коды отказа | FAILED |
| `confidence` | `confirmed` или `probable` | всех; `probable` только у LOGOFF неизвестной сессии |
| `evidence` | список признаков, например `["4624/3", "4624/10", "linked"]` | всех |

Для JSON-сериализации используйте `dataclasses.asdict(rdp)`.

## Формат входных событий

`normalize_event(dict) -> NormalizedEvent | None` ожидает плоский JSON от NXLog (`im_msvistalog` + `to_json()`):

| Поле NXLog | События | Использование |
|---|---|---|
| `EventID`, `Hostname`, `EventTime` (`%Y-%m-%d %H:%M:%S`) | все | обязательны; `EventTime` нужен для окна NLA |
| `LogonType` | 4624, 4625, 4634 | |
| `TargetUserName`, `TargetDomainName`, `TargetLogonId` | 4624, 4625, 4634, 4647 | |
| `TargetLinkedLogonId`, `ElevatedToken` (`%%1842`/`%%1843`), `LogonGuid` | 4624 | пара связанных входов |
| `IpAddress`, `IpPort`, `WorkstationName` | 4624, 4625 | `-` считается отсутствующим значением |
| `AuthenticationPackageName`, `Status`, `SubStatus` | 4624, 4625 | |
| `AccountName`, `AccountDomain`, `LogonID`, `SessionName`, `ClientName`, `ClientAddress` | 4778, 4779 | |
| `Message` | 4624, 4625 | запасной источник IP и `WorkstationName` (русская и английская локализация) |

**Другой источник** (Winlogbeat, Windows Event Forwarding, Splunk и т. п.): напишите адаптер, который приводит событие к этим именам полей, и передайте результат в `normalize_event`. Можно и сразу собирать `NormalizedEvent`, но тогда повторите нормализацию, от которой зависят правила:

- `-` и пустые значения → `None`;
- `IpPort` → `int` или `None`, не `0`;
- `TargetLinkedLogonId` `0x0` → `None`;
- LogonId в нижнем регистре;
- `user_key` — имя пользователя без домена и UPN-суффикса, в нижнем регистре.

Пример для Winlogbeat:

```python
def from_winlogbeat(doc):
    data = doc["winlog"]["event_data"]
    return {
        "EventID": doc["winlog"]["event_id"],
        "Hostname": doc["winlog"]["computer_name"],
        "EventTime": doc["@timestamp"][:19].replace("T", " "),  # учтите часовой пояс
        **data,                                                  # TargetUserName, IpPort, ...
    }
```

Учтите, что Winlogbeat отдаёт `ElevatedToken` как текст (`Yes`/`No`), а не как `%%1842`/`%%1843`. `parse_yes_no` понимает оба варианта.

## Своя отправка вместо Telegram

`formatter.format_rdp_event(rdp) -> str` и `router.Router.route(rdp) -> Route | None` от Telegram не зависят: `Route.thread_id` — просто число из конфига. Для другого мессенджера или SIEM:

- используйте `RDPEvent` напрямую (или `asdict`), а не текст;
- `Router` подходит для любой маршрутизации по серверу: вместо `thread_id` положите в `rdp_servers.json` свой идентификатор канала и читайте его в своём коде. `host_info` для Engine от этого не меняется.

## Расширение

**Новый тип события:**

1. константа в `models.py`;
2. ветка в `CorrelationEngine.process` и метод-обработчик;
3. ветка в `format_rdp_event`;
4. тест в `tests/test_engine.py`; при необходимости новые события в фикстуру и `UPDATE_GOLDEN=1`.

**Новое правило для существующего события** оформляйте отдельной функцией, как `is_nla_failure`, с комментарием, на каких данных правило проверено. Эмпирические правила включайте флагом в `rdp_servers.json`, чтобы их можно было отключить на конкретном сервере.

**Перед изменением правил** соберите статистику по реальным логам ([tools/rdp_stats.py](../tools/rdp_stats.py)) и сравните вывод `replay.py` до и после.

## Тесты при переносе

Каталог `tests/` переносится вместе с модулями. `tests/helpers.py` ищет модули в `../parser` и, если их там нет, в текущем каталоге. Фикстура обезличена, её можно хранить в любом репозитории. Свою фикстуру соберите из своих логов скриптом [tools/make_fixture.py](../tools/make_fixture.py): реальные имена серверов и домен передаются файлом соответствий (`--map`), который держите вне git.
