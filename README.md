# login_mon: мониторинг RDP по журналу Windows Security

Сервис принимает события журнала Security с Windows-серверов (через NXLog и rsyslog), определяет RDP-события и отправляет уведомления в темы Telegram.

| Событие | Источник | Сообщение |
|---|---|---|
| `RDP_LOGIN` | 4624, LogonType 10 | 🟢 RDP LOGIN |
| `RDP_FAILED` | 4625/10; 4625/3 с `IpPort=0` (NLA) | 🔴 RDP LOGIN FAILED |
| `RDP_RECONNECT` | 4778, `SessionName=RDP-Tcp*` | 🟡 RDP RECONNECT |
| `RDP_DISCONNECT` | 4779, `SessionName=RDP-Tcp*` | 🟠 RDP DISCONNECT |
| `RDP_LOGOFF` | 4647 + известная RDP-сессия | 🔵 RDP LOGOFF |

Правила и почему они такие: [docs/detection.md](docs/detection.md).
Как использовать код в другом проекте: [docs/reuse.md](docs/reuse.md).

## Архитектура

```
Windows (NXLog, JSON) ──TCP 1515──> rsyslog ──TCP 1516──> parser
                                      │
                                      └─> logs/raw/<ip>/<дата>.log

parser:
  parse_line ─> normalize_event ─> CorrelationEngine ─> RDPEvent
                                        │                  │
                                  SessionStore        format_rdp_event ─> Router ─> send_telegram
                              (state/sessions.json)                    (config/rdp_servers.json)
```

Слои не зависят друг от друга «вверх»: Engine ничего не знает о Telegram и темах, Router не влияет на определение событий.

| Модуль | Назначение | Зависимости |
|---|---|---|
| [parser/models.py](parser/models.py) | `NormalizedEvent` (вход Engine), `RDPEvent` (выход Engine) | — |
| [parser/normalize.py](parser/normalize.py) | JSON NXLog → `NormalizedEvent` | models |
| [parser/engine.py](parser/engine.py) | `CorrelationEngine`: правила и корреляция | models, state |
| [parser/state.py](parser/state.py) | `SessionStore`: известные RDP-сессии, сохранение в JSON | — |
| [parser/formatter.py](parser/formatter.py) | `RDPEvent` → текст сообщения | models |
| [parser/router.py](parser/router.py) | хост → тема Telegram; факты о хосте для Engine | models |
| [parser/parser.py](parser/parser.py) | TCP-сервер, `parse_line`, `send_telegram`, сборка слоёв | все |
| [parser/replay.py](parser/replay.py) | офлайн-прогон логов без Telegram | все, кроме отправки |

Только стандартная библиотека Python 3.11, без внешних зависимостей.

## Развёртывание

Проект лежит в подкаталоге `windows/windows-rdp-parser` репозитория [kvotti/work](https://github.com/kvotti/work). Чтобы скачать только его:

```bash
git clone --filter=blob:none --sparse https://github.com/kvotti/work.git
cd work && git sparse-checkout set windows/windows-rdp-parser
cd windows/windows-rdp-parser
cp .env.example .env                                         # заполнить
cp config/rdp_servers.example.json config/rdp_servers.json   # заполнить
docker compose up -d --build
docker logs -f winlog_parser
```

При старте в логе должны появиться строки:

```
[*] Router: N серверов, topics={'user': ..., 'admin': ...}, unknown_host_mode=default
[*] SessionStore: загружено N сессий
[*] Listening on 0.0.0.0:1516
```

Обновление: `git pull && docker compose up -d --build parser`, из каталога проекта. Пересобирать нужно именно образ: код копируется в него при сборке, и `docker compose restart` оставит старую версию. rsyslog при этом продолжает принимать события, а пересылку парсеру держит в очереди и досылает после перезапуска.

`.env`, `config/rdp_servers.json`, `logs/` и `state/` находятся в `.gitignore` и при `git pull` не затрагиваются. При переезде со старой установки скопируйте их в каталог проекта до первого запуска.
После правки только `config/rdp_servers.json` достаточно `docker compose restart parser`.

### Переменные окружения (`.env`)

| Переменная | Обязательна | Назначение |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | да | токен бота |
| `TELEGRAM_CHAT_ID` | да | ID группы с темами |
| `TELEGRAM_THREAD_ID` | нет | тема по умолчанию: для хостов вне `rdp_servers.json` и серверов без темы |
| `TELEGRAM_PROXY` | нет | HTTP(S)-прокси для api.telegram.org, `http://user:pass@host:port` |
| `UNKNOWN_HOST_MODE` | нет | `default` (по умолчанию) — хосты вне конфига в тему по умолчанию; `drop` — не отправлять |
| `TELEGRAM_FAILED_MENTION` | нет | упоминание в сообщениях о неудачном входе, например `@username`; по умолчанию без упоминания |

`RDP_SERVERS_PATH` и `SESSIONS_PATH` заданы в `docker-compose.yml`.

### `config/rdp_servers.json`

```json
{
  "topics": { "user": 101, "admin": 102 },
  "servers": {
    "TS1.example.local":  { "type": "user" },
    "DC1.example.local":  { "type": "admin" },
    "WSUS.example.local": { "type": "admin", "nla_failure_heuristic": false },
    "VIP.example.local":  { "type": "admin", "thread_id": 12345 }
  }
}
```

| Поле | Назначение |
|---|---|
| `topics.<type>` | тема Telegram для типа сервера. `user` — пользовательские терминальные серверы, `admin` — административный RDP |
| `servers.<host>` | ключ — `Hostname` из события. Регистр не важен, короткое имя тоже находится |
| `type` | `user` или `admin`. Кроме темы влияет на неподтверждённый logoff (см. [docs/detection.md](docs/detection.md#rdp_logoff)) |
| `thread_id` | своя тема для сервера вместо темы типа |
| `nla_failure_heuristic` | по умолчанию `true`. `false` отключает правило 4625/3 на сервере (например, при ложных срабатываниях на IIS с NTLM) |

Ключи, начинающиеся с `_`, игнорируются: так можно хранить примеры и комментарии.

Сервер, которого нет в списке: его события уходят в тему по умолчанию (или отбрасываются при `UNKNOWN_HOST_MODE=drop`), а 4625/3 с него никогда не считается RDP.

### Источник событий (NXLog)

На каждом Windows-сервере NXLog CE читает канал Security и отправляет события в JSON по TCP на порт 1515 хоста с docker compose. Рабочий конфиг: [nxlog/nxlog.conf](nxlog/nxlog.conf).

**Установка на сервер:**

1. Установить [NXLog Community Edition](https://nxlog.co/downloads/nxlog-ce) (MSI) в каталог по умолчанию `C:\Program Files\nxlog`.
2. Скопировать `nxlog/nxlog.conf` в `C:\Program Files\nxlog\conf\nxlog.conf`. В строке `define SYSLOG_SERVER` указать адрес хоста с docker compose.
3. Включить аудит. Лучше через GPO: *Конфигурация компьютера → Политики → Конфигурация Windows → Параметры безопасности → Конфигурация расширенной политики аудита → Вход/выход*. На отдельном сервере можно командой (GUID работают и в русской, и в английской Windows):

   ```powershell
   # Вход (4624, 4625), Выход (4634, 4647), Другие события входа/выхода (4778, 4779)
   auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
   auditpol /set /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /success:enable
   auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
   auditpol /get /category:"{69979849-797A-11D9-BED3-505054503030}"   # проверка
   ```

4. Перезапустить службу и проверить её лог:

   ```powershell
   Restart-Service nxlog
   Get-Content "C:\Program Files\nxlog\data\nxlog.log" -Tail 20
   ```

   В логе не должно быть ошибок подключения к `SYSLOG_SERVER`. Если они есть, проверьте, что исходящий TCP 1515 разрешён в брандмауэре.

5. На хосте с docker compose должен появиться файл `logs/raw/<ip сервера>/<дата>.log`. Каждая строка в нём — syslog-заголовок и JSON события.
6. Добавить сервер в `config/rdp_servers.json` (см. [Добавление нового сервера](#добавление-нового-сервера)).

Конфиг пересылает и события, которые парсер пока не использует (4648, 4672, 4740). Самое массовое из них — 4672; если трафик важен, его можно убрать из `QueryXML`. Поля, которые использует парсер, перечислены в [docs/reuse.md](docs/reuse.md#формат-входных-событий).

rsyslog ([rsyslog.conf](rsyslog.conf)) пишет сырые логи в `logs/raw/<ip>/<дата>.log` и пересылает каждую строку парсеру.

### Данные на диске

| Путь | Содержимое | В git |
|---|---|---|
| `.env` | секреты | нет |
| `logs/` | сырые события (имена пользователей, IP) | нет |
| `state/sessions.json` | известные RDP-сессии; переживает рестарт контейнера | нет |
| `spool/` | очередь rsyslog для парсера, пока тот недоступен (до 1 ГБ) | нет |
| `config/rdp_servers.json` | серверы и темы (имена инфраструктуры) | нет; в git только `rdp_servers.example.json` |

Удаление `state/sessions.json` безопасно. Последствие: выход из сессий, открытых до этого, на `admin`-серверах не придёт, а на `user`-серверах придёт с пометкой «не подтверждено».

## Тесты

```bash
python -m unittest discover -s tests                     # локально, из корня
docker compose run --rm -v "$PWD/tests:/app/tests:ro" parser \
  python -m unittest discover -s tests                   # в контейнере
```

- `tests/fixtures/events.jsonl` — 146 реальных событий терминального сервера, контроллера домена и сервера приложений. Имена, домен и IP в них заменены условными.
- `test_golden.py` прогоняет всю фикстуру и сравнивает результат с `expected_events.json`. После намеренного изменения поведения эталон пересоздаётся командой `UPDATE_GOLDEN=1 python -m unittest discover -s tests`, а изменения в нём нужно просмотреть до коммита.
- `test_engine.py` — сценарии по каждому правилу, `test_components.py` — нормализация, Router, SessionStore, Formatter.

## Инструменты

| Команда | Назначение |
|---|---|
| `python parser/replay.py logs/raw --config config/rdp_servers.json` | какие сообщения и в какие темы ушли бы, без Telegram; `--json` выводит `RDPEvent` |
| `python tools/rdp_stats.py logs/raw` | статистика для проверки эвристик: `IpPort` у 4625/3, связь 4624/3 → 4624/10, интервалы |
| `python tools/make_fixture.py ... --map logs/fixture_map.json` | сборка обезличенной фикстуры из `logs/`; параметры в начале скрипта |

На сервере, где нет локального Python:

```bash
docker compose run --rm -v "$PWD/logs:/logs" parser python replay.py /logs/raw/<ip>/<дата>.log
docker run --rm -v "$PWD/logs:/logs" -v "$PWD/tools:/tools" python:3.11-slim \
  python /tools/rdp_stats.py /logs/raw
```

## Добавление нового сервера

1. Настроить NXLog на сервере (см. выше).
2. Добавить сервер в `config/rdp_servers.json` и выполнить `docker compose restart parser`.
3. Через несколько дней прогнать `tools/rdp_stats.py` по его логам. Если среди 4625/3 с `IpPort=0` есть не-RDP источники (IIS, RD Web, Exchange), поставить серверу `"nla_failure_heuristic": false`. Подробности: [docs/detection.md](docs/detection.md#проверка-на-новом-сервере).

## Не реализовано

- Сводка при подборе пароля: сейчас каждая неудача приходит отдельным сообщением.
- Отправка в Telegram в отдельном потоке: медленный прокси задерживает разбор событий до 10 с на сообщение.
- Перечитывание `rdp_servers.json` без перезапуска.
- Каналы RdpCoreTS и TerminalServices-LocalSessionManager. Нужны, если эвристика `IpPort=0` перестанет работать, и чтобы получать имя клиента при Kerberos-входе.
