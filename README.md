# White IP Hunter
Поиск Selectel floating IP, чья /24 подсеть доступна с мобильного интернета РФ (Megafon).

---

## Ветки

| Ветка | Статус | Описание |
|---|---|---|
| `beta` | ✅ Работает | Samsung + 2 Selectel аккаунта, ICMP с Мегафона, WLChecker |
| `split` | 🚧 В разработке | VM-оркестратор + Samsung пинг-агент + пул из 18 прокси |

---

## beta — текущая реализация

**Стек:** Samsung Note 9 (Termux, root) + Megafon SIM + happ VPN (SOCKS5 127.0.0.1:10808)

**Логика:**
1. Создать FIP на Selectel (2 аккаунта, макс 12 на каждый)
2. Проверить /24 по `data/white_subnets.txt` (46k подсетей) — не в списке → удалить сразу
3. ICMP пинг всей /24 с Мегафона напрямую через `rmnet0` (минуя VPN)
4. WLChecker API (9 ключей, параллельно по одному на задачу)
5. ICMP alive > 0 **И** WL подтвердил → SUCCESS → Telegram → стоп

**Быстрый старт:**
```bash
cp .env.example .env          # вставь ключи
cp config.example.yaml config.yaml
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m src.orchestrator --no-icmp   # без ICMP (WSL/без рута)
sudo python -m src.orchestrator        # с ICMP пингами (нужен root)
```

**Переменные окружения (.env):**

| Переменная | Описание |
|---|---|
| `SELECTEL_PASSWORD_1` / `_2` | Пароли двух Selectel аккаунтов |
| `WL_API_KEYS` | Ключи WLChecker через запятую |
| `TG_BOT_TOKEN` / `TG_CHAT_ID` | Telegram бот |
| `TG_PROXY_URL` | `socks5://127.0.0.1:10808` (happ VPN на Android) |

**config.yaml — важные параметры:**
```yaml
checkers:
  icmp:
    interface: rmnet0   # Мегафон SIM напрямую, минуя VPN
    concurrency: 32
selectel_accounts:
  - account_id: "577991"
    username: "Priya"
    password_env: SELECTEL_PASSWORD_1
    project_id: "..."
    availability_zone: ru-2
    enabled: true
```

**Флаги:**

| Флаг | Описание |
|---|---|
| `--no-icmp` | WLChecker как единственный оракул (без ICMP) |
| `--dry-run` | Без реальных вызовов Selectel |
| `--config PATH` | Путь к config.yaml |

**Известные особенности:**
- ICMP нужен root + `interface: rmnet0` в конфиге — иначе пинги идут через VPN и дают ложные 254/254
- `ExternalIpAddressExhausted` от Selectel — временно, оркестратор ждёт 30 сек и повторяет
- Таймаут Selectel API: 10с connect / 60с read; при таймауте на ru-3 автофоллбэк на ru-2

---

## split — новая архитектура (в разработке)

**Идея:** разделить оркестратор (VM) и пингер (Samsung), убрать зависимость от одного IP для Selectel.

**Стек:**
- **VM (VPS):** оркестратор + FastAPI job queue + пул из 18 SOCKS5 прокси
- **Samsung (Termux):** лёгкий `ping_agent.py`, polling VM каждые 2 сек

```
VM (VPS)                              Samsung (Termux)
├── orchestrator (без ICMP)           └── ping_agent.py
├── Selectel API → proxy_pool              ├── GET /ping-jobs
│   └── round-robin, 18 прокси            ├── ping /24 → rmnet0
├── WLChecker (9 ключей)                  └── POST /ping-results
├── FastAPI: /ping-jobs, /ping-results
├── Dead subnet кэш (data/dead_subnets.txt)
└── Telegram
```

**Ключевые отличия от beta:**

| | beta | split |
|---|---|---|
| Прокси Selectel | один (happ) | 18 SOCKS5, round-robin + кулдаун |
| ICMP + WL | последовательно | параллельно |
| Логика победы | ICMP **AND** WL | ICMP **OR** WL |
| При нахождении | стоп | продолжает, копит IP |
| Мёртвые подсети | не кэшируются | пропускаются сразу |
| ICMP | на том же устройстве | Samsung агент через HTTP polling |

**Новые компоненты:**
```
src/proxy_pool.py   — пул прокси (аналог WLKeyPool, round-robin + кулдаун)
src/job_server.py   — FastAPI сервер задач на VM
ping_agent.py       — Samsung агент (~60 строк)
```

---

## Troubleshooting

**`SelectelAPIError 401`**
→ Проверь `account_id` / `username` / `password` / `project_id` в config.yaml и .env.
→ Сервисный пользователь: ЛК Selectel → Управление → Пользователи → роль `member`.

**`ExternalIpAddressExhausted`**
→ Selectel временно исчерпал пул IP в регионе. Нормально, оркестратор сам повторит через 30с.

**ICMP всегда 254/254 alive**
→ Пинги идут через VPN. Добавь `interface: rmnet0` в `config.yaml` под `checkers.icmp`.

**Telegram не отправляет**
→ Проверь `TG_PROXY_URL` в `.env` — на Android должно быть `socks5://127.0.0.1:10808`.
→ `python -m src.notifier --test "ping"`

**`ping: operation not permitted`**
→ Нужен root: `sudo python -m src.orchestrator`

**pytest падает с ImportError**
→ `source .venv/bin/activate`
