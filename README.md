# White IP Hunter
Поиск IP-подсетей Selectel, доступных с мобильного интернета РФ (Megafon).

---

## Быстрый старт

```bash
# 1. Заполни переменные окружения
cp .env.example .env
# → отредактируй .env (вставь ключи, см. таблицу ниже)

# 2. Скопируй конфиг
cp config.example.yaml config.yaml

# 3. Установи зависимости (внутри venv)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 4. Проверь что всё в порядке
pytest                             # должно быть 47 зелёных

# 5. Тест без денег (dry-run, не трогает Selectel)
python -m src.orchestrator --dry-run --phase 1

# 6. Реальный запуск (Phase 1 — приоритетные подсети)
python -m src.orchestrator --phase 1
```

---

## Переменные окружения

| Переменная | Описание |
|---|---|
| `SELECTEL_ACCOUNT_ID` | 6-значный номер аккаунта Selectel |
| `SELECTEL_USERNAME` | Логин сервисного пользователя |
| `SELECTEL_PASSWORD` | Пароль сервисного пользователя |
| `SELECTEL_PROJECT_ID` | UUID проекта в Selectel Cloud |
| `WLCHECKER_API_KEY` | Ключ от WLChecker API |
| `TG_BOT_TOKEN` | Токен Telegram-бота для уведомлений |
| `TG_CHAT_ID` | Числовой Telegram ID (узнать у @userinfobot) |

Сервисного пользователя создавай в ЛК Selectel → **Управление** → **Пользователи** →
**Создать сервисного пользователя** с ролью `member` на нужный проект.

---

## Запуск

```bash
source .venv/bin/activate

# Dry-run: WLChecker работает, Selectel create/delete не вызывается
python -m src.orchestrator --dry-run --phase 1

# Phase 1 — только приоритетные подсети из config.yaml
python -m src.orchestrator --phase 1

# Phase 1 без ICMP (быстрее, не нужен root в Termux)
python -m src.orchestrator --phase 1 --no-icmp

# Phase 2 — широкий поиск по всем подсетям AS49505 (~1700 /24)
python -m src.orchestrator --phase 2 --no-icmp

# Полный прогон Phase 1 → Phase 2
python -m src.orchestrator

# Продолжить прерванный прогон
python -m src.orchestrator --resume --phase 2

# Статистика пула подсетей
python -m src.subnet_source --stats

# Принудительное обновление данных RIPE
python -m src.subnet_source --refresh

# Тест Telegram-уведомлений
python -m src.notifier --test "Hello from white-ip-hunter"
```

### Флаги CLI

| Флаг | Описание |
|---|---|
| `--dry-run` | Не вызывать Selectel create/delete |
| `--resume` | Не сбрасывать state, продолжить с прерванного места |
| `--phase {1,2,both}` | 1=только priority, 2=широкий, both=всё |
| `--no-icmp` | Пропустить локальный ICMP, сразу WLChecker |
| `--config PATH` | Путь к config.yaml (default: config.yaml) |

---

## Поток работы

```
config.yaml + .env
        │
        ▼
┌─────────────────────────────┐
│  Phase 1 — Quick Win        │
│  WLChecker.check_batch(     │
│    priority_subnets)        │
│  any alive? → success_flow  │
└──────────────┬──────────────┘
               │ нет белых
               ▼
┌─────────────────────────────┐
│  Phase 2 — Wide Search      │
│  RIPE AS49505 → ~1700 /24s  │
│  for cidr in unchecked:     │
│    ICMP pre-screen (опц.)   │
│    WLChecker.check_subnet   │
│    ≥5% alive → success_flow │
└──────────────┬──────────────┘
               │ найдено
               ▼
┌─────────────────────────────┐
│  success_flow               │
│  Selectel.reroll(cidr, 15)  │
│  FIP выпал в CIDR?          │
│    да → notify_success      │
│         data/found_ips.json │
│         exit(0)             │
│    нет → notify_warning     │
│          exit(1)            │
└─────────────────────────────┘
```

Лог каждого запуска: `data/run_YYYYMMDD_HHMMSS.log`  
Состояние пула: `data/checked_state.json`  
Найденные IP: `data/found_ips.json`

---

## Setup (Termux на Samsung)

```bash
bash setup_termux.sh
```

Подробнее — в самом скрипте.

---

## Troubleshooting

**`SelectelAPIError 401` — Password auth failed**  
→ Проверь `SELECTEL_ACCOUNT_ID` / `SELECTEL_USERNAME` / `SELECTEL_PASSWORD` / `SELECTEL_PROJECT_ID` в `.env`.  
→ Сервисный пользователь создаётся в ЛК Selectel → Управление → Пользователи.  
→ `SELECTEL_PROJECT_ID` — UUID из URL облачного проекта.

**`WLError: Connection failed after retries`**  
→ Проверь доступность `http://150.241.74.147:8082`.  
→ WLChecker cooldown 5 минут между submit — это нормально, жди.

**`WLChecker cooldown 300s` в логе**  
→ Предыдущий submit был меньше 5 минут назад. Подожди или убедись что `.wl_cooldown` актуален.

**Telegram не отправляет**  
→ Проверь `TG_BOT_TOKEN` и `TG_CHAT_ID` в `.env`.  
→ Запусти `python -m src.notifier --test "ping"`.  
→ Если бот молчит — напиши ему `/start` в чате.

**ICMP не работает в WSL**  
→ Добавь `--no-icmp` к команде запуска.

**На Termux: `ping: operation not permitted`**  
→ `pkg install iputils` — если не помогает, используй `--no-icmp`.  
→ С root: `su -c "python -m src.orchestrator --phase 2"`.

**`pytest` падает с ImportError**  
→ Активируй venv: `source .venv/bin/activate`.
