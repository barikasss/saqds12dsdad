# PLAN.md — ветка `split`

Цель: разделить оркестратор (VM) и пингер (Samsung), Resell API, параллельные проверки, OR-логика, бесконечный режим.

---

## Статус

| # | Компонент | Статус |
|---|---|---|
| 1 | `src/proxy_pool.py` — ProxyPool + ResellProxyPool | ✅ готово |
| 2 | `src/selectel_api.py` → Resell API (X-Token, bulk create) | ✅ готово |
| 3 | `src/orchestrator.py` — dead subnet кэш | ✅ готово |
| 4 | `src/orchestrator.py` — ICMP + WL параллельно | ✅ готово |
| 5 | `src/orchestrator.py` — OR логика + не останавливаться | ✅ готово |
| 6 | `src/job_server.py` — FastAPI на VM | ✅ готово |
| 7 | `ping_agent.py` — Samsung агент | ✅ готово |
| 8 | `src/orchestrator.py` — интеграция с job server | ✅ готово |
| 9 | Тесты + проверка на сервере | 🔧 в процессе |

---

## Архитектура API (актуально)

| Операция | API | Auth | Причина |
|---|---|---|---|
| LIST FIPs | Resell API | X-Token | Простой endpoint, один для всех проектов |
| CREATE FIP | OpenStack Neutron | Keystone (service user) | Нет rate limit |
| DELETE FIP | OpenStack Neutron | Keystone (service user) | Нет rate limit |

Config: каждый аккаунт требует и `api_key_env` (Resell list) и `password_env` (OpenStack create/delete).

## FUTURE (не срочно, но не забыть)

- **asyncio + subprocess для ping_agent** — коллега использует этот подход для 150+ одновременных пингов. Сейчас у нас ThreadPoolExecutor(3 workers) что даёт 2.6x ускорение и этого достаточно. Переход на asyncio даст ещё ~1.5x и меньше памяти. Реализация: переписать ICMPChecker.ping_subnet на asyncio.create_subprocess_exec, ping_agent.py на asyncio.gather.

---

## Баги и улучшения (очередь)

| Приоритет | Проблема | Решение |
|---|---|---|
| 🔴 | 401 при старте — API ключ не принимается | Проверить ключ, возможно формат X-Token неверный |
| 🟡 | 401 блокирует аккаунт на 120с (не rate-limit!) | В cleanup: 401 → не блокировать, сразу ошибка конфига |
| 🟡 | `orch.remote_icmp_timeout` — таймаут 60с слишком мало для reclaimed FIP | Увеличить до 120с или считать от enqueue, не от created_at |
| 🟡 | Фильтрация только по priority_subnets (убрать white_subnets.txt) | Добавить опцию `search.filter_by_priority_only: true` |
| 🟡 | TG уведомление когда оба аккаунта в ExternalIpAddressExhausted >5 мин | Новый notify в orchestrator |
| 🟢 | `SELECTEL_PROXIES_FILE` — прокси из файла (обсудили) | Уже в коде, нужен только файл |

---

## Resell API — что изменилось

**Auth:** `X-Token: <api_key>` (из my.selectel.ru → Профиль → Безопасность → API-ключи)

**Эндпоинты:**
```
GET    https://api.selectel.ru/vpc/resell/v2/floatingips              → список всех FIP аккаунта
POST   https://api.selectel.ru/vpc/resell/v2/floatingips/projects/{id} → bulk create
DELETE https://api.selectel.ru/vpc/resell/v2/floatingips/{fip_id}     → удалить
```

**Конфиг (config.yaml):**
```yaml
selectel_accounts:
  - account_id: "577991"
    username: "Priya"
    api_key_env: SELECTEL_API_KEY_1   # ← было password_env
    project_id: "..."
    availability_zone: ru-3
    enabled: true
```

**Конфиг (.env):**
```
SELECTEL_API_KEY_1=...   # из my.selectel.ru
SELECTEL_API_KEY_2=...
RESELL_PROXY_URLS=socks5://...,...   # опционально
```

---

## Что НЕ меняем

- `src/subnet_filter.py`, `src/subnet_source.py`, `src/notifier.py`, `src/checkers/wl_pool.py`
- `ping_agent.py` — только на Samsung, не трогаем
