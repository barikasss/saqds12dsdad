# PLAN.md — ветка `split`

Цель: разделить оркестратор (VM) и пингер (Samsung), добавить пул прокси,
параллельные проверки, OR-логику и бесконечный режим работы.

---

## Статус

| # | Компонент | Статус |
|---|---|---|
| 1 | `src/proxy_pool.py` | ✅ готово |
| 2 | `src/selectel_api.py` — поддержка ProxyPool | ✅ готово |
| 3 | `src/orchestrator.py` — dead subnet кэш | ✅ готово |
| 4 | `src/orchestrator.py` — ICMP + WL параллельно | ✅ готово |
| 5 | `src/orchestrator.py` — OR логика + не останавливаться | ✅ готово |
| 6 | `src/job_server.py` — FastAPI на VM | ✅ готово |
| 7 | `ping_agent.py` — Samsung агент | ✅ готово |
| 8 | `src/orchestrator.py` — интеграция с job server | ✅ готово |
| 9 | Тесты + проверка на тестовом сервере | ⬜ не начато |

---

## Шаг 1 — `src/proxy_pool.py`

**Что делает:** пул SOCKS5 прокси, round-robin с кулдауном. Аналог WLKeyPool.

**Интерфейс:**
```python
pool = ProxyPool(proxies=["socks5://1.2.3.4:1080", ...], cooldown_seconds=120)
proxy_url = pool.get()   # первый свободный или None
pool.release(proxy_url)  # ставит в кулдаун после использования
```

**Конфиг (.env):**
```
SELECTEL_PROXIES=socks5://x:y@1.2.3.4:1080,socks5://x:y@5.6.7.8:1080,...
```

**Тест:** создать пул из 3 прокси, взять все 3, убедиться что 4й вызов возвращает None, подождать кулдаун — снова доступны.

---

## Шаг 2 — `src/selectel_api.py` + ProxyPool

**Что меняем:** `SelectelClient` принимает `proxy_pool: ProxyPool | None`. Если передан — при каждом `create_floating_ip_safe` берёт прокси через `pool.get()`, делает запрос, возвращает в кулдаун через `pool.release()`. Остальные запросы (list, delete) используют постоянный `proxy_url` аккаунта (или первый доступный из пула).

**Тест:** мок пула, убедиться что `get()` и `release()` вызываются при создании FIP.

---

## Шаг 3 — Dead subnet кэш

**Что меняем в оркестраторе:**
- При старте загружаем `data/dead_subnets.txt` в `set[str]`
- В `_create_phase`: если `/24` нового FIP уже в кэше → сразу удаляем FIP, не создаём задачу
- В `_decision_phase`: когда задача признана мёртвой (ICMP=0 И WL=False) → добавляем /24 в кэш + дозаписываем в файл

**Формат файла:** одна CIDR строка на линию (`178.72.153.0/24\n...`)

**Тест:** создать файл с одной подсетью, запустить в dry-run — FIP в этой подсети должен удалиться без пинга.

---

## Шаг 4 — ICMP + WL параллельно

**Что меняем в `_verify_phase`:**

Сейчас: ICMP → (если alive) → WL submit → poll
Станет: WL submit сразу при получении задачи + ICMP одновременно → оба в параллель → ждём результаты

Конкретно:
- WL submit делать не в `_verify_phase` а сразу в `_create_phase` после добавления задачи
- `_verify_phase` только: запускает ICMP для задач без `icmp_result` + поллит WL для задач с `wl_job_id`

**Тест:** в dry-run убедиться что WL submit идёт сразу, не дожидаясь ICMP.

---

## Шаг 5 — OR логика + бесконечный режим

**Что меняем в `_decision_phase`:**

Сейчас: ICMP AND WL → `sys.exit(0)`
Станет:
- ICMP alive > 0 **ИЛИ** WL alive > 0 → сохранить IP, Telegram, **продолжить**
- ICMP=0 **И** WL=False → мёртвая, удалить, добавить в dead кэш
- `sys.exit(0)` убираем полностью

**Что сохраняем:** `data/found_ips.json` пополняется, каждый новый IP — отдельная Telegram нотификация.

**Тест:** dry-run с мок-результатами: один таск с ICMP=True/WL=False — должен сохраниться и скрипт продолжить работу.

---

## Шаг 6 — `src/job_server.py` (FastAPI на VM)

**Эндпоинты:**
```
GET  /ping-jobs          → список CIDR для пинга (макс 10 за раз)
POST /ping-results       → {cidr: "x.x.x.0/24", alive: 12, total: 254}
GET  /health             → {"ok": true}
```

**Авторизация:** `X-Secret: <PING_AGENT_SECRET>` в заголовке.

**Хранение:** простой dict в памяти (jobs: dict[cidr, Event], results: dict[cidr, int]).

**Запуск на VM:**
```bash
uvicorn src.job_server:app --host 0.0.0.0 --port 8888
```

**Тест:** curl запросы вручную — положить задачу, забрать, отправить результат.

---

## Шаг 7 — `ping_agent.py` (Samsung)

**Логика:**
```
while True:
    jobs = GET /ping-jobs
    for cidr in jobs:
        result = ICMPChecker(interface="rmnet0").ping_subnet(cidr)
        alive = sum(v for v in result.values())
        POST /ping-results {cidr, alive, total=254}
    sleep(2)
```

**Конфиг (env):**
```
VM_URL=http://<VM_IP>:8888
PING_AGENT_SECRET=<секрет>
PING_INTERFACE=rmnet0
```

**Запуск на Samsung:**
```bash
sudo python ping_agent.py
```

---

## Шаг 8 — Интеграция оркестратора с job server

**Что меняем:** вместо прямого вызова `ICMPChecker` в оркестраторе — отправить CIDR в job server, ждать результата через поллинг `GET /ping-jobs` (точнее отдельный `GET /ping-results/{cidr}`).

Добавить в конфиг:
```yaml
ping_agent:
  enabled: false          # true = удалённый Samsung агент
  url: "http://VM_IP:8888"
  secret_env: PING_AGENT_SECRET
  poll_interval_seconds: 2
  timeout_seconds: 60
```

Если `enabled: false` — использовать локальный ICMPChecker как сейчас (совместимость с beta).

---

## Шаг 9 — Финальная проверка

**Чеклист:**
- [ ] `pytest` зелёный
- [ ] dry-run на WSL без ошибок
- [ ] job_server поднимается, Samsung агент подключается
- [ ] Реальный запуск: прокси ротируются (видно в логах `proxy_pool.acquired`)
- [ ] Мёртвая подсеть пропускается на следующей итерации
- [ ] IP найден → Telegram уведомление → скрипт продолжает работу

---

## Что НЕ меняем в этой ветке

- `src/subnet_filter.py` — не трогаем
- `src/subnet_source.py` — не трогаем  
- `src/notifier.py` — не трогаем
- `src/checkers/wl_pool.py` — не трогаем
- Формат `config.yaml` — только добавляем новые секции, старые работают

---

## Порядок кодинга

```
Шаг 1 → Шаг 2 → Шаг 3 → Шаг 4+5 (вместе) → Шаг 6 → Шаг 7 → Шаг 8 → Шаг 9
```

Каждый шаг — отдельный коммит. После шага 5 уже можно тестировать на VM без Samsung агента.
