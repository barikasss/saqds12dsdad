# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

White IP Hunter — finds Selectel floating IPs that fall in subnets routable from the РФ Megafon mobile network. The orchestrator allocates floating IPs from one or more Selectel cloud accounts, filters them against a known-white subnet list, confirms via the WLChecker API, and notifies via Telegram on hit.

Code lives in `white-ip-hunter/`. All commands below assume that as the working directory.

## Common commands

Activate the venv first (`source .venv/bin/activate`) or invoke `.venv/bin/python` directly.

```bash
# Tests — always use the venv's python, not system python
.venv/bin/python -m pytest                              # full suite
.venv/bin/python -m pytest tests/test_orchestrator.py   # one file
.venv/bin/python -m pytest -k test_account_pool         # by name
.venv/bin/python -m pytest -x --tb=short                # stop on first fail

# Run the orchestrator
python -m src.orchestrator --dry-run                    # no Selectel writes
python -m src.orchestrator                              # real run
python -m src.orchestrator --resume                     # keep existing state
python -m src.orchestrator --no-icmp                    # skip local ICMP (needed in WSL/Termux)
python -m src.orchestrator --show-log                   # print data/ip_log.jsonl
python -m src.orchestrator --accounts                   # list configured Selectel accounts

# Subnet pool maintenance
python -m src.subnet_source --refresh                   # refresh RIPE AS49505 cache
python -m src.subnet_source --stats                     # pool stats

# Other tools
python -m src.subnet_filter --check 87.228.90.5         # whitelist lookup
python -m src.notifier --test "ping"                    # test Telegram delivery
```

The CLI also accepts `--phase {1,2,both}` and `--zone <ru-2|ru-3|...>`, but note that the current `Orchestrator` doesn't branch on `phase` — it runs a single reroll loop regardless.

## Configuration

- `.env` (copy from `.env.example`) — Selectel creds, WLChecker key, Telegram bot. `SELECTEL_PASSWORD_1`/`_2` map to multi-account entries via `password_env` keys.
- `config.yaml` (copy from `config.example.yaml`) — checker tuning, priority subnets, accounts. If `selectel_accounts:` is non-empty and any entry is `enabled: true`, the legacy single-account `selectel:` block is ignored.
- `SELECTEL_PROXY_URL` / `TG_PROXY_URL` env vars override `proxy_url` in config (set by `src/config.py:load_config`).

## Architecture

The flow is driven by `src/orchestrator.py:Orchestrator.run`:

1. `_check_existing_fips` — for every account, list current floating IPs. If an IP lies in a priority/whitelisted subnet, double-check via WLChecker; otherwise delete it. This cleans stale FIPs before the loop starts.
2. `_reroll_loop` — repeatedly create one floating IP via `AccountPool.next()` (round-robin). For each new IP:
   - If it falls in a known-white `/24` (`SubnetFilter.is_ip_in_whitelist`), confirm via `WLCheckerClient.check_subnet(f"{ip}/32")`. On confirmation → `_success_flow` (notify, save to `data/found_ips.json`, exit 0).
   - Otherwise delete the FIP and continue.
3. `_success_flow` exits the process; failure paths just keep rerolling.

Key collaborators:

- `AccountPool` (in `orchestrator.py`) — round-robin over `SelectelClient` instances. `SelectelRateLimitError` (HTTP 429) marks an account blocked for ~120s; when all are blocked, the loop sleeps 120s and clears the blocks. Each client allocates from its own configured `availability_zone`.
- `SelectelClient` (`src/selectel_api.py`) — Keystone password-method auth (service user → `X-Subject-Token`), token cached until ~60s before expiry. Three auth paths: password (preferred), token-exchange via `/identity`, raw API token (last resort). `_request_with_retry` handles 429/5xx with exponential backoff `[2,4,8]`s; `create_floating_ip_safe` opts out of the 429 sleep so `AccountPool` can switch accounts instead.
- `WLCheckerClient` (`src/checkers/wl_api.py`) — POST `/check` returns a `job_id`, polled via GET `/check/{job_id}` until `finished: true`. **Submit cooldown: 5 minutes**, persisted across runs in `.wl_cooldown` (a single float timestamp). Batches respect `_MAX_BATCH_IPS = 256` total IPs per submit. Honors `Retry-After` on 429.
- `SubnetSource` (`src/subnet_source.py`) — three-tier subnet pool: priority list → RIPE Stat cache (`data/subnets_cache.json`, 24h TTL) → seed file fallback (`data/selectel_subnets_seed.txt`). Everything is normalised to `/24`. State (`data/checked_state.json`) tracks `white|dead|ambiguous` per CIDR. All persisted writes use `_atomic_write` (tmp + `os.replace`), exported for the orchestrator to reuse.
- `SubnetFilter` (`src/subnet_filter.py`) — two-level O(1) index: a `set` of `/24` strings + a small list of wider networks. Lookups derive the parent `/24` of an address, then check the set; the wide list is fallback for prefixes shorter than `/24` (rare).
- `TelegramNotifier` (`src/notifier.py`) — `sendMessage` with HTML `parse_mode`. Local rate limit: 1 message per 3s (monotonic clock). Disabled silently when token/chat_id missing.
- `src/config.py:load_config` — `dotenv` + YAML merge; injects `SELECTEL_PROXY_URL` / `TG_PROXY_URL` into the relevant config sections.

Side-effect files (under `data/`, gitignored except `.gitkeep`):

- `run_YYYYMMDD_HHMMSS.log` — per-run structlog output
- `checked_state.json` — subnet pool state
- `subnets_cache.json` — RIPE cache (24h TTL)
- `found_ips.json` — successful hits (appended)
- `ip_log.jsonl` — every IP seen, with action (`candidate`, `kept`, `deleted_*`)

External constraints worth knowing:

- WLChecker's 5-minute submit cooldown is enforced both by the server and locally via `.wl_cooldown` — don't delete that file casually.
- Selectel's password-method Keystone auth requires a **service user** (created in ЛК Selectel → Управление → Пользователи) with `member` role on the project; ordinary user creds won't work.
- ICMP requires raw sockets; in WSL and stock Termux it'll fail — pass `--no-icmp`.

## Testing notes

- `pytest.ini` sets `asyncio_mode = auto`. Tests live under `tests/`.
- The user's preference (saved in memory): always invoke pytest as `.venv/bin/python -m pytest`, never bare `pytest` or system `python`.
- Tests heavily use `responses` (HTTP mocking) and `pytest-mock`. Network is mocked; tests should not hit real Selectel/WLChecker/Telegram endpoints.
