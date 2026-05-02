# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

White IP Hunter — finds Selectel floating IPs that fall in subnets routable from the РФ Megafon mobile network. The orchestrator allocates floating IPs from one or more Selectel cloud accounts, filters them against a known-white subnet list, confirms via ICMP + WLChecker API, and notifies via Telegram on hit.

Code lives in `white-ip-hunter/`. All commands below assume that as the working directory.

## Common commands

Always use `.venv/bin/python`, never system python or bare `pytest`.

```bash
# Tests
.venv/bin/python -m pytest                              # full suite
.venv/bin/python -m pytest tests/test_orchestrator.py   # one file
.venv/bin/python -m pytest -k test_account_pool         # by name
.venv/bin/python -m pytest -x --tb=short                # stop on first fail

# Run the orchestrator
python -m src.orchestrator --dry-run                    # no Selectel writes
python -m src.orchestrator                              # real run
python -m src.orchestrator --no-icmp                    # skip local ICMP (required in WSL/Termux)

# Subnet pool maintenance
python -m src.subnet_source --refresh                   # refresh RIPE AS49505 cache
python -m src.subnet_source --stats                     # pool stats

# Other tools
python -m src.subnet_filter --check 87.228.90.5         # whitelist lookup
python -m src.notifier --test "ping"                    # test Telegram delivery
```

## Configuration

- `.env` (copy from `.env.example`) — Selectel creds, WLChecker keys, Telegram bot. `SELECTEL_PASSWORD_1`/`_2` map to multi-account entries via `password_env` keys. `WL_API_KEYS` is a comma-separated list of keys for `WLKeyPool`.
- `config.yaml` (copy from `config.example.yaml`) — checker tuning, priority subnets, accounts. If `selectel_accounts:` has any `enabled: true` entry, the legacy single-account `selectel:` block is ignored.
- `SELECTEL_PROXY_URL` / `TG_PROXY_URL` env vars override `proxy_url` in config (injected by `src/config.py:load_config`).

## Architecture

The main loop is `src/orchestrator.py:Orchestrator.run`, which runs three phases per iteration:

1. **`_create_phase`** — for each non-blocked account, list existing FIPs and fill up to `MAX_FIPS_PER_ACCOUNT = 12`. Each new IP is checked via `SubnetFilter.is_ip_in_whitelist`; if not whitelisted it is deleted immediately (`stats["deleted_not_in_whitelist"]`), otherwise a `SubnetTask` is appended to `_pending_tasks`.

2. **`_verify_phase`** — for all pending tasks, concurrently: submit to `WLKeyPool` (if no job yet), ICMP-probe the `/24` via `ICMPChecker` (parallel threads), and poll WL job results. `--no-icmp` makes WL results drive the ICMP field instead.

3. **`_decision_phase`** — tasks with a resolved `icmp_result` are either kept (→ winner, `stats["white_found"]`) or deleted (→ `stats["dead"]`). The first winner exits the process via `sys.exit(0)`.

**Key collaborators:**

- `AccountPool` (in `orchestrator.py`) — round-robin over `SelectelClient` instances. HTTP 429 marks an account blocked for 120s; when all are blocked the loop sleeps and calls `reset_blocks()`.
- `SelectelClient` (`src/selectel_api.py`) — Keystone password-method auth, token cached until ~60s before expiry. `create_floating_ip_safe` raises `SelectelRateLimitError` on 429 (no internal sleep) so `AccountPool` can switch accounts.
- `WLKeyPool` (`src/checkers/wl_pool.py`) — pool of WLChecker API keys each with its own cooldown. `submit(cidr)` picks the first ready key, POSTs `/check`, returns `(job_id, key)` or `None`. `get_result()` polls and returns the payload only when `finished: true`.
- `ICMPChecker` (`src/checkers/icmp_checker.py`) — raw-socket ping, requires root or `CAP_NET_RAW`; fails silently in WSL.
- `SubnetSource` (`src/subnet_source.py`) — three-tier pool: `priority_subnets` → RIPE Stat cache (`data/subnets_cache.json`, 24h TTL) → seed file. State (`data/checked_state.json`) tracks `white|dead|ambiguous` per `/24`. All persisted writes use `_atomic_write` (tmp + `os.replace`).
- `SubnetFilter` (`src/subnet_filter.py`) — two-level O(1) index: a `set` of `/24` strings + wider networks for prefixes shorter than `/24`.
- `TelegramNotifier` (`src/notifier.py`) — HTML `sendMessage`, local rate limit 3s. `notify_progress` fires every 600s of wall-clock time (tracked by `_last_progress_notify`); `notify_white_found` fires on each winner.

**Stats tracked in `self.stats`:** `checked`, `white_found`, `dead`, `deleted_not_in_whitelist`, `total_created`. `_current_stats()` adds `elapsed`, `pending`, and `account_counts` (per-account live FIP count from `_get_account_fips_counts()`).

**Side-effect files** (under `data/`, gitignored except `.gitkeep`): `run_YYYYMMDD_HHMMSS.log`, `checked_state.json`, `subnets_cache.json`, `found_ips.json`, `ip_log.jsonl`.

## External constraints

- WLChecker per-key cooldown is 300s, enforced in `WLKeyPool._last_used`. Adding more keys to `WL_API_KEYS` increases throughput.
- Selectel requires a **service user** (`member` role on the project) — ordinary account creds won't authenticate via Keystone password-method.
- ICMP requires raw sockets; pass `--no-icmp` in WSL and Termux.

## Testing notes

- `pytest.ini` sets `asyncio_mode = auto`. Tests live under `tests/`.
- Tests use `responses` (HTTP mocking) and `pytest-mock`. No real network calls.
- `src/checkers/wl_api.py` contains the older `WLCheckerClient` (single-key, file-based cooldown). It is tested by `tests/test_wl_api.py` but **not used by the orchestrator** — the orchestrator uses `WLKeyPool` from `wl_pool.py`.
