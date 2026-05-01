"""Tests for AccountPool, SubnetFilter, batch reroll, and IP logging."""
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.orchestrator import AccountPool, Orchestrator
from src.selectel_api import SelectelClient, SelectelRateLimitError
from src.subnet_filter import SubnetFilter
from src.subnet_source import SubnetSource


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_client(username: str = "user") -> SelectelClient:
    c = MagicMock(spec=SelectelClient)
    c.username = username
    return c


def make_orch(tmp_path, **kwargs) -> Orchestrator:
    orch = object.__new__(Orchestrator)
    orch.dry_run = False
    orch.resume = False
    orch.phase = "both"
    orch.no_icmp = True
    orch._running = True
    orch._start_time = time.monotonic()
    orch._zone = "ru-2"
    orch.stats = {
        "total_subnets": 0, "checked": 0, "white_found": 0,
        "dead": 0, "ambiguous": 0,
        "start_time": datetime.now(timezone.utc).isoformat(),
    }
    orch.max_iter = 100
    orch.shuffle = False
    orch.reroll_attempts = 15

    c = _mock_client("test_user")
    orch._account_pool = AccountPool([c])
    orch.selectel = c
    orch.icmp = MagicMock()
    orch.tcp = MagicMock()
    orch.wl = MagicMock()
    orch.notifier = MagicMock()
    for m in ("notify_success", "notify_warning", "notify_error", "notify_progress"):
        setattr(orch.notifier, m, MagicMock(return_value=True))
    orch.source = SubnetSource(
        priority_subnets=[],
        seed_file="data/selectel_subnets_seed.txt",
        cache_file=str(tmp_path / "cache.json"),
        state_file=str(tmp_path / "state.json"),
    )
    orch.ip_log_file = str(tmp_path / "ip_log.jsonl")
    orch._save_found_ip = MagicMock()
    orch.__dict__.update(kwargs)
    return orch


# ---------------------------------------------------------------------------
# 1. test_account_pool_round_robin
# ---------------------------------------------------------------------------

def test_account_pool_round_robin():
    c1 = _mock_client("user1")
    c2 = _mock_client("user2")
    pool = AccountPool([c1, c2])

    assert pool.next() is c1
    assert pool.next() is c2
    assert pool.next() is c1   # wraps around


# ---------------------------------------------------------------------------
# 2. test_account_pool_skip_blocked
# ---------------------------------------------------------------------------

def test_account_pool_skip_blocked():
    c1 = _mock_client("user1")
    c2 = _mock_client("user2")
    pool = AccountPool([c1, c2])

    pool.mark_rate_limited(c1, datetime.now(timezone.utc) + timedelta(seconds=300))

    # c1 is blocked: both calls should return c2
    assert pool.next() is c2
    assert pool.next() is c2

    # After unblocking c1, round-robin resumes normally
    pool.reset_blocks()
    first = pool.next()
    second = pool.next()
    assert {first, second} == {c1, c2}


# ---------------------------------------------------------------------------
# 3. test_all_blocked_then_sleep
# ---------------------------------------------------------------------------

def test_all_blocked_then_sleep(tmp_path):
    c1 = _mock_client("user1")
    pool = AccountPool([c1])

    pool.mark_rate_limited(c1, datetime.now(timezone.utc) + timedelta(seconds=300))
    assert pool.all_blocked() is True

    orch = make_orch(tmp_path)
    orch._account_pool = pool
    # Build a filter with no white subnets so every IP is deleted
    sf = SubnetFilter([])

    with patch("src.orchestrator.time.sleep") as mock_sleep:
        # After one sleep+reset cycle, pool is unblocked; batch exhausts max_ips=0
        found, _ = orch._batch_reroll(sf, "ru-2", max_ips=0)

    assert found is None
    mock_sleep.assert_not_called()  # max_ips=0 → loop exits immediately

    # Separate test: sleep IS called when all blocked and max_ips > 0
    c2 = _mock_client("user2")
    pool2 = AccountPool([c2])
    pool2.mark_rate_limited(c2, datetime.now(timezone.utc) + timedelta(seconds=300))

    orch2 = make_orch(tmp_path)
    orch2._account_pool = pool2
    orch2._account_pool.reset_blocks = MagicMock(side_effect=lambda: pool2._blocked_until.clear())

    with patch("src.orchestrator.time.sleep") as mock_sleep:
        # After sleep+reset, account is unblocked but we hit max_ips=0
        # To avoid infinite loop, mock create_floating_ip_safe to exhaust immediately
        c2.create_floating_ip_safe = MagicMock(side_effect=SelectelRateLimitError(429, ""))
        found2, _ = orch2._batch_reroll(sf, "ru-2", max_ips=1)

    assert found2 is None
    mock_sleep.assert_called_with(120)


# ---------------------------------------------------------------------------
# 4. test_whitelist_lookup_o1
# ---------------------------------------------------------------------------

def test_whitelist_lookup_o1():
    # 46k /24 entries
    cidrs = [f"10.{a}.{b}.0/24" for a in range(256) for b in range(180)]
    sf = SubnetFilter(cidrs[:46_000])

    # 10k lookups should complete in < 500ms
    ips = [f"10.{a}.{b}.1" for a in range(100) for b in range(100)]
    t0 = time.monotonic()
    for ip in ips:
        sf.is_ip_in_whitelist(ip)
    elapsed = time.monotonic() - t0

    assert elapsed < 0.5, f"10k lookups took {elapsed:.3f}s — expected < 0.5s"


# ---------------------------------------------------------------------------
# 5. test_multi_account_rate_limit_failover
# ---------------------------------------------------------------------------

def test_multi_account_rate_limit_failover():
    c1 = _mock_client("user1")
    c2 = _mock_client("user2")
    pool = AccountPool([c1, c2])

    # c1 gets rate limited
    pool.mark_rate_limited(c1, datetime.now(timezone.utc) + timedelta(seconds=120))

    assert pool.all_blocked() is False   # c2 is still available
    nxt = pool.next()
    assert nxt is c2                     # skipped c1


def test_selectel_rate_limit_error_is_raised(tmp_path):
    """create_floating_ip_safe raises SelectelRateLimitError on 429."""
    import responses as resp_lib
    from src.selectel_api import SelectelClient

    url_base = "https://ru-2.cloud.api.selcloud.ru/network/v2.0"
    identity_url = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"

    with resp_lib.RequestsMock() as rsps:
        # auth
        rsps.add(resp_lib.POST, identity_url, status=404)
        # list networks
        rsps.add(resp_lib.GET, f"{url_base}/networks",
                 json={"networks": [{"id": "net-1"}]})
        # POST floatingips → 429
        rsps.add(resp_lib.POST, f"{url_base}/floatingips", status=429)

        client = SelectelClient(
            api_token="testtoken", region="ru-2"
        )
        with pytest.raises(SelectelRateLimitError):
            client.create_floating_ip_safe()


# ---------------------------------------------------------------------------
# 6. test_ip_log_append
# ---------------------------------------------------------------------------

def test_ip_log_append(tmp_path):
    orch = make_orch(tmp_path)

    orch._log_ip("1.2.3.4", "1.2.3.0/24", True,  "kept",    "user1", "ru-2")
    orch._log_ip("5.6.7.8", "5.6.7.0/24", False, "deleted", "user2", "ru-2")

    lines = Path(orch.ip_log_file).read_text().splitlines()
    assert len(lines) == 2

    first = json.loads(lines[0])
    assert first["ip"] == "1.2.3.4"
    assert first["in_whitelist"] is True
    assert first["action"] == "kept"
    assert first["account"] == "user1"
    assert first["zone"] == "ru-2"

    second = json.loads(lines[1])
    assert second["ip"] == "5.6.7.8"
    assert second["action"] == "deleted"
