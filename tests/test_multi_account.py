"""Tests for AccountPool, SubnetFilter, and Selectel rate-limit signalling."""
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from src.orchestrator import AccountPool
from src.selectel_api import SelectelClient, SelectelRateLimitError
from src.subnet_filter import SubnetFilter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_client(username: str = "user") -> SelectelClient:
    c = MagicMock(spec=SelectelClient)
    c.username = username
    return c


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
# 3. test_whitelist_lookup_o1
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


