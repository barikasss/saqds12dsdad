import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import responses as resp_lib

from src.subnet_source import SubnetSource, _atomic_write, _to_24s

RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
SEED_FILE = "data/selectel_subnets_seed.txt"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def make_source(tmp_path, priority_subnets=None, **kwargs) -> SubnetSource:
    defaults = dict(
        priority_subnets=priority_subnets or [],
        seed_file=SEED_FILE,
        cache_file=str(tmp_path / "cache.json"),
        state_file=str(tmp_path / "state.json"),
        cache_ttl_hours=24,
    )
    defaults.update(kwargs)
    return SubnetSource(**defaults)


def _ripe_resp(prefixes: list[str]) -> dict:
    return {"data": {"prefixes": [{"prefix": p} for p in prefixes]}}


# ---------------------------------------------------------------------------
# 1. test_priority_first
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_priority_first(tmp_path):
    resp_lib.add(resp_lib.GET, RIPE_URL, json=_ripe_resp(["1.0.0.0/24", "2.0.0.0/24"]))

    source = make_source(tmp_path, priority_subnets=["87.228.90.0/24", "87.228.96.0/24"])
    subnets = source.get_all_subnets()

    assert subnets[0] == "87.228.90.0/24"
    assert subnets[1] == "87.228.96.0/24"
    assert "1.0.0.0/24" in subnets
    # priority subnets must precede RIPE-sourced ones
    assert subnets.index("87.228.90.0/24") < subnets.index("1.0.0.0/24")


# ---------------------------------------------------------------------------
# 2. test_seed_loaded
# ---------------------------------------------------------------------------

def test_seed_loaded(tmp_path):
    # RIPE fails → module falls back to seed file
    source = make_source(tmp_path)
    with patch("src.subnet_source.requests.get", side_effect=OSError("offline")):
        subnets = source.get_all_subnets()

    assert "87.228.90.0/24" in subnets
    assert "87.228.96.0/24" in subnets
    # Seed has /22 entries that must be expanded to /24s
    assert "87.228.84.0/24" in subnets   # part of 87.228.84.0/22
    assert len(subnets) >= 10


# ---------------------------------------------------------------------------
# 3. test_ripe_fetch_and_split
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_ripe_fetch_and_split(tmp_path):
    resp_lib.add(resp_lib.GET, RIPE_URL, json=_ripe_resp([
        "5.188.112.0/22",   # → 4 /24s: .112 .113 .114 .115
        "1.2.3.0/24",       # → 1 /24 as-is
        "10.0.0.4/30",      # > /24 → ignored
    ]))

    source = make_source(tmp_path)
    count = source.refresh_from_ripe()

    assert count == 5

    cache = json.loads((tmp_path / "cache.json").read_text())
    for net in ("5.188.112.0/24", "5.188.113.0/24", "5.188.114.0/24", "5.188.115.0/24"):
        assert net in cache["subnets_24"]
    assert "1.2.3.0/24" in cache["subnets_24"]
    assert "10.0.0.4/30" not in cache["subnets_24"]
    assert cache["asn"] == 49505
    assert "fetched_at" in cache


# ---------------------------------------------------------------------------
# 4. test_cache_ttl
# ---------------------------------------------------------------------------

def test_cache_ttl(tmp_path):
    # Write a cache that is 25 hours old (beyond default 24-hour TTL)
    stale_ts = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    stale_cache = {
        "fetched_at": stale_ts,
        "asn": 49505,
        "subnets_24": ["10.99.99.0/24"],   # not in seed file
    }
    (tmp_path / "cache.json").write_text(json.dumps(stale_cache))

    source = make_source(tmp_path)

    # RIPE also fails → must fall back to seed, NOT stale cache
    with patch("src.subnet_source.requests.get", side_effect=OSError("offline")):
        subnets = source.get_all_subnets()

    assert "10.99.99.0/24" not in subnets   # stale cache was not used
    assert "87.228.90.0/24" in subnets      # seed was used


# ---------------------------------------------------------------------------
# 5. test_mark_and_get_state
# ---------------------------------------------------------------------------

def test_mark_and_get_state(tmp_path):
    source = make_source(tmp_path)

    source.mark("87.228.90.0/24", "white", {"alive_count": 13, "tcp_open": 5})
    entry = source.get_state("87.228.90.0/24")

    assert entry is not None
    assert entry["status"] == "white"
    assert entry["evidence"]["alive_count"] == 13
    assert "checked_at" in entry

    # State file was actually written
    assert (tmp_path / "state.json").exists()
    raw = json.loads((tmp_path / "state.json").read_text())
    assert "87.228.90.0/24" in raw


# ---------------------------------------------------------------------------
# 6. test_unchecked_excludes_marked
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_unchecked_excludes_marked(tmp_path):
    resp_lib.add(resp_lib.GET, RIPE_URL, json=_ripe_resp([
        "1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24", "4.0.0.0/24",
    ]))

    source = make_source(tmp_path, priority_subnets=["1.0.0.0/24"])
    source.mark("2.0.0.0/24", "dead")
    source.mark("3.0.0.0/24", "white")

    unchecked = source.get_unchecked()

    assert "1.0.0.0/24" in unchecked        # priority, not yet marked
    assert "4.0.0.0/24" in unchecked        # regular, not yet marked
    assert "2.0.0.0/24" not in unchecked    # dead
    assert "3.0.0.0/24" not in unchecked    # white

    # Priority subnet must be first
    assert unchecked.index("1.0.0.0/24") < unchecked.index("4.0.0.0/24")


# ---------------------------------------------------------------------------
# 7. test_atomic_write
# ---------------------------------------------------------------------------

def test_atomic_write(tmp_path):
    path = tmp_path / "state.json"

    # Normal write
    _atomic_write(str(path), {"version": 1})
    assert json.loads(path.read_text()) == {"version": 1}

    # Overwrite
    _atomic_write(str(path), {"version": 2})
    assert json.loads(path.read_text()) == {"version": 2}

    # No stray tmp files
    assert not list(tmp_path.glob("*.tmp"))

    # --- Interrupt simulation ---
    # If os.replace is interrupted (SIGKILL scenario), the original file
    # must remain intact and no tmp files must be left behind.
    with patch("os.replace", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            _atomic_write(str(path), {"should_not_appear": True})

    assert json.loads(path.read_text()) == {"version": 2}   # original preserved
    assert not list(tmp_path.glob("*.tmp"))                  # tmp cleaned up


# ---------------------------------------------------------------------------
# 8. test_stats
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_stats(tmp_path):
    resp_lib.add(resp_lib.GET, RIPE_URL, json=_ripe_resp([
        "1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24", "4.0.0.0/24",
    ]))

    source = make_source(tmp_path)
    source.mark("1.0.0.0/24", "white")
    source.mark("2.0.0.0/24", "dead")
    source.mark("3.0.0.0/24", "ambiguous")

    s = source.stats()

    assert s["total_known"] == 4
    assert s["white"] == 1
    assert s["dead"] == 1
    assert s["ambiguous"] == 1
    assert s["checked"] == 3
    assert s["unchecked"] == 1
