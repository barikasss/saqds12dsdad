"""Tests for the rewritten Orchestrator + WLKeyPool."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import responses
import yaml

from src.checkers.wl_pool import WLKeyPool
from pathlib import Path

from src.orchestrator import (
    AccountPool,
    MAX_FIPS_PER_ACCOUNT,
    Orchestrator,
    SubnetTask,
)
from src.selectel_api import SelectelRateLimitError


CONFIG = {
    "selectel": {"availability_zone": "ru-2"},
    "selectel_accounts": [],
    "search": {
        "priority_subnets": ["10.0.0.0/24"],
    },
    "checkers": {
        "icmp": {"timeout": 0.1, "concurrency": 4},
        "wlchecker": {
            "base_url": "http://wl",
            "submit_cooldown_seconds": 300,
        },
    },
    "notifier": {"telegram": {}},
}


@pytest.fixture
def write_config(tmp_path, monkeypatch):
    """tmp_path becomes cwd; an isolated config.yaml lives there."""
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.dump(CONFIG))
    for var in ("SELECTEL_USERNAME", "SELECTEL_PASSWORD", "SELECTEL_ACCOUNT_ID",
                "SELECTEL_PROJECT_ID", "WL_API_KEYS", "TG_BOT_TOKEN", "TG_CHAT_ID"):
        monkeypatch.delenv(var, raising=False)
    return str(config_path)


# ---------------------------------------------------------------------------
# 1. WLKeyPool round-robin: first 3 keys in cooldown → picks 4th
# ---------------------------------------------------------------------------

@responses.activate
def test_wl_key_pool_round_robin():
    keys = [f"k{i}" for i in range(7)]
    pool = WLKeyPool(keys=keys, base_url="http://wl", cooldown_seconds=300)

    for k in keys[:3]:
        pool.mark_cooldown(k)

    responses.add(
        responses.POST, "http://wl/check",
        json={"job_id": "job-xyz"}, status=200,
    )

    result = pool.submit("10.0.0.0/24")

    assert result is not None
    job_id, used_key = result
    assert job_id == "job-xyz"
    assert used_key == "k3"
    assert responses.calls[0].request.headers.get("X-API-Key") == "k3"


# ---------------------------------------------------------------------------
# 2. SubnetTask flow: ICMP True + WL True → confirmed winner
# ---------------------------------------------------------------------------

def test_subnet_task_flow(write_config):
    orch = Orchestrator(config_path=write_config, dry_run=True)

    task = SubnetTask(
        cidr="10.0.0.0/24",
        fip_id="dry-1",
        fip_ip="10.0.0.5",
        account="dry-A",
        client=orch._account_pool.clients[0],
        icmp_result=True,
        wl_result=True,
    )
    orch._pending_tasks.append(task)

    winner = orch._decision_phase()

    assert winner is task
    assert orch.stats["white_found"] == 1


def test_subnet_task_icmp_fallback(write_config):
    """ICMP alive but WL unavailable (no keys) >120s → winner by fallback."""
    import time
    orch = Orchestrator(config_path=write_config, dry_run=True)

    task = SubnetTask(
        cidr="10.0.0.0/24",
        fip_id="dry-1",
        fip_ip="10.0.0.5",
        account="dry-A",
        client=orch._account_pool.clients[0],
        icmp_result=True,
        wl_job_id=None,
        wl_result=None,
    )
    task.created_at = time.time() - 200  # simulate 200s old task
    orch._pending_tasks.append(task)

    winner = orch._decision_phase()

    assert winner is task
    assert orch.stats["white_found"] == 1


def test_subnet_task_suspect(write_config):
    """ICMP alive but WL dead → suspect: FIP kept, stats updated, no deletion."""
    orch = Orchestrator(config_path=write_config, dry_run=True)
    client = orch._account_pool.clients[0]

    task = SubnetTask(
        cidr="10.0.0.0/24",
        fip_id="dry-1",
        fip_ip="10.0.0.5",
        account="dry-A",
        client=client,
        icmp_result=True,
        wl_result=False,
    )
    orch._pending_tasks.append(task)

    winner = orch._decision_phase()

    assert winner is None
    assert orch.stats["suspects"] == 1
    assert orch.stats["dead"] == 0
    assert task not in orch._pending_tasks


# ---------------------------------------------------------------------------
# 3. Non-whitelist IPs are deleted immediately during _create_phase
# ---------------------------------------------------------------------------

def test_not_in_whitelist_delete(write_config):
    orch = Orchestrator(config_path=write_config, dry_run=True)

    bad_fip = {"id": "f-bad", "floating_ip_address": "1.2.3.4"}  # outside 10.0.0.0/24

    fake = MagicMock()
    fake.username = "fake"
    fake._region = "ru-2"
    fake.list_floating_ips.return_value = []
    # First call yields a non-whitelist FIP, second raises rate-limit so we stop
    fake.create_floating_ip_safe.side_effect = [
        bad_fip,
        SelectelRateLimitError(429, "stop"),
    ]
    fake.delete_floating_ip.return_value = True

    orch._clients = [fake]
    orch._account_pool = AccountPool([fake])

    orch._create_phase()

    fake.delete_floating_ip.assert_called_once_with("f-bad")
    assert orch._pending_tasks == []
    assert orch.stats["deleted_not_in_whitelist"] == 1


# ---------------------------------------------------------------------------
# 4. _create_phase respects MAX_FIPS_PER_ACCOUNT
# ---------------------------------------------------------------------------

def test_max_fips_limit(write_config):
    orch = Orchestrator(config_path=write_config, dry_run=True)

    counter = {"i": 0}

    def make_fip(network_id=None, availability_zone=None):
        counter["i"] += 1
        return {"id": f"f-{counter['i']}", "floating_ip_address": "10.0.0.10"}

    fake = MagicMock()
    fake.username = "fake"
    fake._region = "ru-2"
    fake.list_floating_ips.return_value = []
    fake.create_floating_ip_safe.side_effect = make_fip
    fake.delete_floating_ip.return_value = True

    orch._clients = [fake]
    orch._account_pool = AccountPool([fake])

    orch._create_phase()

    assert fake.create_floating_ip_safe.call_count == MAX_FIPS_PER_ACCOUNT
    assert len(orch._pending_tasks) == MAX_FIPS_PER_ACCOUNT


# ---------------------------------------------------------------------------
# 5. All accounts blocked → orchestrator sleeps via next_available_in()
# ---------------------------------------------------------------------------

def test_rate_limit_sleep(write_config, monkeypatch):
    orch = Orchestrator(config_path=write_config, dry_run=True)

    until = datetime.now(timezone.utc) + timedelta(seconds=30)
    for c in orch._account_pool.clients:
        orch._account_pool.mark_rate_limited(c, until)

    assert orch._account_pool.all_blocked()
    wait = orch._account_pool.next_available_in()
    assert 25 <= wait <= 35

    sleeps: list[float] = []

    def fake_sleep(s):
        sleeps.append(s)
        orch._running = False  # break out after the first sleep call

    monkeypatch.setattr(orch, "_create_phase", lambda: None)
    monkeypatch.setattr(orch, "_verify_phase", lambda: None)
    monkeypatch.setattr(orch, "_decision_phase", lambda: None)

    import src.orchestrator as orch_mod
    monkeypatch.setattr(orch_mod.time, "sleep", fake_sleep)

    orch.run()

    assert sleeps, "orchestrator did not sleep when all accounts were blocked"
    assert sleeps[0] > 0
    assert sleeps[0] <= 120  # clamped


# ---------------------------------------------------------------------------
# 6. Dead subnet cache
# ---------------------------------------------------------------------------

def test_dead_subnet_loaded_from_file(write_config, tmp_path):
    """Dead subnets file is read at startup into _dead_subnets."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(exist_ok=True)
    (data_dir / "dead_subnets.txt").write_text("10.0.0.0/24\n192.168.1.0/24\n")

    orch = Orchestrator(config_path=write_config, dry_run=True)

    assert "10.0.0.0/24" in orch._dead_subnets
    assert "192.168.1.0/24" in orch._dead_subnets


def test_dead_subnet_skipped_in_create_phase(write_config, tmp_path):
    """FIP in a known-dead /24 is deleted immediately without creating a task."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(exist_ok=True)
    (data_dir / "dead_subnets.txt").write_text("10.0.0.0/24\n")

    orch = Orchestrator(config_path=write_config, dry_run=True)

    dead_fip = {"id": "f-dead", "floating_ip_address": "10.0.0.5"}

    fake = MagicMock()
    fake.username = "fake"
    fake._region = "ru-2"
    fake.list_floating_ips.return_value = []
    fake.create_floating_ip_safe.side_effect = [
        dead_fip,
        SelectelRateLimitError(429, "stop"),
    ]
    fake.delete_floating_ip.return_value = True

    orch._clients = [fake]
    orch._account_pool = AccountPool([fake])

    orch._create_phase()

    fake.delete_floating_ip.assert_called_once_with("f-dead")
    assert orch._pending_tasks == []
    assert orch.stats["skipped_dead_subnet"] == 1


def test_dead_decision_writes_to_cache(write_config, tmp_path):
    """ICMP=False → subnet added to _dead_subnets in memory and written to file."""
    orch = Orchestrator(config_path=write_config, dry_run=True)

    task = SubnetTask(
        cidr="10.0.0.0/24",
        fip_id="f-1",
        fip_ip="10.0.0.5",
        account="dry-A",
        client=orch._account_pool.clients[0],
        icmp_result=False,
    )
    orch._pending_tasks.append(task)

    orch._decision_phase()

    assert "10.0.0.0/24" in orch._dead_subnets
    dead_file = tmp_path / "data" / "dead_subnets.txt"
    assert dead_file.exists()
    assert "10.0.0.0/24" in dead_file.read_text()


def test_dead_subnet_not_duplicated_in_file(write_config, tmp_path):
    """Same dead subnet is not appended twice if it's already in the cache."""
    orch = Orchestrator(config_path=write_config, dry_run=True)
    orch._dead_subnets.add("10.0.0.0/24")  # already in cache

    task = SubnetTask(
        cidr="10.0.0.0/24",
        fip_id="f-2",
        fip_ip="10.0.0.7",
        account="dry-A",
        client=orch._account_pool.clients[0],
        icmp_result=False,
    )
    orch._pending_tasks.append(task)
    orch._decision_phase()

    # File should not exist (was never written since cidr was already cached)
    dead_file = tmp_path / "data" / "dead_subnets.txt"
    assert not dead_file.exists()
