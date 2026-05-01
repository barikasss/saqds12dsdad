"""
Orchestrator tests — bypass __init__ via object.__new__ to inject mock components.
"""
import signal
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, call

import pytest

from src.checkers.wl_api import WLCheckerClient
from src.orchestrator import AccountPool, Orchestrator
from src.subnet_source import SubnetSource


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def make_orch(
    tmp_path,
    priority_subnets=None,
    dry_run=False,
    no_icmp=True,
    resume=False,
) -> Orchestrator:
    orch = object.__new__(Orchestrator)
    orch.dry_run = dry_run
    orch.resume = resume
    orch.no_icmp = no_icmp
    orch._running = True
    orch._start_time = time.monotonic()
    orch._zone = "ru-2"
    orch.stats = {
        "total_subnets": 0,
        "checked": 0,
        "white_found": 0,
        "dead": 0,
        "ambiguous": 0,
        "start_time": datetime.now(timezone.utc).isoformat(),
    }
    orch.reroll_attempts = 15
    orch.ip_log_file = str(tmp_path / "ip_log.jsonl")

    orch.source = SubnetSource(
        priority_subnets=priority_subnets or [],
        seed_file="data/selectel_subnets_seed.txt",
        cache_file=str(tmp_path / "cache.json"),
        state_file=str(tmp_path / "state.json"),
    )

    orch.wl = WLCheckerClient(
        base_url="http://test.local",
        api_key="testkey",
        submit_cooldown=0,
        poll_interval=0,
        poll_timeout=10,
        cooldown_state_file=str(tmp_path / ".wl_cooldown"),
    )

    orch.selectel = MagicMock()
    # list_floating_ips returns [] by default (no pre-existing FIPs)
    orch.selectel.list_floating_ips = MagicMock(return_value=[])
    orch.selectel._region = "ru-2"

    orch.icmp = MagicMock()
    orch.tcp = MagicMock()
    orch.notifier = MagicMock()
    for m in ("notify_success", "notify_warning", "notify_error", "notify_progress", "notify"):
        setattr(orch.notifier, m, MagicMock(return_value=True))

    orch._account_pool = AccountPool([orch.selectel])
    orch._save_found_ip = MagicMock()

    return orch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fip(fip_id: str, ip: str) -> dict:
    return {"id": fip_id, "floating_ip_address": ip}


def wl_result_true(ip: str) -> dict:
    return {ip: True}


def wl_result_false(ip: str) -> dict:
    return {ip: False}


# ---------------------------------------------------------------------------
# 1. test_reroll_finds_white_ip — FIP lands in priority subnet, WLChecker confirms
# ---------------------------------------------------------------------------

def test_reroll_finds_white_ip(tmp_path):
    orch = make_orch(tmp_path, priority_subnets=["87.228.96.0/24"])

    orch.selectel.create_floating_ip_safe = MagicMock(
        return_value=_fip("fip-1", "87.228.96.5")
    )
    orch.wl.check_subnet = MagicMock(return_value=wl_result_true("87.228.96.5"))

    with pytest.raises(SystemExit) as exc_info:
        orch.run()

    assert exc_info.value.code == 0
    orch.selectel.create_floating_ip_safe.assert_called_once()
    orch.wl.check_subnet.assert_called_once_with("87.228.96.5/32")
    orch.notifier.notify_success.assert_called_once()
    orch._save_found_ip.assert_called_once()


# ---------------------------------------------------------------------------
# 2. test_fip_outside_whitelist_deleted — FIP outside whitelist → delete, loop stops
# ---------------------------------------------------------------------------

def test_fip_outside_whitelist_deleted(tmp_path):
    orch = make_orch(tmp_path, priority_subnets=["87.228.96.0/24"])

    # First call returns IP outside whitelist; side effect stops loop
    def make_fip_and_stop(*args, **kwargs):
        orch._running = False
        return _fip("fip-1", "5.5.5.5")

    orch.selectel.create_floating_ip_safe = MagicMock(side_effect=make_fip_and_stop)
    orch.selectel.delete_floating_ip = MagicMock()

    orch.run()

    orch.selectel.delete_floating_ip.assert_called_once_with("fip-1")
    orch.notifier.notify_success.assert_not_called()
    assert orch.stats["dead"] == 1


# ---------------------------------------------------------------------------
# 3. test_wl_rejection_deletes_fip — FIP in whitelist but WLChecker rejects it
# ---------------------------------------------------------------------------

def test_wl_rejection_deletes_fip(tmp_path):
    orch = make_orch(tmp_path, priority_subnets=["87.228.96.0/24"])

    call_count = [0]

    def make_fip(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] > 1:
            orch._running = False
        return _fip(f"fip-{call_count[0]}", "87.228.96.5")

    orch.selectel.create_floating_ip_safe = MagicMock(side_effect=make_fip)
    orch.selectel.delete_floating_ip = MagicMock()
    orch.wl.check_subnet = MagicMock(return_value=wl_result_false("87.228.96.5"))

    orch.run()

    # FIP deleted after WLChecker rejection
    orch.selectel.delete_floating_ip.assert_called()
    orch.notifier.notify_success.assert_not_called()


# ---------------------------------------------------------------------------
# 4. test_dry_run_no_selectel_calls
# ---------------------------------------------------------------------------

def test_dry_run_no_selectel_calls(tmp_path):
    orch = make_orch(tmp_path, priority_subnets=["87.228.90.0/24"], dry_run=True)

    with pytest.raises(SystemExit) as exc_info:
        orch.run()

    assert exc_info.value.code == 0
    orch.selectel.create_floating_ip_safe.assert_not_called()


# ---------------------------------------------------------------------------
# 5. test_sigint_saves_state
# ---------------------------------------------------------------------------

def test_sigint_saves_state(tmp_path):
    orch = make_orch(tmp_path)

    orch.source.mark("10.0.0.0/24", "dead", {})
    orch.source.mark("10.0.1.0/24", "ambiguous", {})

    with pytest.raises(SystemExit) as exc_info:
        orch._handle_shutdown(signal.SIGINT, None)

    assert exc_info.value.code == 130
    orch.notifier.notify_warning.assert_called()
    assert orch.source.get_state("10.0.0.0/24") is not None
    assert orch.source.get_state("10.0.1.0/24") is not None


# ---------------------------------------------------------------------------
# 6. test_existing_fip_confirmed — existing FIP passes filter + WLChecker → success
# ---------------------------------------------------------------------------

def test_existing_fip_confirmed(tmp_path):
    orch = make_orch(tmp_path, priority_subnets=["87.228.90.0/24"])

    existing = _fip("fip-old", "87.228.90.10")
    orch.selectel.list_floating_ips = MagicMock(return_value=[existing])
    orch.wl.check_subnet = MagicMock(return_value=wl_result_true("87.228.90.10"))

    with pytest.raises(SystemExit) as exc_info:
        orch.run()

    assert exc_info.value.code == 0
    orch.wl.check_subnet.assert_called_once_with("87.228.90.10/32")
    orch.notifier.notify_success.assert_called_once()
    # Main reroll loop never started — found in existing FIPs check
    orch.selectel.create_floating_ip_safe.assert_not_called()
