"""
Orchestrator tests — bypass __init__ via object.__new__ to inject mock components.
"""
import signal
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from src.checkers.wl_api import WLCheckerClient
from src.orchestrator import Orchestrator
from src.subnet_source import SubnetSource


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def make_orch(
    tmp_path,
    priority_subnets=None,
    dry_run=False,
    no_icmp=True,
    phase="both",
    resume=False,
) -> Orchestrator:
    orch = object.__new__(Orchestrator)
    orch.dry_run = dry_run
    orch.resume = resume
    orch.phase = phase
    orch.no_icmp = no_icmp
    orch._running = True
    orch._start_time = time.monotonic()
    orch.stats = {
        "total_subnets": 0,
        "checked": 0,
        "white_found": 0,
        "dead": 0,
        "ambiguous": 0,
        "start_time": datetime.now(timezone.utc).isoformat(),
    }
    orch.max_iter = 100
    orch.shuffle = False
    orch.reroll_attempts = 15

    # Real SubnetSource with tmp files, mock network methods
    orch.source = SubnetSource(
        priority_subnets=priority_subnets or [],
        seed_file="data/selectel_subnets_seed.txt",
        cache_file=str(tmp_path / "cache.json"),
        state_file=str(tmp_path / "state.json"),
    )

    # Real WLCheckerClient (gives us real is_subnet_white); only network methods mocked
    orch.wl = WLCheckerClient(
        base_url="http://test.local",
        api_key="testkey",
        submit_cooldown=0,
        poll_interval=0,
        poll_timeout=10,
        cooldown_state_file=str(tmp_path / ".wl_cooldown"),
    )

    # Full mocks for Selectel + local checkers + notifier
    orch.selectel = MagicMock()
    orch.icmp = MagicMock()
    orch.tcp = MagicMock()
    orch.notifier = MagicMock()
    for m in ("notify_success", "notify_warning", "notify_error", "notify_progress", "notify"):
        setattr(orch.notifier, m, MagicMock(return_value=True))

    # Avoid writing to data/found_ips.json in tests
    orch._save_found_ip = MagicMock()

    return orch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def dead_results(cidr_prefix: str) -> dict[str, bool]:
    return {f"{cidr_prefix}.{i}": False for i in range(1, 255)}


def white_results(cidr_prefix: str, alive: int = 20) -> dict[str, bool]:
    return {f"{cidr_prefix}.{i}": (i <= alive) for i in range(1, 255)}


# ---------------------------------------------------------------------------
# 1. test_phase1_finds_white_in_priority
# ---------------------------------------------------------------------------

def test_phase1_finds_white_in_priority(tmp_path):
    orch = make_orch(tmp_path, priority_subnets=["87.228.96.0/24"])

    # 20/254 ≈ 7.9% alive; threshold=0.0 (any alive) → white
    orch.wl.check_subnets_batch = MagicMock(
        return_value={"87.228.96.0/24": white_results("87.228.96")}
    )
    orch.selectel.reroll_until_in_subnet = MagicMock(return_value={
        "id": "fip-1", "floating_ip_address": "87.228.96.5",
    })

    with pytest.raises(SystemExit) as exc_info:
        orch.run()

    assert exc_info.value.code == 0
    orch.wl.check_subnets_batch.assert_called_once_with(["87.228.96.0/24"])
    orch.selectel.reroll_until_in_subnet.assert_called_once_with(
        "87.228.96.0/24", max_attempts=15
    )
    orch.notifier.notify_success.assert_called_once()


# ---------------------------------------------------------------------------
# 2. test_phase2_iteration — first 4 dead, 5th white → exit 0
# ---------------------------------------------------------------------------

def test_phase2_iteration(tmp_path):
    orch = make_orch(tmp_path, no_icmp=True, phase="2")

    subnets = [f"10.0.{i}.0/24" for i in range(5)]
    orch.source.get_unchecked = MagicMock(return_value=subnets)
    orch.source.refresh_from_ripe = MagicMock(return_value=5)

    call_n = [0]

    def fake_check_subnet(cidr, on_progress=None):
        call_n[0] += 1
        if call_n[0] == 5:
            return white_results("10.0.4")   # 20/254 ≈ 7.9% > 5% → white
        return dead_results(f"10.0.{call_n[0]-1}")

    orch.wl.check_subnet = fake_check_subnet
    orch.selectel.reroll_until_in_subnet = MagicMock(return_value={
        "id": "fip-5", "floating_ip_address": "10.0.4.5",
    })

    with pytest.raises(SystemExit) as exc_info:
        orch.run()

    assert exc_info.value.code == 0
    assert call_n[0] == 5
    orch.selectel.reroll_until_in_subnet.assert_called_once_with(
        "10.0.4.0/24", max_attempts=15
    )


# ---------------------------------------------------------------------------
# 3. test_dry_run_no_selectel_calls
# ---------------------------------------------------------------------------

def test_dry_run_no_selectel_calls(tmp_path):
    orch = make_orch(tmp_path, priority_subnets=["87.228.90.0/24"], dry_run=True)

    orch.wl.check_subnets_batch = MagicMock(
        return_value={"87.228.90.0/24": white_results("87.228.90")}
    )

    with pytest.raises(SystemExit) as exc_info:
        orch.run()

    assert exc_info.value.code == 0
    # In dry_run, the reroll (which calls create_floating_ip) must NOT happen
    orch.selectel.reroll_until_in_subnet.assert_not_called()
    orch.selectel.create_floating_ip.assert_not_called()


# ---------------------------------------------------------------------------
# 4. test_resume_skips_checked
# ---------------------------------------------------------------------------

def test_resume_skips_checked(tmp_path):
    orch = make_orch(tmp_path, no_icmp=True, phase="2")

    # Pre-mark 3 subnets as dead (already checked)
    for i in range(1, 4):
        orch.source.mark(f"10.0.{i}.0/24", "dead")

    # RIPE returns 5; get_unchecked returns only the 2 unmarked
    orch.source.refresh_from_ripe = MagicMock(return_value=5)
    orch.source.get_unchecked = MagicMock(
        return_value=[f"10.0.{i}.0/24" for i in range(4, 6)]
    )

    checked: list[str] = []

    def fake_check(cidr, on_progress=None):
        checked.append(cidr)
        return dead_results("10.0.0")

    orch.wl.check_subnet = fake_check
    orch.run()   # no white found → normal exit (no sys.exit)

    assert len(checked) == 2
    assert "10.0.4.0/24" in checked
    assert "10.0.5.0/24" in checked
    for i in range(1, 4):
        assert f"10.0.{i}.0/24" not in checked


# ---------------------------------------------------------------------------
# 5. test_sigint_saves_state
# ---------------------------------------------------------------------------

def test_sigint_saves_state(tmp_path):
    orch = make_orch(tmp_path)

    # Put some state first
    orch.source.mark("10.0.0.0/24", "dead", {})
    orch.source.mark("10.0.1.0/24", "ambiguous", {})

    with pytest.raises(SystemExit) as exc_info:
        orch._handle_shutdown(signal.SIGINT, None)

    assert exc_info.value.code == 130
    orch.notifier.notify_warning.assert_called()

    # State was preserved
    assert orch.source.get_state("10.0.0.0/24") is not None
    assert orch.source.get_state("10.0.1.0/24") is not None


# ---------------------------------------------------------------------------
# 6. test_reroll_failure_warns
# ---------------------------------------------------------------------------

def test_reroll_failure_warns(tmp_path):
    orch = make_orch(tmp_path, priority_subnets=["87.228.90.0/24"])

    orch.wl.check_subnets_batch = MagicMock(
        return_value={"87.228.90.0/24": white_results("87.228.90")}
    )
    orch.selectel.reroll_until_in_subnet = MagicMock(return_value=None)  # exhausted

    with pytest.raises(SystemExit) as exc_info:
        orch.run()

    assert exc_info.value.code == 1
    orch.notifier.notify_warning.assert_called()
    # Warning message must mention the subnet
    warn_msg = orch.notifier.notify_warning.call_args[0][0]
    assert "87.228.90.0/24" in warn_msg
