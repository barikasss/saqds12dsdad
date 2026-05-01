import json
from unittest.mock import patch

import pytest
import responses as resp_lib

from src.checkers.wl_api import (
    WLAuthError,
    WLCheckerClient,
    WLTimeoutError,
    _mask_key,
)

BASE_URL = "http://test.local:8082"
API_KEY = "supersecretapikey123"


def make_client(tmp_path, **kwargs) -> WLCheckerClient:
    defaults = dict(
        base_url=BASE_URL,
        api_key=API_KEY,
        submit_cooldown=0,
        poll_interval=0,
        poll_timeout=10,
        cooldown_state_file=str(tmp_path / ".wl_cooldown"),
    )
    defaults.update(kwargs)
    return WLCheckerClient(**defaults)


# ---------------------------------------------------------------------------
# 1. test_submit_success
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_submit_success(tmp_path):
    resp_lib.add(
        resp_lib.POST, f"{BASE_URL}/check",
        json={"job_id": "abc-123", "total": 8, "errors": []},
        status=200,
    )
    client = make_client(tmp_path)
    job_id = client.submit(["158.160.210.0/29"])

    assert job_id == "abc-123"
    req = resp_lib.calls[0].request
    assert req.headers["X-API-Key"] == API_KEY
    assert json.loads(req.body) == {"targets": ["158.160.210.0/29"]}


# ---------------------------------------------------------------------------
# 2. test_submit_cooldown
# ---------------------------------------------------------------------------

def test_submit_cooldown(tmp_path):
    # time.time() calls: [first_submit_check, first_submit_write,
    #                     second_submit_check, second_submit_write]
    time_seq = iter([1000.0, 1000.1, 1000.2, 1300.0])
    sleep_calls: list[float] = []

    with patch("src.checkers.wl_api.time") as mock_time:
        mock_time.time.side_effect = lambda: next(time_seq)
        mock_time.sleep.side_effect = lambda s: sleep_calls.append(s)

        with resp_lib.RequestsMock() as rsps:
            rsps.add(resp_lib.POST, f"{BASE_URL}/check",
                     json={"job_id": "j1", "total": 1, "errors": []})
            rsps.add(resp_lib.POST, f"{BASE_URL}/check",
                     json={"job_id": "j2", "total": 1, "errors": []})

            client = WLCheckerClient(
                base_url=BASE_URL,
                api_key=API_KEY,
                submit_cooldown=300,
                poll_interval=0,
                poll_timeout=10,
                cooldown_state_file=str(tmp_path / ".wl_cooldown"),
            )
            client.submit(["1.2.3.4"])   # elapsed=1000s → no wait
            client.submit(["1.2.3.5"])   # elapsed=0.1s  → wait ~299.9s

    assert len(sleep_calls) == 1
    assert sleep_calls[0] == pytest.approx(299.9, abs=0.5)


# ---------------------------------------------------------------------------
# 3. test_fetch_pending
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_fetch_pending(tmp_path):
    resp_lib.add(
        resp_lib.GET, f"{BASE_URL}/check/job-pending",
        json={
            "job_id": "job-pending",
            "total": 2,
            "done": 0,
            "pending": 2,
            "finished": False,
            "results": [
                {"ip": "1.2.3.1", "alive": None, "status": "pending"},
                {"ip": "1.2.3.2", "alive": None, "status": "pending"},
            ],
        },
    )
    client = make_client(tmp_path)
    data = client.fetch("job-pending")

    assert data["finished"] is False
    assert data["done"] == 0
    assert all(r["status"] == "pending" for r in data["results"])


# ---------------------------------------------------------------------------
# 4. test_wait_for_completion
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_wait_for_completion(tmp_path):
    resp_lib.add(
        resp_lib.GET, f"{BASE_URL}/check/job-xyz",
        json={"job_id": "job-xyz", "total": 2, "done": 1, "pending": 1,
              "finished": False,
              "results": [{"ip": "1.1.1.1", "alive": True, "status": "done"},
                          {"ip": "1.1.1.2", "alive": None, "status": "pending"}]},
    )
    resp_lib.add(
        resp_lib.GET, f"{BASE_URL}/check/job-xyz",
        json={"job_id": "job-xyz", "total": 2, "done": 2, "pending": 0,
              "finished": True,
              "results": [{"ip": "1.1.1.1", "alive": True, "status": "done"},
                          {"ip": "1.1.1.2", "alive": False, "status": "done"}]},
    )
    progress_calls: list[tuple[int, int]] = []
    client = make_client(tmp_path)
    data = client.wait_for_completion("job-xyz", on_progress=lambda d, t: progress_calls.append((d, t)))

    assert data["finished"] is True
    assert len(data["results"]) == 2
    assert len(resp_lib.calls) == 2
    assert (1, 2) in progress_calls
    assert (2, 2) in progress_calls


# ---------------------------------------------------------------------------
# 5. test_check_subnet
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_check_subnet(tmp_path):
    resp_lib.add(resp_lib.POST, f"{BASE_URL}/check",
                 json={"job_id": "job-sub", "total": 2, "errors": []})
    resp_lib.add(
        resp_lib.GET, f"{BASE_URL}/check/job-sub",
        json={"job_id": "job-sub", "total": 2, "done": 2, "pending": 0,
              "finished": True,
              "results": [{"ip": "10.0.0.1", "alive": True, "status": "done"},
                          {"ip": "10.0.0.2", "alive": False, "status": "done"},
                          {"ip": "10.0.0.3", "alive": None, "status": "pending"}]},
    )
    client = make_client(tmp_path)
    result = client.check_subnet("10.0.0.0/30")

    # pending IPs are excluded
    assert result == {"10.0.0.1": True, "10.0.0.2": False}


# ---------------------------------------------------------------------------
# 6. test_batch_split
# ---------------------------------------------------------------------------

def test_batch_split(tmp_path):
    # Each /24 = 256 IPs; three /24s = 768 IPs > MAX_BATCH_IPS=256
    # → each /24 must land in its own batch (3 batches total)
    cidrs = ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]
    client = make_client(tmp_path)

    submitted_batches: list[list[str]] = []

    def fake_submit(targets: list[str]) -> str:
        submitted_batches.append(list(targets))
        return f"job-{len(submitted_batches)}"

    def fake_wait(job_id: str, on_progress=None) -> dict:
        return {"finished": True, "results": []}

    client.submit = fake_submit  # type: ignore[method-assign]
    client.wait_for_completion = fake_wait  # type: ignore[method-assign]

    result = client.check_subnets_batch(cidrs)

    assert len(submitted_batches) == 3
    assert submitted_batches[0] == ["10.0.0.0/24"]
    assert submitted_batches[1] == ["10.0.1.0/24"]
    assert submitted_batches[2] == ["10.0.2.0/24"]
    assert set(result.keys()) == set(cidrs)


# ---------------------------------------------------------------------------
# 7. test_auth_error
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_auth_error(tmp_path):
    resp_lib.add(resp_lib.POST, f"{BASE_URL}/check", status=401)

    client = make_client(tmp_path)
    with pytest.raises(WLAuthError):
        client.submit(["1.2.3.4"])

    assert len(resp_lib.calls) == 1  # no retries on 401


# ---------------------------------------------------------------------------
# 8. test_logs_no_secret
# ---------------------------------------------------------------------------

def test_logs_no_secret(tmp_path):
    from structlog.testing import capture_logs

    with capture_logs() as cap:
        with resp_lib.RequestsMock() as rsps:
            rsps.add(resp_lib.POST, f"{BASE_URL}/check",
                     json={"job_id": "j1", "total": 1, "errors": []})
            client = make_client(tmp_path)
            client.submit(["1.2.3.4"])

    for event in cap:
        for v in event.values():
            assert API_KEY not in str(v), f"Full API key leaked in log event: {event}"


# ---------------------------------------------------------------------------
# 9. test_is_subnet_white_threshold
# ---------------------------------------------------------------------------

def test_is_subnet_white_threshold(tmp_path):
    client = make_client(tmp_path)

    # 13 alive out of 254 ≈ 5.1% → above 5% threshold
    results_above = {f"10.0.0.{i}": (i <= 13) for i in range(1, 255)}
    assert client.is_subnet_white(results_above, threshold=0.05) is True

    # 12 alive out of 254 ≈ 4.7% → below 5% threshold
    results_below = {f"10.0.0.{i}": (i <= 12) for i in range(1, 255)}
    assert client.is_subnet_white(results_below, threshold=0.05) is False

    # threshold=0 → any alive IP is enough
    assert client.is_subnet_white({"10.0.0.1": True, "10.0.0.2": False}, threshold=0) is True
    assert client.is_subnet_white({"10.0.0.1": False}, threshold=0) is False

    # empty dict → always False
    assert client.is_subnet_white({}) is False

    # mask helper sanity
    masked = _mask_key(API_KEY)
    assert API_KEY not in masked
    assert masked.startswith(API_KEY[:8])
    assert masked.endswith("...")
