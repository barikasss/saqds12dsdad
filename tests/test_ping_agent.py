"""Tests for ping_agent — fetch_jobs, report_result, run_once."""
from unittest.mock import MagicMock, patch

import pytest
import responses as resp_lib

import ping_agent as pa

VM = "http://10.0.0.1:8888"
SECRET = "test-secret"


@pytest.fixture(autouse=True)
def patch_env(monkeypatch):
    monkeypatch.setattr(pa, "VM_URL", VM)
    monkeypatch.setattr(pa, "SECRET", SECRET)
    monkeypatch.setattr(pa, "_HEADERS", {"X-Secret": SECRET})


# ---------------------------------------------------------------------------

@resp_lib.activate
def test_fetch_jobs_returns_list():
    resp_lib.add(resp_lib.GET, f"{VM}/ping-jobs",
                 json=["10.0.0.0/24", "10.0.1.0/24"], status=200)

    jobs = pa.fetch_jobs()

    assert jobs == ["10.0.0.0/24", "10.0.1.0/24"]
    assert resp_lib.calls[0].request.headers["X-Secret"] == SECRET


@resp_lib.activate
def test_fetch_jobs_empty():
    resp_lib.add(resp_lib.GET, f"{VM}/ping-jobs", json=[], status=200)
    assert pa.fetch_jobs() == []


@resp_lib.activate
def test_report_result_sends_correct_body():
    resp_lib.add(resp_lib.POST, f"{VM}/ping-results", status=204)

    pa.report_result("10.0.0.0/24", alive=12)

    import json
    body = json.loads(resp_lib.calls[0].request.body)
    assert body == {"cidr": "10.0.0.0/24", "alive": 12, "total": 254}
    assert resp_lib.calls[0].request.headers["X-Secret"] == SECRET


@resp_lib.activate
def test_run_once_pings_and_reports():
    resp_lib.add(resp_lib.POST, f"{VM}/ping-results", status=204)
    resp_lib.add(resp_lib.POST, f"{VM}/ping-results", status=204)

    mock_checker = MagicMock()
    mock_checker.ping_subnet.side_effect = [
        {"10.0.0.1": True,  "10.0.0.2": False},  # 1 alive
        {"10.0.1.1": False, "10.0.1.2": False},   # 0 alive
    ]

    with patch.object(pa, "_checker", mock_checker):
        pa.run_once(["10.0.0.0/24", "10.0.1.0/24"])

    import json
    bodies = [json.loads(c.request.body) for c in resp_lib.calls]
    assert bodies[0]["cidr"] == "10.0.0.0/24"
    assert bodies[0]["alive"] == 1
    assert bodies[1]["cidr"] == "10.0.1.0/24"
    assert bodies[1]["alive"] == 0


@resp_lib.activate
def test_run_once_reports_zero_on_ping_error():
    resp_lib.add(resp_lib.POST, f"{VM}/ping-results", status=204)

    mock_checker = MagicMock()
    mock_checker.ping_subnet.side_effect = OSError("no raw socket")

    with patch.object(pa, "_checker", mock_checker):
        pa.run_once(["10.0.0.0/24"])

    import json
    body = json.loads(resp_lib.calls[0].request.body)
    assert body["alive"] == 0


def test_main_exits_without_vm_url(monkeypatch):
    monkeypatch.setattr(pa, "VM_URL", "")
    with pytest.raises(SystemExit):
        pa.main()
