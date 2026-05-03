"""Tests for job_server FastAPI endpoints."""
import pytest
from fastapi.testclient import TestClient

import src.job_server as js
from src.job_server import app

SECRET = "test-secret-xyz"


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    """Clear in-memory state and set a known secret before each test."""
    monkeypatch.setattr(js, "_SECRET", SECRET)
    js._pending_jobs.clear()
    js._results.clear()


client = TestClient(app, raise_server_exceptions=True)

HEADERS = {"X-Secret": SECRET}


# ---------------------------------------------------------------------------

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_health_no_auth_required():
    r = client.get("/health", headers={})
    assert r.status_code == 200


def test_get_jobs_empty():
    r = client.get("/ping-jobs", headers=HEADERS)
    assert r.status_code == 200
    assert r.json() == []


def test_get_jobs_returns_enqueued():
    js.enqueue("10.0.0.0/24")
    js.enqueue("10.0.1.0/24")

    r = client.get("/ping-jobs", headers=HEADERS)
    assert r.status_code == 200
    jobs = r.json()
    assert "10.0.0.0/24" in jobs
    assert "10.0.1.0/24" in jobs


def test_get_jobs_max_10():
    for i in range(15):
        js.enqueue(f"10.0.{i}.0/24")

    r = client.get("/ping-jobs", headers=HEADERS)
    assert len(r.json()) == 10


def test_get_jobs_excludes_completed():
    js.enqueue("10.0.0.0/24")
    js.enqueue("10.0.1.0/24")
    # Simulate result received for first
    js._results["10.0.0.0/24"] = 5

    r = client.get("/ping-jobs", headers=HEADERS)
    jobs = r.json()
    assert "10.0.0.0/24" not in jobs
    assert "10.0.1.0/24" in jobs


def test_post_result_accepted():
    js.enqueue("10.0.0.0/24")

    r = client.post("/ping-results", json={
        "cidr": "10.0.0.0/24", "alive": 12, "total": 254,
    }, headers=HEADERS)
    assert r.status_code == 204


def test_post_result_sets_event():
    evt = js.enqueue("10.0.0.0/24")
    assert not evt.is_set()

    client.post("/ping-results", json={
        "cidr": "10.0.0.0/24", "alive": 7, "total": 254,
    }, headers=HEADERS)

    assert evt.is_set()
    assert js.get_result("10.0.0.0/24") == 7


def test_post_result_unknown_cidr():
    r = client.post("/ping-results", json={
        "cidr": "1.2.3.0/24", "alive": 0, "total": 254,
    }, headers=HEADERS)
    assert r.status_code == 404


def test_auth_missing_secret():
    js.enqueue("10.0.0.0/24")
    r = client.get("/ping-jobs")  # no X-Secret
    assert r.status_code == 403


def test_auth_wrong_secret():
    js.enqueue("10.0.0.0/24")
    r = client.get("/ping-jobs", headers={"X-Secret": "wrong"})
    assert r.status_code == 403


def test_enqueue_endpoint_adds_job():
    r = client.post("/enqueue", json={"cidr": "10.0.0.0/24"}, headers=HEADERS)
    assert r.status_code == 204

    jobs = client.get("/ping-jobs", headers=HEADERS).json()
    assert "10.0.0.0/24" in jobs


def test_get_ping_result_not_ready():
    js.enqueue("10.0.0.0/24")
    r = client.get("/ping-results", params={"cidr": "10.0.0.0/24"}, headers=HEADERS)
    assert r.status_code == 404


def test_get_ping_result_ready():
    js.enqueue("10.0.0.0/24")
    js._results["10.0.0.0/24"] = 17

    r = client.get("/ping-results", params={"cidr": "10.0.0.0/24"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json() == {"cidr": "10.0.0.0/24", "alive": 17}


def test_clear_removes_job_and_result():
    js.enqueue("10.0.0.0/24")
    js._results["10.0.0.0/24"] = 3

    js.clear("10.0.0.0/24")

    assert js.get_result("10.0.0.0/24") is None
    r = client.get("/ping-jobs", headers=HEADERS)
    assert "10.0.0.0/24" not in r.json()
