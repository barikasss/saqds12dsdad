"""Tests for Selectel Resell API client."""
import json
from unittest.mock import MagicMock, patch

import pytest
import responses as resp_lib

from src.proxy_pool import ResellProxyPool
from src.selectel_api import SelectelAPIError, SelectelClient, SelectelRateLimitError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_KEY = "test-api-key-12345"
ACCOUNT_ID = "577991"
PROJECT_ID = "96536fd09a294164aaf5592a79b5356e"
REGION = "ru-3"

RESELL_BASE = "https://api.selectel.ru/vpc/resell/v2"
FLOATINGIPS_URL = f"{RESELL_BASE}/floatingips"
CREATE_URL = f"{RESELL_BASE}/floatingips/projects/{PROJECT_ID}"


def make_client(**kwargs) -> SelectelClient:
    defaults = dict(
        account_id=ACCOUNT_ID,
        username="Priya",
        api_key=API_KEY,
        project_id=PROJECT_ID,
        region=REGION,
    )
    defaults.update(kwargs)
    return SelectelClient(**defaults)


def make_fip(ip: str, fip_id: str | None = None) -> dict:
    return {
        "id": fip_id or f"fip-{ip}",
        "floating_ip_address": ip,
        "region": REGION,
        "status": "DOWN",
        "project_id": PROJECT_ID,
    }


# ---------------------------------------------------------------------------
# 1. list_floating_ips
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_list_floating_ips_success():
    resp_lib.add(resp_lib.GET, FLOATINGIPS_URL, json={
        "floatingips": [
            make_fip("87.228.90.1", "fip-1"),
            make_fip("87.228.90.2", "fip-2"),
        ]
    })

    client = make_client()
    fips = client.list_floating_ips()

    assert len(fips) == 2
    assert fips[0]["floating_ip_address"] == "87.228.90.1"
    assert resp_lib.calls[0].request.headers["X-Token"] == API_KEY


@resp_lib.activate
def test_list_floating_ips_filters_by_project():
    resp_lib.add(resp_lib.GET, FLOATINGIPS_URL, json={
        "floatingips": [
            {**make_fip("1.2.3.4"), "project_id": "other-project"},
            make_fip("87.228.90.1"),  # own project
        ]
    })

    client = make_client()
    fips = client.list_floating_ips()

    assert len(fips) == 1
    assert fips[0]["floating_ip_address"] == "87.228.90.1"


@resp_lib.activate
def test_list_floating_ips_error():
    resp_lib.add(resp_lib.GET, FLOATINGIPS_URL, status=401, body="Unauthorized")

    client = make_client()
    with pytest.raises(SelectelAPIError) as exc:
        client.list_floating_ips()
    assert exc.value.status == 401


# ---------------------------------------------------------------------------
# 2. create_floating_ips_bulk
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_create_bulk_success():
    resp_lib.add(resp_lib.POST, CREATE_URL, json={
        "floatingips": [
            make_fip("178.72.153.1", "fip-a"),
            make_fip("178.72.153.2", "fip-b"),
        ]
    }, status=201)

    client = make_client()
    fips = client.create_floating_ips_bulk(2)

    assert len(fips) == 2
    assert fips[0]["floating_ip_address"] == "178.72.153.1"

    body = json.loads(resp_lib.calls[0].request.body)
    assert body == {"floatingips": [{"region": REGION, "quantity": 2}]}


@resp_lib.activate
def test_create_bulk_zero_returns_empty():
    client = make_client()
    result = client.create_floating_ips_bulk(0)
    assert result == []
    assert len(resp_lib.calls) == 0


@resp_lib.activate
def test_create_bulk_quota_exceeded_429():
    resp_lib.add(resp_lib.POST, CREATE_URL, status=429,
                 json={"error": "quota_exceeded"})

    client = make_client()
    with pytest.raises(SelectelRateLimitError):
        client.create_floating_ips_bulk(1)


@resp_lib.activate
def test_create_bulk_quota_exceeded_in_body():
    """quota_exceeded comes as 409."""
    resp_lib.add(resp_lib.POST, CREATE_URL, status=409,
                 json={"error": "quota_exceeded", "quotas": {}})

    client = make_client()
    with pytest.raises(SelectelRateLimitError):
        client.create_floating_ips_bulk(1)


@resp_lib.activate
def test_create_bulk_api_error():
    resp_lib.add(resp_lib.POST, CREATE_URL, status=500, body="Server Error")

    client = make_client()
    with pytest.raises(SelectelAPIError) as exc:
        client.create_floating_ips_bulk(1)
    assert exc.value.status == 500


# ---------------------------------------------------------------------------
# 3. delete_floating_ip
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_delete_success():
    resp_lib.add(resp_lib.DELETE, f"{RESELL_BASE}/floatingips/fip-123", status=204)

    client = make_client()
    result = client.delete_floating_ip("fip-123")

    assert result is True


@resp_lib.activate
def test_delete_not_found_returns_true():
    """404 on delete means already gone — treat as success."""
    resp_lib.add(resp_lib.DELETE, f"{RESELL_BASE}/floatingips/fip-gone", status=404)

    client = make_client()
    result = client.delete_floating_ip("fip-gone")

    assert result is True


@resp_lib.activate
def test_delete_error():
    resp_lib.add(resp_lib.DELETE, f"{RESELL_BASE}/floatingips/fip-x", status=403)

    client = make_client()
    with pytest.raises(SelectelAPIError):
        client.delete_floating_ip("fip-x")


# ---------------------------------------------------------------------------
# 4. Proxy rotation
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_proxy_pool_rotates():
    resp_lib.add(resp_lib.GET, FLOATINGIPS_URL, json={"floatingips": []})
    resp_lib.add(resp_lib.GET, FLOATINGIPS_URL, json={"floatingips": []})

    pool = ResellProxyPool(["socks5://p1:1080", "socks5://p2:1080"])
    client = make_client(proxy_pool=pool)

    client.list_floating_ips()
    client.list_floating_ips()

    assert pool._idx == 2  # advanced by 2


@resp_lib.activate
def test_proxy_error_retries():
    """ProxyError triggers retry up to max_retries."""
    resp_lib.add(resp_lib.GET, FLOATINGIPS_URL, body=resp_lib.ConnectionError())
    resp_lib.add(resp_lib.GET, FLOATINGIPS_URL, body=resp_lib.ConnectionError())
    resp_lib.add(resp_lib.GET, FLOATINGIPS_URL, body=resp_lib.ConnectionError())

    client = make_client()
    with pytest.raises(SelectelAPIError):
        client.list_floating_ips(max_conn_retries=3)


# ---------------------------------------------------------------------------
# 5. create_floating_ip_safe (compat wrapper)
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_create_floating_ip_safe_compat():
    resp_lib.add(resp_lib.POST, CREATE_URL, json={
        "floatingips": [make_fip("5.188.112.1", "fip-safe")]
    }, status=201)

    client = make_client()
    fip = client.create_floating_ip_safe()

    assert fip["id"] == "fip-safe"
    assert fip["floating_ip_address"] == "5.188.112.1"
