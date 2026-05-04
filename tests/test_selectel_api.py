"""Tests for Selectel API client (OpenStack create/delete + Resell list)."""
import json
from unittest.mock import MagicMock, patch, create_autospec

import pytest
import responses as resp_lib

from src.proxy_pool import ResellProxyPool
from src.selectel_api import SelectelAPIError, SelectelClient, SelectelRateLimitError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ACCOUNT_ID = "577991"
USERNAME = "Priya"
PASSWORD = "s3cr3t"
API_KEY = "test-api-key-12345"
PROJECT_ID = "96536fd09a294164aaf5592a79b5356e"
REGION = "ru-3"

IDENTITY_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"
KS_TOKEN = "ks-subject-token-xyz"
EXPIRES_AT = "2030-01-01T12:00:00.000000Z"

NET_BASE = f"https://{REGION}.cloud.api.selcloud.ru/network/v2.0"
FLOATINGIPS_URL = f"{NET_BASE}/floatingips"
NETWORKS_URL = f"{NET_BASE}/networks"

RESELL_BASE = "https://api.selectel.ru/vpc/resell/v2"
RESELL_FLOATINGIPS_URL = f"{RESELL_BASE}/floatingips"


def make_client(**kwargs) -> SelectelClient:
    defaults = dict(
        account_id=ACCOUNT_ID,
        username=USERNAME,
        api_key=API_KEY,
        password=PASSWORD,
        project_id=PROJECT_ID,
        region=REGION,
    )
    defaults.update(kwargs)
    return SelectelClient(**defaults)


def add_auth_ok(rsps, token: str = KS_TOKEN) -> None:
    rsps.add(
        resp_lib.POST, IDENTITY_URL,
        json={"token": {"expires_at": EXPIRES_AT}},
        headers={"X-Subject-Token": token},
        status=201,
    )


def add_networks(rsps) -> None:
    rsps.add(resp_lib.GET, NETWORKS_URL,
             json={"networks": [{"id": "ext-net-1"}]},
             match_querystring=False)


def make_fip(ip: str, fip_id: str | None = None) -> dict:
    return {
        "id": fip_id or f"fip-{ip}",
        "floating_ip_address": ip,
        "floating_network_id": "ext-net-1",
        "status": "DOWN",
    }


# ---------------------------------------------------------------------------
# 1. Auth — Keystone password method
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_auth_password_method():
    add_auth_ok(resp_lib, "ks-pw-token")

    client = make_client()
    token = client._auth()

    assert token == "ks-pw-token"
    auth_body = json.loads(resp_lib.calls[0].request.body)
    assert auth_body["auth"]["identity"]["methods"][0] == "password"
    assert auth_body["auth"]["identity"]["password"]["user"]["name"] == USERNAME


@resp_lib.activate
def test_auth_cached():
    add_auth_ok(resp_lib)
    add_auth_ok(resp_lib)  # second call in case not cached

    client = make_client()
    t1 = client._auth()
    t2 = client._auth()  # should use cache

    assert t1 == t2 == KS_TOKEN
    # only one actual auth request (second from cache)
    auth_calls = [c for c in resp_lib.calls
                  if "identity" in c.request.url]
    assert len(auth_calls) == 1


@resp_lib.activate
def test_auth_no_credentials_raises():
    client = SelectelClient(api_key=API_KEY)  # no password
    with pytest.raises(SelectelAPIError):
        client._auth()


# ---------------------------------------------------------------------------
# 2. list_floating_ips — Resell API
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_list_floating_ips_success():
    resp_lib.add(resp_lib.GET, RESELL_FLOATINGIPS_URL, json={
        "floatingips": [
            {"id": "fip-1", "floating_ip_address": "87.228.90.1",
             "project_id": PROJECT_ID},
        ]
    })

    client = make_client()
    fips = client.list_floating_ips()

    assert len(fips) == 1
    assert resp_lib.calls[0].request.headers["X-Token"] == API_KEY


@resp_lib.activate
def test_list_filters_by_project():
    resp_lib.add(resp_lib.GET, RESELL_FLOATINGIPS_URL, json={
        "floatingips": [
            {"id": "fip-1", "floating_ip_address": "1.2.3.4",
             "project_id": "other"},
            {"id": "fip-2", "floating_ip_address": "87.228.90.1",
             "project_id": PROJECT_ID},
        ]
    })

    client = make_client()
    fips = client.list_floating_ips()

    assert len(fips) == 1
    assert fips[0]["id"] == "fip-2"


# ---------------------------------------------------------------------------
# 3. create_floating_ips_bulk — OpenStack
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_create_bulk_success():
    add_auth_ok(resp_lib)
    add_networks(resp_lib)
    resp_lib.add(resp_lib.POST, FLOATINGIPS_URL, json={
        "floatingip": make_fip("87.228.90.10", "fip-new")
    }, status=201)

    client = make_client()
    fips = client.create_floating_ips_bulk(1)

    assert len(fips) == 1
    assert fips[0]["id"] == "fip-new"
    # Verify auth token used
    create_req = next(c for c in resp_lib.calls if c.request.method == "POST"
                      and "floatingips" in c.request.url
                      and "identity" not in c.request.url)
    assert create_req.request.headers["X-Auth-Token"] == KS_TOKEN


@resp_lib.activate
def test_create_bulk_zero_returns_empty():
    client = make_client()
    assert client.create_floating_ips_bulk(0) == []
    assert len(resp_lib.calls) == 0


@resp_lib.activate
def test_create_bulk_multiple():
    add_auth_ok(resp_lib)
    add_networks(resp_lib)
    resp_lib.add(resp_lib.POST, FLOATINGIPS_URL,
                 json={"floatingip": make_fip("1.2.3.4", "fip-1")}, status=201)
    resp_lib.add(resp_lib.POST, FLOATINGIPS_URL,
                 json={"floatingip": make_fip("5.6.7.8", "fip-2")}, status=201)

    client = make_client()
    fips = client.create_floating_ips_bulk(2)

    assert len(fips) == 2


@resp_lib.activate
def test_create_bulk_quota_exceeded_429():
    add_auth_ok(resp_lib)
    add_networks(resp_lib)
    resp_lib.add(resp_lib.POST, FLOATINGIPS_URL, status=429)

    client = make_client()
    with pytest.raises(SelectelRateLimitError):
        client.create_floating_ips_bulk(1)


@resp_lib.activate
def test_create_bulk_api_error():
    add_auth_ok(resp_lib)
    add_networks(resp_lib)
    resp_lib.add(resp_lib.POST, FLOATINGIPS_URL, status=500, body="error")

    client = make_client()
    with pytest.raises(SelectelAPIError) as exc:
        client.create_floating_ips_bulk(1)
    assert exc.value.status == 500


# ---------------------------------------------------------------------------
# 4. delete_floating_ip — OpenStack
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_delete_success():
    add_auth_ok(resp_lib)
    resp_lib.add(resp_lib.DELETE, f"{FLOATINGIPS_URL}/fip-123", status=204)

    client = make_client()
    assert client.delete_floating_ip("fip-123") is True
    del_req = next(c for c in resp_lib.calls if c.request.method == "DELETE")
    assert del_req.request.headers["X-Auth-Token"] == KS_TOKEN


@resp_lib.activate
def test_delete_not_found_returns_true():
    add_auth_ok(resp_lib)
    resp_lib.add(resp_lib.DELETE, f"{FLOATINGIPS_URL}/fip-gone", status=404)

    client = make_client()
    assert client.delete_floating_ip("fip-gone") is True


@resp_lib.activate
def test_delete_error_raises():
    add_auth_ok(resp_lib)
    resp_lib.add(resp_lib.DELETE, f"{FLOATINGIPS_URL}/fip-x", status=403)

    client = make_client()
    with pytest.raises(SelectelAPIError):
        client.delete_floating_ip("fip-x")


# ---------------------------------------------------------------------------
# 5. Network ID cached
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_network_id_cached_across_creates():
    add_auth_ok(resp_lib)
    add_networks(resp_lib)
    resp_lib.add(resp_lib.POST, FLOATINGIPS_URL,
                 json={"floatingip": make_fip("1.1.1.1")}, status=201)
    resp_lib.add(resp_lib.POST, FLOATINGIPS_URL,
                 json={"floatingip": make_fip("2.2.2.2")}, status=201)

    client = make_client()
    client.create_floating_ips_bulk(2)

    network_calls = [c for c in resp_lib.calls
                     if "networks" in c.request.url]
    assert len(network_calls) == 1  # fetched only once


# ---------------------------------------------------------------------------
# 6. multi-account test compat
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_selectel_rate_limit_error_is_raised():
    add_auth_ok(resp_lib)
    add_networks(resp_lib)
    resp_lib.add(resp_lib.POST, FLOATINGIPS_URL, status=429)

    client = make_client()
    with pytest.raises(SelectelRateLimitError):
        client.create_floating_ips_bulk(1)
