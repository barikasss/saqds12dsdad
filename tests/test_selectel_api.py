import json
from unittest.mock import MagicMock, patch, create_autospec

import pytest
import responses as resp_lib

from src.proxy_pool import ProxyPool
from src.selectel_api import SelectelAPIError, SelectelClient

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_TOKEN = "testtoken_api_secret123"
KS_TOKEN = "ks-subject-token-xyz"
REGION = "ru-3"
IDENTITY_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"
BASE_NET = f"https://{REGION}.cloud.api.selcloud.ru/network/v2.0"
FIP_URL = f"{BASE_NET}/floatingips"
NETS_URL = f"{BASE_NET}/networks"
COMPUTE_URL = f"https://{REGION}.cloud.api.selcloud.ru/compute/v2.1"

EXPIRES_AT = "2026-05-02T12:00:00.000000Z"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def add_identity_ok(rsps, token: str = KS_TOKEN) -> None:
    rsps.add(
        resp_lib.POST,
        IDENTITY_URL,
        json={"token": {"expires_at": EXPIRES_AT}},
        headers={"X-Subject-Token": token},
        status=201,
    )


def add_identity_fail(rsps) -> None:
    rsps.add(resp_lib.POST, IDENTITY_URL, status=404)


def make_client(**kwargs) -> SelectelClient:
    defaults = dict(api_token=API_TOKEN, region=REGION)
    defaults.update(kwargs)
    return SelectelClient(**defaults)


# ---------------------------------------------------------------------------
# 0. test_auth_password_method — service user (username/password/account_id)
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_auth_password_method():
    resp_lib.add(
        resp_lib.POST, IDENTITY_URL,
        json={"token": {"expires_at": EXPIRES_AT}},
        headers={"X-Subject-Token": "ks-pw-token"},
        status=201,
    )
    resp_lib.add(resp_lib.GET, FIP_URL, json={"floatingips": []})

    client = SelectelClient(
        account_id="123456",
        username="svc-user",
        password="s3cr3t",
        project_id="proj-uuid",
        region=REGION,
    )
    client.list_floating_ips()

    auth_body = json.loads(resp_lib.calls[0].request.body)
    assert auth_body["auth"]["identity"]["methods"][0] == "password"
    assert auth_body["auth"]["identity"]["password"]["user"]["name"] == "svc-user"
    assert auth_body["auth"]["identity"]["password"]["user"]["domain"]["name"] == "123456"
    assert auth_body["auth"]["scope"] == {"project": {"id": "proj-uuid"}}

    fip_req = resp_lib.calls[1].request
    assert fip_req.headers["X-Auth-Token"] == "ks-pw-token"


# ---------------------------------------------------------------------------
# 0b. test_auth_real_flow — full auth + list_floating_ips with mocks
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_auth_real_flow():
    resp_lib.add(
        resp_lib.POST, IDENTITY_URL,
        json={"token": {"expires_at": EXPIRES_AT}},
        headers={"X-Subject-Token": "project-tok"},
        status=201,
    )
    resp_lib.add(resp_lib.GET, FIP_URL, json={"floatingips": [
        {"id": "fip-1", "floating_ip_address": "87.228.90.5"},
    ]})

    client = SelectelClient(
        account_id="478320",
        username="Alena",
        password="secret",
        project_id="96536fd09a294164aaf5592a79b5356e",
        region=REGION,
    )

    token = client._auth()
    assert token == "project-tok"
    assert len(token) > 0

    fips = client.list_floating_ips()
    assert isinstance(fips, list)
    assert fips[0]["floating_ip_address"] == "87.228.90.5"


# ---------------------------------------------------------------------------
# 1. test_auth_via_identity_token
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_auth_via_identity_token():
    add_identity_ok(resp_lib)
    resp_lib.add(resp_lib.GET, FIP_URL, json={"floatingips": []})

    client = make_client()
    client.list_floating_ips()

    # Auth call: calls[0]; FIP call: calls[1]
    fip_req = resp_lib.calls[1].request
    assert fip_req.headers["X-Auth-Token"] == KS_TOKEN
    assert fip_req.headers["X-Auth-Token"] != API_TOKEN


# ---------------------------------------------------------------------------
# 2. test_auth_fallback_direct
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_auth_fallback_direct():
    add_identity_fail(resp_lib)
    resp_lib.add(resp_lib.GET, FIP_URL, json={"floatingips": []})

    client = make_client()
    client.list_floating_ips()

    fip_req = resp_lib.calls[1].request
    assert fip_req.headers["X-Auth-Token"] == API_TOKEN


# ---------------------------------------------------------------------------
# 3. test_list_floating_ips_success
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_list_floating_ips_success():
    add_identity_ok(resp_lib)
    resp_lib.add(resp_lib.GET, FIP_URL, json={"floatingips": [
        {"id": "fip-1", "floating_ip_address": "87.228.90.1", "status": "ACTIVE", "port_id": None},
        {"id": "fip-2", "floating_ip_address": "87.228.96.5", "status": "DOWN",   "port_id": None},
    ]})

    client = make_client()
    fips = client.list_floating_ips()

    assert len(fips) == 2
    assert fips[0]["id"] == "fip-1"
    assert fips[0]["floating_ip_address"] == "87.228.90.1"
    assert fips[1]["status"] == "DOWN"


# ---------------------------------------------------------------------------
# 4. test_create_floating_ip_success
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_create_floating_ip_success():
    add_identity_ok(resp_lib)
    resp_lib.add(resp_lib.GET, NETS_URL, json={"networks": [
        {"id": "ext-net-ru3", "name": "ext-net", "router:external": True},
    ]})
    resp_lib.add(resp_lib.POST, FIP_URL, json={"floatingip": {
        "id": "new-fip-42",
        "floating_ip_address": "87.228.90.10",
        "status": "DOWN",
    }}, status=201)

    client = make_client()
    fip = client.create_floating_ip()

    assert fip["id"] == "new-fip-42"
    assert fip["floating_ip_address"] == "87.228.90.10"

    # Verify POST body used the auto-detected network
    post_req = next(c for c in resp_lib.calls if c.request.method == "POST" and "floatingips" in c.request.url)
    body = json.loads(post_req.request.body)
    assert body["floatingip"]["floating_network_id"] == "ext-net-ru3"


# ---------------------------------------------------------------------------
# 5. test_delete_floating_ip_success
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_delete_floating_ip_success():
    add_identity_ok(resp_lib)
    resp_lib.add(resp_lib.DELETE, f"{FIP_URL}/fip-del-99", status=204)

    client = make_client()
    result = client.delete_floating_ip("fip-del-99")

    assert result is True
    del_req = next(c for c in resp_lib.calls if c.request.method == "DELETE")
    assert "fip-del-99" in del_req.request.url


# ---------------------------------------------------------------------------
# 6. test_reroll_until_in_subnet_finds_match
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_reroll_until_in_subnet_finds_match():
    add_identity_ok(resp_lib)
    # Networks: reused for all create calls
    resp_lib.add(resp_lib.GET, NETS_URL, json={"networks": [{"id": "net-1"}]})

    # Three FIP creation attempts
    for ip, fip_id in [("1.2.3.4", "fip-a"), ("5.6.7.8", "fip-b"), ("10.0.0.5", "fip-c")]:
        resp_lib.add(resp_lib.POST, FIP_URL,
                     json={"floatingip": {"id": fip_id, "floating_ip_address": ip}},
                     status=201)

    # Misses are deleted
    resp_lib.add(resp_lib.DELETE, f"{FIP_URL}/fip-a", status=204)
    resp_lib.add(resp_lib.DELETE, f"{FIP_URL}/fip-b", status=204)

    client = make_client()
    result = client.reroll_until_in_subnet("10.0.0.0/29", max_attempts=5)

    assert result is not None
    assert result["floating_ip_address"] == "10.0.0.5"

    deletes = [c for c in resp_lib.calls if c.request.method == "DELETE"]
    assert len(deletes) == 2
    deleted_ids = [c.request.url.split("/")[-1] for c in deletes]
    assert "fip-a" in deleted_ids
    assert "fip-b" in deleted_ids
    assert "fip-c" not in deleted_ids


# ---------------------------------------------------------------------------
# 7. test_reroll_until_in_subnet_max_attempts
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_reroll_until_in_subnet_max_attempts():
    add_identity_ok(resp_lib)
    resp_lib.add(resp_lib.GET, NETS_URL, json={"networks": [{"id": "net-1"}]})

    for i in range(15):
        resp_lib.add(
            resp_lib.POST, FIP_URL,
            json={"floatingip": {"id": f"fip-{i}", "floating_ip_address": f"1.2.{i}.1"}},
            status=201,
        )
        resp_lib.add(resp_lib.DELETE, f"{FIP_URL}/fip-{i}", status=204)

    client = make_client()
    result = client.reroll_until_in_subnet("10.0.0.0/29", max_attempts=15)

    assert result is None
    deletes = [c for c in resp_lib.calls if c.request.method == "DELETE"]
    assert len(deletes) == 15


# ---------------------------------------------------------------------------
# 8. test_retry_on_503
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_retry_on_503():
    add_identity_fail(resp_lib)                            # fallback to direct token
    resp_lib.add(resp_lib.GET, FIP_URL, status=503)       # first attempt fails
    resp_lib.add(resp_lib.GET, FIP_URL, json={"floatingips": [
        {"id": "fip-x", "floating_ip_address": "1.2.3.4"},
    ]})                                                    # retry succeeds

    with patch("src.selectel_api.time") as mock_time:
        mock_time.time.return_value = 0.0
        mock_time.sleep = MagicMock()

        client = make_client()
        result = client.list_floating_ips()

    assert len(result) == 1
    assert result[0]["id"] == "fip-x"
    # Exactly one backoff sleep for the 503
    mock_time.sleep.assert_called_once_with(2)


# ---------------------------------------------------------------------------
# 9. test_logs_no_secret
# ---------------------------------------------------------------------------

def test_logs_no_secret():
    from structlog.testing import capture_logs

    with capture_logs() as cap:
        with resp_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            add_identity_fail(rsps)
            rsps.add(resp_lib.GET, FIP_URL, json={"floatingips": []})

            client = make_client()
            client.list_floating_ips()

    for event in cap:
        for v in event.values():
            assert API_TOKEN not in str(v), f"API token leaked in log event: {event}"


# ---------------------------------------------------------------------------
# 10. ProxyPool integration — get() and release() called on create_fip_safe
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_create_fip_safe_uses_proxy_pool():
    add_identity_ok(resp_lib)
    resp_lib.add(resp_lib.GET, NETS_URL, json={"networks": [{"id": "net-pool-1"}]})
    resp_lib.add(resp_lib.POST, FIP_URL, json={"floatingip": {
        "id": "fip-pool-1",
        "floating_ip_address": "87.228.90.55",
    }}, status=201)

    pool = create_autospec(ProxyPool, instance=True)
    pool.get.return_value = "socks5://proxy:pass@1.2.3.4:1080"

    client = make_client(proxy_pool=pool)
    fip = client.create_floating_ip_safe()

    assert fip["id"] == "fip-pool-1"
    pool.get.assert_called_once()
    pool.release.assert_called_once_with("socks5://proxy:pass@1.2.3.4:1080")


@resp_lib.activate
def test_create_fip_safe_pool_exhausted_raises():
    """When ProxyPool.get() returns None, create_floating_ip_safe raises immediately."""
    pool = create_autospec(ProxyPool, instance=True)
    pool.get.return_value = None

    client = make_client(proxy_pool=pool)
    with pytest.raises(SelectelAPIError, match="ProxyPool exhausted"):
        client.create_floating_ip_safe()

    pool.release.assert_not_called()


@resp_lib.activate
def test_create_fip_safe_releases_on_error():
    """Proxy is released even when the API call fails."""
    add_identity_ok(resp_lib)
    resp_lib.add(resp_lib.GET, NETS_URL, json={"networks": [{"id": "net-err"}]})
    resp_lib.add(resp_lib.POST, FIP_URL, status=500)
    resp_lib.add(resp_lib.POST, FIP_URL, status=500)
    resp_lib.add(resp_lib.POST, FIP_URL, status=500)
    resp_lib.add(resp_lib.POST, FIP_URL, status=500)

    pool = create_autospec(ProxyPool, instance=True)
    pool.get.return_value = "socks5://proxy:pass@1.2.3.4:1080"

    client = make_client(proxy_pool=pool)
    with patch("src.selectel_api.time") as mock_time:
        mock_time.time.return_value = 0.0
        mock_time.sleep = MagicMock()
        with pytest.raises(SelectelAPIError):
            client.create_floating_ip_safe()

    pool.release.assert_called_once_with("socks5://proxy:pass@1.2.3.4:1080")
