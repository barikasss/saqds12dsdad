# selectel_api.py — Selectel Resell API client (floating IPs)
#
# Auth: X-Token: <api_key>  (from my.selectel.ru → Profile → Security → API keys)
# Docs: https://docs.selectel.ru/api/
#
# Replaces OpenStack Neutron API — no Keystone auth, no network_id lookups.

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import requests
import structlog

if TYPE_CHECKING:
    from src.proxy_pool import ResellProxyPool

log = structlog.get_logger(__name__)

_RESELL_BASE = "https://api.selectel.ru/vpc/resell/v2"
_IDENTITY_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"


def _mask_proxy(proxy_url: str) -> str:
    try:
        if "@" in proxy_url:
            scheme, rest = proxy_url.split("://", 1)
            _, host = rest.split("@", 1)
            return f"{scheme}://***@{host}"
    except Exception:
        pass
    return proxy_url


class SelectelAPIError(Exception):
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"Selectel API {status}: {body[:200]}")


class SelectelRateLimitError(SelectelAPIError):
    """Raised when quota is exceeded (HTTP 429 or quota_exceeded in body)."""


class SelectelClient:
    def __init__(
        self,
        account_id: str = "",
        username: str = "",
        api_key: str = "",
        project_id: str = "",
        region: str = "ru-3",
        proxy_pool: "ResellProxyPool | None" = None,
    ) -> None:
        self._account_id = account_id
        self.username = username or account_id   # public — used by AccountPool for logging
        self._api_key = api_key
        self._project_id = project_id
        self._region = region
        self._proxy_pool = proxy_pool
        self._session = requests.Session()
        self._last_delete_time: float = 0.0
        self._delete_interval: float = 5.0  # min seconds between deletes
        self._keystone_token: str | None = None
        self._keystone_expires: float = 0.0

    # ------------------------------------------------------------------

    def _headers(self) -> dict:
        return {"X-Token": self._api_key, "Content-Type": "application/json"}

    def _proxies_for_request(self) -> dict | None:
        if self._proxy_pool is None:
            return None
        proxy = self._proxy_pool.next()
        if proxy is None:
            return None
        log.debug("selectel_resell.proxy_used",
                  proxy=_mask_proxy(proxy), account=self.username)
        return {"http": proxy, "https": proxy}

    def _request(
        self, method: str, url: str,
        max_retries: int = 3,
        **kwargs,
    ) -> requests.Response:
        last_exc: Exception | None = None
        for attempt in range(max(1, max_retries)):
            proxies = self._proxies_for_request()
            try:
                resp = self._session.request(
                    method, url,
                    headers=self._headers(),
                    proxies=proxies,
                    timeout=(10, 30),
                    **kwargs,
                )
                return resp
            except requests.exceptions.ProxyError as exc:
                log.warning("selectel_resell.proxy_error",
                            attempt=attempt + 1, error=str(exc))
                last_exc = exc
                continue
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as exc:
                log.warning("selectel_resell.connection_error",
                            attempt=attempt + 1, error=str(exc))
                last_exc = exc
                if attempt + 1 < max_retries:
                    time.sleep(2 ** attempt)
                continue
        raise SelectelAPIError(
            0, f"Request failed after {max_retries} retries: {last_exc}"
        ) from last_exc

    # ------------------------------------------------------------------
    # OpenStack fallback for DELETE (no Resell rate limit)
    # ------------------------------------------------------------------

    def _get_keystone_token(self) -> str | None:
        """Exchange X-Token for a Keystone token (for OpenStack API calls)."""
        if self._keystone_token and time.time() < self._keystone_expires:
            return self._keystone_token
        try:
            resp = requests.post(
                _IDENTITY_URL,
                json={"auth": {"identity": {
                    "methods": ["token"],
                    "token": {"id": self._api_key},
                }}},
                timeout=10,
            )
            if resp.status_code in (200, 201):
                token = resp.headers.get("X-Subject-Token", "")
                if token:
                    self._keystone_token = token
                    self._keystone_expires = time.time() + 3000
                    log.info("selectel.keystone_token_ok")
                    return token
        except Exception as exc:
            log.warning("selectel.keystone_exchange_error", error=str(exc))
        return None

    def _delete_via_openstack(self, fip_id: str) -> bool:
        """Delete FIP via OpenStack Neutron API (no rate limiting issues)."""
        token = self._get_keystone_token()
        if not token:
            return False
        url = (f"https://{self._region}.cloud.api.selcloud.ru"
               f"/network/v2.0/floatingips/{fip_id}")
        try:
            resp = requests.delete(
                url,
                headers={"X-Auth-Token": token},
                timeout=(10, 30),
            )
            if resp.status_code in (204, 404):
                log.info("selectel_openstack.fip_deleted", id=fip_id)
                return True
            log.warning("selectel_openstack.delete_failed",
                        id=fip_id, status=resp.status_code)
            return False
        except Exception as exc:
            log.warning("selectel_openstack.delete_error",
                        id=fip_id, error=str(exc))
            return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_floating_ips(self, max_conn_retries: int = 3) -> list[dict]:
        """Return FIPs belonging to this client's project_id."""
        resp = self._request("GET", f"{_RESELL_BASE}/floatingips",
                             max_retries=max_conn_retries)
        if not resp.ok:
            raise SelectelAPIError(resp.status_code, resp.text)
        fips: list[dict] = resp.json().get("floatingips", [])
        if self._project_id:
            fips = [f for f in fips if f.get("project_id") == self._project_id]
        return fips

    def create_floating_ips_bulk(self, quantity: int) -> list[dict]:
        """Create `quantity` FIPs in one request.

        Returns list of dicts: [{id, floating_ip_address, region, status, project_id}].
        Raises SelectelRateLimitError on quota_exceeded.
        """
        if quantity <= 0:
            return []

        resp = self._request(
            "POST",
            f"{_RESELL_BASE}/floatingips/projects/{self._project_id}",
            json={"floatingips": [{"region": self._region, "quantity": quantity}]},
        )

        if resp.status_code in (429, 409):
            try:
                if resp.json().get("error") == "quota_exceeded":
                    raise SelectelRateLimitError(resp.status_code, resp.text)
            except (ValueError, SelectelRateLimitError):
                raise
            except Exception:
                pass

        if not resp.ok:
            raise SelectelAPIError(resp.status_code, resp.text)

        body = resp.json()
        fips: list[dict] = body.get("floatingips", [])
        for fip in fips:
            log.info("selectel_resell.fip_created",
                     id=fip.get("id"), ip=fip.get("floating_ip_address"),
                     region=fip.get("region"), account=self.username)
        return fips

    def create_floating_ip_safe(
        self,
        network_id: str | None = None,
        availability_zone: str | None = None,
    ) -> dict:
        """Single FIP — thin wrapper for backward compat with _DryRunClient."""
        fips = self.create_floating_ips_bulk(1)
        if not fips:
            raise SelectelAPIError(0, "No FIPs returned from bulk create")
        return fips[0]

    def delete_floating_ip(self, fip_id: str) -> bool:
        # Enforce minimum interval between deletes to avoid Resell burst limit
        elapsed = time.time() - self._last_delete_time
        if elapsed < self._delete_interval:
            time.sleep(self._delete_interval - elapsed)

        resp = self._request("DELETE", f"{_RESELL_BASE}/floatingips/{fip_id}")
        self._last_delete_time = time.time()

        if resp.status_code in (204, 404):
            log.info("selectel_resell.fip_deleted", id=fip_id)
            return True

        if resp.status_code == 429:
            log.warning("selectel_resell.delete_rate_limit_fallback", fip_id=fip_id)
            return self._delete_via_openstack(fip_id)

        raise SelectelAPIError(resp.status_code, resp.text)
