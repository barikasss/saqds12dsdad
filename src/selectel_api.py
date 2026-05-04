# selectel_api.py — Selectel API client
#
# List FIPs:    Resell API (X-Token, single endpoint)
# Create FIPs:  OpenStack Neutron API (Keystone auth, no rate limit)
# Delete FIPs:  OpenStack Neutron API (Keystone auth, no rate limit)

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any

import requests
import structlog

if TYPE_CHECKING:
    from src.proxy_pool import ResellProxyPool

log = structlog.get_logger(__name__)

_RESELL_BASE = "https://api.selectel.ru/vpc/resell/v2"
_IDENTITY_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"


def _mask_token(token: str) -> str:
    return token[:8] + "..." if len(token) > 8 else "***"


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
        api_key: str = "",       # X-Token for Resell list
        password: str = "",      # service user password for OpenStack create/delete
        project_id: str = "",
        region: str = "ru-3",
        proxy_pool: "ResellProxyPool | None" = None,
    ) -> None:
        self._account_id = account_id
        self.username = username or account_id
        self._api_key = api_key
        self._password = password
        self._project_id = project_id
        self._region = region
        self._proxy_pool = proxy_pool
        self._session = requests.Session()
        # Keystone token cache (for OpenStack create/delete)
        self._keystone_token: str | None = None
        self._keystone_expires: float = 0.0
        # Cached external network ID per region
        self._network_id: str | None = None

    # ------------------------------------------------------------------
    # Proxy helpers
    # ------------------------------------------------------------------

    def _proxies_for_request(self) -> dict | None:
        if self._proxy_pool is None:
            return None
        proxy = self._proxy_pool.next()
        if proxy is None:
            return None
        log.debug("selectel.proxy_used", proxy=_mask_proxy(proxy),
                  account=self.username)
        return {"http": proxy, "https": proxy}

    # ------------------------------------------------------------------
    # Keystone auth (for OpenStack create/delete)
    # ------------------------------------------------------------------

    def _auth(self) -> str:
        """Return valid Keystone X-Auth-Token, cached until ~1 min before expiry."""
        if self._keystone_token and time.time() < self._keystone_expires:
            return self._keystone_token

        if not (self.username and self._password and self._account_id):
            raise SelectelAPIError(
                0,
                "No service user credentials for OpenStack auth. "
                "Set password_env in config.",
            )

        body: dict[str, Any] = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "domain": {"name": self._account_id},
                            "password": self._password,
                        }
                    },
                },
                **({"scope": {"project": {"id": self._project_id}}}
                   if self._project_id else {}),
            }
        }

        proxies = self._proxies_for_request()
        try:
            resp = requests.post(
                _IDENTITY_URL, json=body,
                timeout=10, proxies=proxies,
            )
            if resp.status_code == 201:
                token = resp.headers.get("X-Subject-Token", "")
                if token:
                    try:
                        expires_str = resp.json()["token"]["expires_at"]
                        from datetime import datetime
                        dt = datetime.fromisoformat(
                            expires_str.replace("Z", "+00:00"))
                        self._keystone_expires = dt.timestamp() - 60
                    except Exception:
                        self._keystone_expires = time.time() + 3000
                    self._keystone_token = token
                    log.info("selectel.auth_ok", token=_mask_token(token))
                    return token
            raise SelectelAPIError(resp.status_code, resp.text)
        except SelectelAPIError:
            raise
        except Exception as exc:
            log.warning("selectel.auth_error", error=str(exc))
            raise SelectelAPIError(0, f"Auth failed: {exc}") from exc

    # ------------------------------------------------------------------
    # OpenStack helpers (authenticated)
    # ------------------------------------------------------------------

    @property
    def _net_base(self) -> str:
        return f"https://{self._region}.cloud.api.selcloud.ru/network/v2.0"

    def _ks_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Authenticated OpenStack request with Keystone token."""
        for attempt in range(3):
            proxies = self._proxies_for_request()  # rotate proxy on each attempt
            token = self._auth()
            headers = {
                "X-Auth-Token": token,
                "Content-Type": "application/json",
            }
            try:
                resp = requests.request(
                    method, url,
                    headers=headers,
                    proxies=proxies,
                    timeout=(10, 30),
                    **kwargs,
                )
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as exc:
                raise SelectelAPIError(0, f"OpenStack request failed: {exc}") from exc

            if resp.status_code == 401 and attempt < 2:
                log.warning("selectel.ks_token_expired_retry")
                self._keystone_token = None
                self._keystone_expires = 0.0
                continue
            if resp.status_code == 403 and attempt < 2:
                log.warning("selectel.ks_403_rotate_proxy",
                            account=self.username, attempt=attempt)
                continue
            return resp
        raise SelectelAPIError(403, "OpenStack: all proxy attempts got 403")

    def _get_network_id(self) -> str:
        if self._network_id:
            return self._network_id
        resp = self._ks_request(
            "GET", f"{self._net_base}/networks",
            params={"router:external": "True"},
        )
        if not resp.ok:
            raise SelectelAPIError(resp.status_code, resp.text)
        nets = resp.json().get("networks", [])
        if not nets:
            raise SelectelAPIError(0, "No external networks found in region")
        self._network_id = nets[0]["id"]
        return self._network_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_floating_ips(self, max_conn_retries: int = 3) -> list[dict]:
        """List FIPs via Resell API (simple, single endpoint)."""
        max_attempts = max(1, max_conn_retries)
        for attempt in range(max_attempts):
            proxies = self._proxies_for_request()  # rotate proxy on each attempt
            try:
                resp = requests.get(
                    f"{_RESELL_BASE}/floatingips",
                    headers={"X-Token": self._api_key},
                    proxies=proxies,
                    timeout=(10, 30),
                )
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as exc:
                if attempt + 1 >= max_attempts:
                    raise SelectelAPIError(0, f"List FIPs failed: {exc}") from exc
                time.sleep(2 ** attempt)
                continue
            if resp.status_code == 403 and attempt + 1 < max_attempts:
                log.warning("selectel.resell_403_rotate_proxy",
                            account=self.username, attempt=attempt)
                continue
            if not resp.ok:
                raise SelectelAPIError(resp.status_code, resp.text)
            fips: list[dict] = resp.json().get("floatingips", [])
            if self._project_id:
                fips = [f for f in fips if f.get("project_id") == self._project_id]
            return fips
        raise SelectelAPIError(403, f"list_floating_ips: all {max_attempts} proxy attempts got 403")

    def _create_one_fip(self, network_id: str) -> dict | None:
        """Create a single FIP; returns fip dict or None on ExternalIpAddressExhausted."""
        resp = self._ks_request(
            "POST", f"{self._net_base}/floatingips",
            json={"floatingip": {"floating_network_id": network_id}},
        )
        if resp.status_code == 429:
            raise SelectelRateLimitError(429, resp.text)
        if resp.status_code == 400 and "ExternalIpAddressExhausted" in resp.text:
            log.warning("selectel.exhausted", account=self.username)
            return None
        if not resp.ok:
            raise SelectelAPIError(resp.status_code, resp.text)
        fip = resp.json()["floatingip"]
        fip.setdefault("region", self._region)
        log.info("selectel.fip_created",
                 id=fip["id"], ip=fip.get("floating_ip_address"),
                 region=self._region, account=self.username)
        return fip

    def create_floating_ips_bulk(self, quantity: int) -> list[dict]:
        """Create `quantity` FIPs in parallel via OpenStack."""
        if quantity <= 0:
            return []
        network_id = self._get_network_id()
        fips: list[dict] = []
        with ThreadPoolExecutor(max_workers=quantity) as pool:
            futures = [pool.submit(self._create_one_fip, network_id)
                       for _ in range(quantity)]
            for future in as_completed(futures):
                result = future.result()  # propagates SelectelRateLimitError/SelectelAPIError
                if result is not None:
                    fips.append(result)
        return fips

    def create_floating_ip_safe(
        self,
        network_id: str | None = None,
        availability_zone: str | None = None,
    ) -> dict:
        """Single FIP — wrapper for _DryRunClient compat."""
        fips = self.create_floating_ips_bulk(1)
        if not fips:
            raise SelectelAPIError(0, "No FIPs returned")
        return fips[0]

    def delete_floating_ip(self, fip_id: str) -> bool:
        """Delete FIP via OpenStack (no burst rate limit)."""
        resp = self._ks_request(
            "DELETE", f"{self._net_base}/floatingips/{fip_id}",
        )
        if resp.status_code in (204, 404):
            log.info("selectel.fip_deleted", id=fip_id)
            return True
        raise SelectelAPIError(resp.status_code, resp.text)
