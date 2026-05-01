# selectel_api.py — Selectel Cloud API client (floating IPs, servers, networks)

from __future__ import annotations

import ipaddress
import time
from typing import Any

import requests
import structlog

log = structlog.get_logger(__name__)


def _mask_token(token: str) -> str:
    return token[:8] + "..." if len(token) > 8 else "***"


class SelectelAPIError(Exception):
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        hint = ""
        if status == 401:
            hint = (
                "\n\nПроверь токен в личном кабинете Selectel → "
                "Управление пользователями → API-ключи. "
                "Убедись, что токен активен и имеет права на нужный проект."
            )
        super().__init__(f"Selectel API {status}: {body[:200]}{hint}")


class SelectelRateLimitError(SelectelAPIError):
    """Raised by create_floating_ip_safe when account is rate limited (HTTP 429)."""


class SelectelClient:
    _IDENTITY_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"

    def __init__(
        self,
        api_token: str = "",
        region: str = "ru-3",
        project_id: str | None = None,
        # Password-method Keystone (service user)
        account_id: str = "",
        username: str = "",
        password: str = "",
    ) -> None:
        self._api_token = api_token
        self._region = region
        self._project_id = project_id
        self._account_id = account_id
        self.username = username          # public for AccountPool logging
        self._password = password
        self._keystone_token: str | None = None
        self._token_expires: float = 0.0
        self._session = requests.Session()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def _net_base(self) -> str:
        return f"https://{self._region}.cloud.api.selcloud.ru/network/v2.0"

    @property
    def _compute_base(self) -> str:
        return f"https://{self._region}.cloud.api.selcloud.ru/compute/v2.1"

    def _cache_ks_token(self, ks_token: str, body: dict) -> None:
        try:
            from datetime import datetime
            expires_str: str = body["token"]["expires_at"]
            dt = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            self._token_expires = dt.timestamp() - 60
        except Exception:
            self._token_expires = time.time() + 3000
        self._keystone_token = ks_token

    def _auth(self) -> str:
        """Returns a valid X-Auth-Token. Caches until ~1 min before expiry.

        Priority:
          1. password-method Keystone (SELECTEL_USERNAME / PASSWORD / ACCOUNT_ID)
          2. token-exchange via /identity (SELECTEL_API_TOKEN → short-lived ks token)
          3. api_token used directly as X-Auth-Token (last resort)
        """
        if self._keystone_token and time.time() < self._token_expires:
            return self._keystone_token

        # --- Method 1: password auth (service user) ---
        if self.username and self._password and self._account_id:
            log.debug(
                "auth.attempt",
                username=self.username,
                account_id=self._account_id,
                project_id=self._project_id[:8] if self._project_id else None,
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
                    **({"scope": {"project": {"id": self._project_id}}} if self._project_id else {}),
                }
            }
            try:
                resp = requests.post(self._IDENTITY_URL, json=body, timeout=10)
                if resp.status_code == 201:
                    token = resp.headers.get("X-Subject-Token", "")
                    if token:
                        self._cache_ks_token(token, resp.json())
                        log.info("selectel.auth_ok", token=_mask_token(token))
                        return token
                raise SelectelAPIError(resp.status_code, resp.text)
            except SelectelAPIError:
                raise
            except requests.RequestException:
                pass

        # --- Method 2: token exchange ---
        if self._api_token:
            token_body: dict[str, Any] = {
                "auth": {
                    "identity": {"methods": ["token"], "token": {"id": self._api_token}},
                    **({"scope": {"domain": {"name": self._account_id}}} if self._account_id else {}),
                }
            }
            try:
                resp = requests.post(self._IDENTITY_URL, json=token_body, timeout=15)
                if resp.status_code in (200, 201):
                    ks_token = resp.headers.get("X-Subject-Token", "")
                    if ks_token:
                        self._cache_ks_token(ks_token, resp.json())
                        log.info("selectel.auth_token_ok", token=_mask_token(ks_token))
                        return ks_token
            except requests.RequestException:
                pass

            # Method 3: api_token direct
            log.info(
                "selectel.auth_direct_fallback",
                hint="identity exchange unavailable — using api_token directly",
            )
            self._keystone_token = self._api_token
            self._token_expires = time.time() + 3600
            return self._api_token

        raise SelectelAPIError(
            0,
            "No Selectel credentials found. Set SELECTEL_USERNAME/PASSWORD/ACCOUNT_ID "
            "or SELECTEL_API_TOKEN in .env",
        )

    def _request_with_retry(
        self, method: str, url: str,
        raise_on_rate_limit: bool = False,
        **kwargs,
    ) -> requests.Response:
        """Raw HTTP request with backoff retry on 429 and 5xx.

        If raise_on_rate_limit=True, HTTP 429 raises SelectelRateLimitError
        instead of sleeping — used by create_floating_ip_safe for AccountPool.
        """
        delays = [2, 4, 8]
        server_errors = 0
        conn_errors = 0
        max_retries = 3

        while True:
            try:
                resp = self._session.request(method, url, **kwargs)
            except requests.ConnectionError as exc:
                conn_errors += 1
                if conn_errors > max_retries:
                    raise SelectelAPIError(
                        0, f"Connection error after {max_retries} retries: {exc}"
                    ) from exc
                log.warning("selectel.connection_retry", attempt=conn_errors)
                time.sleep(delays[conn_errors - 1])
                continue

            if resp.status_code == 429:
                if raise_on_rate_limit:
                    raise SelectelRateLimitError(429, resp.text)
                retry_after = int(resp.headers.get("Retry-After", 30))
                log.warning("selectel.rate_limit", retry_after=retry_after)
                time.sleep(retry_after)
                continue

            if resp.status_code >= 500:
                server_errors += 1
                if server_errors > max_retries:
                    raise SelectelAPIError(resp.status_code, resp.text)
                log.warning(
                    "selectel.server_error",
                    status=resp.status_code,
                    attempt=server_errors,
                )
                time.sleep(delays[server_errors - 1])
                continue

            if not resp.ok:
                raise SelectelAPIError(resp.status_code, resp.text)

            return resp

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Authenticated request. Retries auth once on 401."""
        caller_headers: dict[str, str] = kwargs.pop("headers", {})
        raise_on_rate_limit: bool = kwargs.pop("raise_on_rate_limit", False)
        for auth_attempt in range(2):
            merged = {"X-Auth-Token": self._auth(), **caller_headers}
            if self._project_id:
                merged["X-Auth-Project"] = self._project_id
            try:
                return self._request_with_retry(
                    method, url,
                    raise_on_rate_limit=raise_on_rate_limit,
                    headers=merged,
                    **kwargs,
                )
            except SelectelAPIError as exc:
                if exc.status == 401 and auth_attempt == 0:
                    log.warning("selectel.auth_expired_retry")
                    self._keystone_token = None
                    self._token_expires = 0.0
                    continue
                raise
        raise SelectelAPIError(401, "Authentication failed after token refresh")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_floating_ips(self) -> list[dict]:
        """[{id, floating_ip_address, status, port_id, ...}]"""
        resp = self._request("GET", f"{self._net_base}/floatingips")
        return resp.json().get("floatingips", [])

    def list_external_networks(self) -> list[dict]:
        """External networks in this region — needed for create_floating_ip."""
        resp = self._request(
            "GET",
            f"{self._net_base}/networks",
            params={"router:external": "True"},
        )
        return resp.json().get("networks", [])

    def create_floating_ip(self, network_id: str | None = None) -> dict:
        """Create a floating IP. Auto-detects external network when network_id is None."""
        if network_id is None:
            nets = self.list_external_networks()
            if not nets:
                raise SelectelAPIError(0, "No external networks found in region")
            network_id = nets[0]["id"]

        resp = self._request(
            "POST",
            f"{self._net_base}/floatingips",
            json={"floatingip": {"floating_network_id": network_id}},
        )
        fip: dict = resp.json()["floatingip"]
        log.info("selectel.fip_created", id=fip["id"], ip=fip.get("floating_ip_address"))
        return fip

    def delete_floating_ip(self, fip_id: str) -> bool:
        self._request("DELETE", f"{self._net_base}/floatingips/{fip_id}")
        log.info("selectel.fip_deleted", id=fip_id)
        return True

    def create_floating_ip_safe(
        self,
        network_id: str | None = None,
        availability_zone: str | None = None,
    ) -> dict:
        """Create a floating IP, raising SelectelRateLimitError on HTTP 429.

        Unlike create_floating_ip, does NOT sleep on rate-limit — the caller
        (AccountPool) is expected to handle the error and switch accounts.
        """
        if network_id is None:
            nets = self.list_external_networks()
            if not nets:
                raise SelectelAPIError(0, "No external networks found in region")
            network_id = nets[0]["id"]

        resp = self._request(
            "POST",
            f"{self._net_base}/floatingips",
            raise_on_rate_limit=True,
            json={"floatingip": {"floating_network_id": network_id}},
        )
        fip: dict = resp.json()["floatingip"]
        log.info("selectel.fip_created", id=fip["id"], ip=fip.get("floating_ip_address"))
        return fip

    def list_servers(self) -> list[dict]:
        """[{id, name, status, addresses, ...}]"""
        resp = self._request("GET", f"{self._compute_base}/servers")
        return resp.json().get("servers", [])

    def attach_floating_ip_to_server(self, fip_id: str, server_id: str) -> bool:
        """Attach FIP to the first port of the server."""
        ports_resp = self._request(
            "GET",
            f"{self._net_base}/ports",
            params={"device_id": server_id},
        )
        ports = ports_resp.json().get("ports", [])
        if not ports:
            raise SelectelAPIError(0, f"No ports found for server {server_id}")
        port_id: str = ports[0]["id"]
        self._request(
            "PUT",
            f"{self._net_base}/floatingips/{fip_id}",
            json={"floatingip": {"port_id": port_id}},
        )
        log.info(
            "selectel.fip_attached",
            fip_id=fip_id,
            server_id=server_id,
            port_id=port_id,
        )
        return True

    def detach_floating_ip(self, fip_id: str) -> bool:
        self._request(
            "PUT",
            f"{self._net_base}/floatingips/{fip_id}",
            json={"floatingip": {"port_id": None}},
        )
        log.info("selectel.fip_detached", fip_id=fip_id)
        return True

    def reroll_until_in_subnet(
        self, target_cidr: str, max_attempts: int = 15
    ) -> dict | None:
        """Create floating IPs until one lands in target_cidr; delete misses.

        Returns the matching FIP dict, or None if exhausted max_attempts.
        """
        network = ipaddress.ip_network(target_cidr, strict=False)
        for attempt in range(1, max_attempts + 1):
            fip = self.create_floating_ip()
            ip_str = fip.get("floating_ip_address", "")
            if ip_str and ipaddress.ip_address(ip_str) in network:
                log.info(
                    "selectel.reroll_hit",
                    ip=ip_str,
                    cidr=target_cidr,
                    attempt=attempt,
                )
                return fip
            log.info(
                "selectel.reroll_miss",
                ip=ip_str,
                attempt=attempt,
                remaining=max_attempts - attempt,
            )
            self.delete_floating_ip(fip["id"])

        log.warning(
            "selectel.reroll_exhausted",
            cidr=target_cidr,
            max_attempts=max_attempts,
        )
        return None
