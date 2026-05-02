# wl_pool.py — pool of WLChecker API keys with per-key cooldown

from __future__ import annotations

import time

import requests
import structlog

log = structlog.get_logger(__name__)


def _mask_key(key: str) -> str:
    return key[:8] + "..." if len(key) > 8 else "***"


class WLKeyPool:
    """Pool of WLChecker API keys, each with an independent cooldown.

    submit() picks the first key whose cooldown has elapsed and POSTs /check,
    returning (job_id, key) on success or None when every key is in cooldown.
    get_result() polls one job; returns the parsed response only when finished.
    """

    def __init__(
        self,
        keys: list[str],
        base_url: str,
        cooldown_seconds: int = 300,
        proxy_url: str | None = None,
        request_timeout: int = 30,
    ) -> None:
        self.keys = list(keys)
        self.base_url = base_url.rstrip("/")
        self.cooldown_seconds = cooldown_seconds
        self.proxy_url = proxy_url
        self.request_timeout = request_timeout
        self._last_used: dict[str, float] = {}
        self._session = requests.Session()

    @property
    def _proxies(self) -> dict | None:
        if not self.proxy_url:
            return None
        return {"http": self.proxy_url, "https": self.proxy_url}

    def submit(self, cidr: str) -> tuple[str, str] | None:
        if not self.keys:
            return None

        now = time.time()
        for key in self.keys:
            last = self._last_used.get(key, 0.0)
            if now - last < self.cooldown_seconds:
                continue

            try:
                resp = self._session.post(
                    f"{self.base_url}/check",
                    json={"targets": [cidr]},
                    headers={"X-API-Key": key},
                    proxies=self._proxies,
                    timeout=self.request_timeout,
                )
            except requests.RequestException as exc:
                log.warning("wl_pool.submit_network_error",
                            key=_mask_key(key), error=str(exc))
                continue

            if resp.status_code == 429:
                log.warning("wl_pool.cooldown_429", key=_mask_key(key))
                self.mark_cooldown(key)
                continue
            if resp.status_code in (401, 403):
                log.warning("wl_pool.auth_error",
                            key=_mask_key(key), status=resp.status_code)
                continue
            if not resp.ok:
                log.warning("wl_pool.submit_http_error", key=_mask_key(key),
                            status=resp.status_code, body=resp.text[:200])
                continue

            try:
                job_id = resp.json()["job_id"]
            except (KeyError, ValueError) as exc:
                log.warning("wl_pool.submit_bad_body",
                            key=_mask_key(key), error=str(exc))
                continue

            self._last_used[key] = time.time()
            log.info("wl_pool.submitted",
                     cidr=cidr, job_id=job_id, key=_mask_key(key))
            return job_id, key

        return None

    def get_result(self, job_id: str, key: str) -> dict | None:
        try:
            resp = self._session.get(
                f"{self.base_url}/check/{job_id}",
                headers={"X-API-Key": key},
                proxies=self._proxies,
                timeout=self.request_timeout,
            )
        except requests.RequestException as exc:
            log.warning("wl_pool.get_network_error",
                        job_id=job_id, error=str(exc))
            return None

        if not resp.ok:
            log.warning("wl_pool.get_http_error",
                        job_id=job_id, status=resp.status_code)
            return None
        try:
            data = resp.json()
        except ValueError:
            return None

        if data.get("finished"):
            return data
        return None

    def mark_cooldown(self, key: str) -> None:
        self._last_used[key] = time.time()

    def next_available_in(self) -> float:
        if not self.keys:
            return 0.0
        now = time.time()
        waits: list[float] = []
        for key in self.keys:
            last = self._last_used.get(key, 0.0)
            wait = self.cooldown_seconds - (now - last)
            if wait <= 0:
                return 0.0
            waits.append(wait)
        return min(waits) if waits else 0.0
