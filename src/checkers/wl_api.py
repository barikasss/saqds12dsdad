# wl_api.py — WLChecker external API client (submit / poll results)

from __future__ import annotations

import ipaddress
import time
from pathlib import Path
from typing import Callable

import requests
import structlog

log = structlog.get_logger(__name__)


class WLError(Exception):
    pass


class WLAuthError(WLError):
    pass


class WLRateLimitError(WLError):
    pass


class WLTimeoutError(WLError):
    pass


def _mask_key(key: str) -> str:
    return key[:8] + "..." if len(key) > 8 else "***"



class WLCheckerClient:
    _MAX_BATCH_IPS = 256

    def __init__(
        self,
        base_url: str,
        api_key: str,
        submit_cooldown: int = 300,
        poll_interval: int = 5,
        poll_timeout: int = 600,
        cooldown_state_file: str = ".wl_cooldown",
        request_timeout: int = 30,
        proxy_url: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._submit_cooldown = submit_cooldown
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout
        self._cooldown_file = Path(cooldown_state_file)
        self._request_timeout = request_timeout
        self._proxy_url = proxy_url
        self._session = requests.Session()
        self._session.headers["X-API-Key"] = api_key

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self._base_url}{path}"
        proxies = {"http": self._proxy_url, "https": self._proxy_url} if self._proxy_url else None
        conn_failures = 0
        max_retries = 3

        while True:
            try:
                resp = self._session.request(
                    method, url, timeout=self._request_timeout, proxies=proxies, **kwargs
                )
            except requests.ConnectionError as exc:
                conn_failures += 1
                if conn_failures > max_retries:
                    raise WLError(f"Connection failed after {max_retries} retries") from exc
                delay = [2, 4, 8][conn_failures - 1]
                log.warning("wlchecker.connection_retry", attempt=conn_failures, delay=delay)
                time.sleep(delay)
                continue

            if resp.status_code in (401, 403):
                raise WLAuthError(f"Auth failed: HTTP {resp.status_code}")

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", 60))
                log.warning("wlchecker.rate_limit", retry_after=retry_after)
                time.sleep(retry_after)
                continue

            resp.raise_for_status()
            return resp

    def _read_last_submit_time(self) -> float:
        try:
            return float(self._cooldown_file.read_text().strip())
        except (FileNotFoundError, ValueError):
            return 0.0

    def _write_last_submit_time(self, ts: float) -> None:
        self._cooldown_file.write_text(str(ts))

    def submit(self, targets: list[str]) -> str:
        """POST /check, возвращает job_id. Ждёт cooldown если нужно."""
        last = self._read_last_submit_time()
        elapsed = time.time() - last
        if elapsed < self._submit_cooldown:
            wait = self._submit_cooldown - elapsed
            log.info("wlchecker.cooldown_wait", wait_seconds=round(wait, 1))
            time.sleep(wait)

        log.info("wlchecker.submit", count=len(targets), key=_mask_key(self._api_key))
        resp = self._request("POST", "/check", json={"targets": targets})
        data = resp.json()
        job_id: str = data["job_id"]
        self._write_last_submit_time(time.time())
        log.info("wlchecker.submitted", job_id=job_id, total=data.get("total"))
        return job_id

    def fetch(self, job_id: str) -> dict:
        """GET /check/{job_id}, возвращает сырой ответ."""
        resp = self._request("GET", f"/check/{job_id}")
        return resp.json()

    def wait_for_completion(
        self,
        job_id: str,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> dict:
        """Polls fetch() каждые poll_interval секунд пока finished=true или истечёт poll_timeout."""
        deadline = time.time() + self._poll_timeout
        last_done = -1

        while time.time() < deadline:
            data = self.fetch(job_id)
            done: int = data.get("done", 0)
            total: int = data.get("total", 0)

            if done != last_done:
                log.info("wlchecker.progress", job_id=job_id, done=done, total=total)
                last_done = done

            if on_progress:
                on_progress(done, total)

            if data.get("finished"):
                log.info("wlchecker.finished", job_id=job_id, total=total)
                return data

            time.sleep(self._poll_interval)

        raise WLTimeoutError(f"Job {job_id} timed out after {self._poll_timeout}s")

    def check_subnet(
        self,
        cidr: str,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> dict[str, bool]:
        """submit + wait, возвращает {ip: alive}. Игнорирует status=pending."""
        job_id = self.submit([cidr])
        data = self.wait_for_completion(job_id, on_progress=on_progress)
        return {
            r["ip"]: bool(r["alive"])
            for r in data.get("results", [])
            if r.get("status") == "done" and r.get("alive") is not None
        }

    def check_subnets_batch(self, cidrs: list[str]) -> dict[str, dict[str, bool]]:
        """Проверяет несколько CIDR через минимальное число submit-вызовов (батчи ≤256 IP)."""
        def ip_count(cidr: str) -> int:
            return ipaddress.ip_network(cidr, strict=False).num_addresses

        def find_parent_cidr(ip: str) -> str | None:
            addr = ipaddress.ip_address(ip)
            for c in cidrs:
                if addr in ipaddress.ip_network(c, strict=False):
                    return c
            return None

        batches: list[list[str]] = []
        current: list[str] = []
        current_count = 0

        for cidr in cidrs:
            n = ip_count(cidr)
            if current_count + n > self._MAX_BATCH_IPS and current:
                batches.append(current)
                current = []
                current_count = 0
            current.append(cidr)
            current_count += n

        if current:
            batches.append(current)

        results: dict[str, dict[str, bool]] = {cidr: {} for cidr in cidrs}

        for batch in batches:
            job_id = self.submit(batch)
            data = self.wait_for_completion(job_id)
            for r in data.get("results", []):
                if r.get("status") == "done" and r.get("alive") is not None:
                    parent = find_parent_cidr(r["ip"])
                    if parent:
                        results[parent][r["ip"]] = bool(r["alive"])

        return results

    def is_subnet_white(
        self,
        cidr_results: dict[str, bool],
        threshold: float = 0.05,
    ) -> bool:
        """Эвристика: подсеть "белая" если >= threshold IP отвечают."""
        if not cidr_results:
            return False
        alive = sum(1 for v in cidr_results.values() if v)
        if threshold <= 0:
            return alive > 0
        return alive / len(cidr_results) >= threshold
