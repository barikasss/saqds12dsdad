# proxy_pool.py — SOCKS5 proxy pool with round-robin and per-proxy cooldown

from __future__ import annotations

import time

import structlog

log = structlog.get_logger(__name__)


class ProxyPool:
    """Round-robin pool of SOCKS5 proxy URLs with per-proxy cooldown.

    get()     → first proxy whose cooldown has elapsed, or None if all busy
    release() → marks proxy as used, starts cooldown timer
    """

    def __init__(
        self,
        proxies: list[str],
        cooldown_seconds: int = 120,
    ) -> None:
        self.proxies = list(proxies)
        self.cooldown_seconds = cooldown_seconds
        self._released_at: dict[str, float] = {}

    def get(self) -> str | None:
        """Return the first available proxy URL, or None if all are in cooldown."""
        if not self.proxies:
            return None
        now = time.time()
        for proxy in self.proxies:
            last = self._released_at.get(proxy, 0.0)
            if now - last >= self.cooldown_seconds:
                log.debug("proxy_pool.acquired", proxy=_mask(proxy))
                return proxy
        return None

    def release(self, proxy_url: str) -> None:
        """Start cooldown timer for this proxy after use."""
        self._released_at[proxy_url] = time.time()
        log.debug("proxy_pool.released", proxy=_mask(proxy_url))

    def next_available_in(self) -> float:
        """Seconds until at least one proxy is free; 0 if any is free now."""
        if not self.proxies:
            return 0.0
        now = time.time()
        waits: list[float] = []
        for proxy in self.proxies:
            last = self._released_at.get(proxy, 0.0)
            wait = self.cooldown_seconds - (now - last)
            if wait <= 0:
                return 0.0
            waits.append(wait)
        return min(waits) if waits else 0.0

    @staticmethod
    def from_env(env_value: str, cooldown_seconds: int = 120) -> "ProxyPool":
        """Build ProxyPool from comma-separated SELECTEL_PROXIES env value."""
        proxies = [p.strip() for p in env_value.split(",") if p.strip()]
        return ProxyPool(proxies=proxies, cooldown_seconds=cooldown_seconds)

    @staticmethod
    def from_file(path: str, cooldown_seconds: int = 0) -> "ProxyPool":
        """Build ProxyPool from a file with one proxy URL per line."""
        from pathlib import Path
        lines = Path(path).read_text().splitlines()
        proxies = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        return ProxyPool(proxies=proxies, cooldown_seconds=cooldown_seconds)


class ResellProxyPool:
    """Simple round-robin proxy pool for Resell API — no cooldown, rotates on every call."""

    def __init__(self, proxy_urls: list[str]) -> None:
        self.proxy_urls = list(proxy_urls)
        self._idx = 0

    def next(self) -> str | None:
        if not self.proxy_urls:
            return None
        proxy = self.proxy_urls[self._idx % len(self.proxy_urls)]
        self._idx += 1
        return proxy

    @staticmethod
    def from_env(env_value: str) -> "ResellProxyPool":
        proxies = [p.strip() for p in env_value.split(",") if p.strip()]
        return ResellProxyPool(proxy_urls=proxies)


def _mask(proxy_url: str) -> str:
    """Hide credentials in proxy URL for logging."""
    try:
        # socks5://user:pass@host:port → socks5://***@host:port
        if "@" in proxy_url:
            scheme_rest = proxy_url.split("://", 1)
            if len(scheme_rest) == 2:
                creds_host = scheme_rest[1].split("@", 1)
                return f"{scheme_rest[0]}://***@{creds_host[1]}"
    except Exception:
        pass
    return proxy_url
