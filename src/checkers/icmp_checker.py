# icmp_checker.py — ICMP ping probe for a given IP or subnet

from __future__ import annotations

import ipaddress
import platform
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import structlog

log = structlog.get_logger(__name__)


class ICMPChecker:
    def __init__(
        self,
        timeout: float = 1.0,
        count: int = 1,
        concurrency: int = 32,
    ) -> None:
        self.timeout = timeout
        self.count = count
        self.concurrency = concurrency

    def _ping_bin(self) -> str:
        found = shutil.which("ping")
        if found:
            return found
        return "/system/bin/ping"  # Termux / Android fallback

    def ping_one(self, ip: str) -> bool:
        """System ping via subprocess. Returns True if the host replied."""
        ping_bin = self._ping_bin()
        system = platform.system()

        if system == "Windows":
            cmd = [
                ping_bin, "-n", str(self.count),
                "-w", str(int(self.timeout * 1000)),
                ip,
            ]
        else:
            # Linux / macOS / Termux
            # busybox ping needs an integer; modern iputils accepts floats.
            # Use int with min=1 so we never pass "-W 0".
            timeout_arg = str(max(1, int(self.timeout)))
            cmd = [ping_bin, "-c", str(self.count), "-W", timeout_arg, ip]

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout * self.count + 2,
            )
            return proc.returncode == 0
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return False

    def ping_subnet(
        self,
        cidr: str,
        on_progress=None,
    ) -> dict[str, bool]:
        """Ping all host addresses in cidr in parallel.

        Excludes network and broadcast addresses (mirrors network.hosts()).
        Raises ValueError on bad CIDR.
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR '{cidr}': {exc}") from exc

        hosts = [str(ip) for ip in network.hosts()]
        results: dict[str, bool] = {}
        completed = 0

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {executor.submit(self.ping_one, ip): ip for ip in hosts}
            try:
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        results[ip] = future.result()
                    except Exception:
                        results[ip] = False
                    completed += 1
                    if on_progress:
                        on_progress(completed, len(hosts))
            except KeyboardInterrupt:
                executor.shutdown(wait=False, cancel_futures=True)
                raise

        alive = sum(1 for v in results.values() if v)
        log.info("icmp.subnet_done", cidr=cidr, alive=alive, total=len(hosts))
        return results
