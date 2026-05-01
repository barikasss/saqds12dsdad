# tcp_checker.py — async TCP port probe (asyncio.open_connection, stdlib only)

from __future__ import annotations

import asyncio
import ipaddress

import structlog

log = structlog.get_logger(__name__)


class TCPChecker:
    def __init__(
        self,
        ports: list[int] | None = None,
        timeout: float = 2.0,
        concurrency: int = 16,
    ) -> None:
        self.ports = list(ports) if ports is not None else [22, 80, 443]
        self.timeout = timeout
        self.concurrency = concurrency

    async def probe(self, ip: str, port: int) -> bool:
        """TCP connect probe. True if the three-way handshake completes."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def probe_ip(self, ip: str) -> list[int]:
        """Probe all configured ports for ip in parallel. Returns open ports."""
        results = await asyncio.gather(
            *[self.probe(ip, port) for port in self.ports]
        )
        return [port for port, open_ in zip(self.ports, results) if open_]

    async def probe_subnet(
        self,
        cidr: str,
        on_progress=None,
    ) -> dict[str, list[int]]:
        """Probe all host addresses in cidr with Semaphore(concurrency).

        Returns {ip: [open_ports]}. Empty list means all ports closed/filtered.
        Raises ValueError on bad CIDR.
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR '{cidr}': {exc}") from exc

        hosts = [str(ip) for ip in network.hosts()]
        sem = asyncio.Semaphore(self.concurrency)
        completed = 0

        async def probe_one(ip: str) -> tuple[str, list[int]]:
            nonlocal completed
            async with sem:
                open_ports = await self.probe_ip(ip)
            completed += 1
            if on_progress:
                on_progress(completed, len(hosts))
            return ip, open_ports

        pairs = await asyncio.gather(*[probe_one(ip) for ip in hosts])
        results = dict(pairs)

        hosts_with_open = sum(1 for ports in results.values() if ports)
        log.info(
            "tcp.subnet_done",
            cidr=cidr,
            hosts_with_open_ports=hosts_with_open,
            total=len(hosts),
        )
        return results

    def probe_subnet_sync(
        self,
        cidr: str,
        on_progress=None,
    ) -> dict[str, list[int]]:
        """Synchronous wrapper around probe_subnet. Call from non-async contexts."""
        try:
            return asyncio.run(self.probe_subnet(cidr, on_progress=on_progress))
        except KeyboardInterrupt:
            raise
