"""
Checks for ICMP and TCP checkers.

Network notes:
  127.0.0.1        — loopback, always reachable
  240.0.0.1        — Class-E reserved; kernel rejects routing → always unreachable
  240.0.0.0/29     — 6 Class-E hosts (.1-.6), all unreachable, used for concurrency tests
"""
import asyncio
import socket
import time

import pytest

from src.checkers.icmp_checker import ICMPChecker
from src.checkers.tcp_checker import TCPChecker

# Class-E (240.0.0.0/4) — kernel drops packets, no route exists on any normal host
UNREACHABLE_IP = "240.0.0.1"
UNREACHABLE_SUBNET_29 = "240.0.0.0/29"   # 6 usable hosts: .1 - .6


# ---------------------------------------------------------------------------
# ICMP tests
# ---------------------------------------------------------------------------

def test_ping_localhost():
    checker = ICMPChecker(timeout=1.0, count=1)
    assert checker.ping_one("127.0.0.1") is True


def test_ping_unreachable():
    checker = ICMPChecker(timeout=1.0, count=1)
    assert checker.ping_one(UNREACHABLE_IP) is False


def test_ping_subnet_concurrency():
    # /29 → 6 hosts; all unreachable → all timeout at ~1s each.
    # Parallel execution must finish well under 5 × timeout.
    checker = ICMPChecker(timeout=1.0, concurrency=32)
    t0 = time.monotonic()
    results = checker.ping_subnet(UNREACHABLE_SUBNET_29)
    elapsed = time.monotonic() - t0

    assert len(results) == 6                       # .1 through .6
    assert all(v is False for v in results.values())
    assert elapsed < 5 * checker.timeout           # 5 s — sequential would be ~6 s


def test_ping_handles_invalid_cidr():
    checker = ICMPChecker()
    with pytest.raises(ValueError):
        checker.ping_subnet("not_a_valid_cidr")


# ---------------------------------------------------------------------------
# TCP tests  (pytest-asyncio with asyncio_mode=auto handles async def)
# ---------------------------------------------------------------------------

async def test_probe_localhost_open():
    """Open a real listening socket, probe it → True."""
    server = await asyncio.start_server(
        lambda r, w: w.close(), "127.0.0.1", 0
    )
    port: int = server.sockets[0].getsockname()[1]
    try:
        checker = TCPChecker(timeout=2.0)
        result = await checker.probe("127.0.0.1", port)
    finally:
        server.close()
        await server.wait_closed()
    assert result is True


async def test_probe_localhost_closed():
    """Bind a port to get its number, release it, then probe → False (RST)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port: int = s.getsockname()[1]
    s.close()  # nothing is listening; OS will send RST

    checker = TCPChecker(timeout=1.0)
    result = await checker.probe("127.0.0.1", port)
    assert result is False


async def test_probe_subnet_async():
    # 6 Class-E hosts, each probed on 1 port.
    # Sequential would take 6 × timeout; parallel takes ~timeout.
    checker = TCPChecker(ports=[80], timeout=0.5, concurrency=16)
    t0 = time.monotonic()
    results = await checker.probe_subnet(UNREACHABLE_SUBNET_29)
    elapsed = time.monotonic() - t0

    assert len(results) == 6
    assert all(ports == [] for ports in results.values())
    # 6 sequential × 0.5 s = 3 s; parallel should finish in < 5 × 0.5 = 2.5 s
    assert elapsed < 5 * checker.timeout


async def test_probe_handles_timeout():
    """Probe to unreachable IP with tight timeout must return False, not raise."""
    checker = TCPChecker(timeout=0.3)
    result = await checker.probe(UNREACHABLE_IP, 80)
    assert result is False
