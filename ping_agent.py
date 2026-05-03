#!/usr/bin/env python3
# ping_agent.py — Samsung ICMP ping agent
# Polls VM job server, pings /24 subnets via rmnet0, posts results back.
# Run: sudo python ping_agent.py

from __future__ import annotations

import os
import time

import requests
import structlog
from dotenv import load_dotenv

from src.checkers.icmp_checker import ICMPChecker

load_dotenv()

log = structlog.get_logger(__name__)

VM_URL       = os.environ.get("VM_URL", "").rstrip("/")
SECRET       = os.environ.get("PING_AGENT_SECRET", "")
INTERFACE    = os.environ.get("PING_INTERFACE", "rmnet0") or None
POLL_INTERVAL = float(os.environ.get("PING_POLL_INTERVAL", "2"))

_HEADERS = {"X-Secret": SECRET}
_checker = ICMPChecker(interface=INTERFACE)


def fetch_jobs() -> list[str]:
    resp = requests.get(f"{VM_URL}/ping-jobs", headers=_HEADERS, timeout=10)
    resp.raise_for_status()
    return resp.json()


def report_result(cidr: str, alive: int) -> None:
    requests.post(
        f"{VM_URL}/ping-results",
        json={"cidr": cidr, "alive": alive, "total": 254},
        headers=_HEADERS,
        timeout=10,
    )


def run_once(jobs: list[str]) -> None:
    for cidr in jobs:
        log.info("ping_agent.pinging", cidr=cidr)
        try:
            results = _checker.ping_subnet(cidr)
            alive = sum(1 for v in results.values() if v)
        except Exception as exc:
            log.warning("ping_agent.ping_error", cidr=cidr, error=str(exc))
            alive = 0
        log.info("ping_agent.result", cidr=cidr, alive=alive)
        report_result(cidr, alive)


def main() -> None:
    if not VM_URL:
        raise SystemExit("VM_URL is not set in .env")
    log.info("ping_agent.start", vm=VM_URL, interface=INTERFACE,
             poll_interval=POLL_INTERVAL)
    while True:
        try:
            jobs = fetch_jobs()
            if jobs:
                log.info("ping_agent.got_jobs", count=len(jobs))
                run_once(jobs)
        except Exception as exc:
            log.warning("ping_agent.poll_error", error=str(exc))
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
