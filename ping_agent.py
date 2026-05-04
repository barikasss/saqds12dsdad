#!/usr/bin/env python3
# ping_agent.py — Samsung ICMP ping agent
# Polls VM job server, pings /24 subnets via rmnet0, posts results back.
# Run: sudo python ping_agent.py
#
# FUTURE: migrate to asyncio + asyncio.create_subprocess_exec for lower
# memory overhead and better scalability (150+ concurrent subnets).
# Currently uses ThreadPoolExecutor(max_workers=PING_WORKERS) which gives
# ~2.6x speedup vs sequential with no false positives (tested on Note 9).

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import structlog
from dotenv import load_dotenv

from src.checkers.icmp_checker import ICMPChecker

load_dotenv()

log = structlog.get_logger(__name__)

VM_URL        = os.environ.get("VM_URL", "").rstrip("/")
SECRET        = os.environ.get("PING_AGENT_SECRET", "")
INTERFACE     = os.environ.get("PING_INTERFACE", "rmnet0") or None
POLL_INTERVAL = float(os.environ.get("PING_POLL_INTERVAL", "2"))
PING_WORKERS  = int(os.environ.get("PING_WORKERS", "3"))
CONCURRENCY   = int(os.environ.get("PING_CONCURRENCY", "16"))

_HEADERS = {"X-Secret": SECRET}
_checker = ICMPChecker(interface=INTERFACE, concurrency=CONCURRENCY)


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


def _ping_and_report(cidr: str) -> None:
    log.info("ping_agent.pinging", cidr=cidr)
    try:
        results = _checker.ping_subnet(cidr)
        alive = sum(1 for v in results.values() if v)
    except Exception as exc:
        log.warning("ping_agent.ping_error", cidr=cidr, error=str(exc))
        alive = 0
    log.info("ping_agent.result", cidr=cidr, alive=alive)
    report_result(cidr, alive)


def run_once(jobs: list[str]) -> None:
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        futures = {ex.submit(_ping_and_report, cidr): cidr for cidr in jobs}
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as exc:
                log.warning("ping_agent.worker_error", error=str(exc))


def main() -> None:
    if not VM_URL:
        raise SystemExit("VM_URL is not set in .env")
    log.info("ping_agent.start", vm=VM_URL, interface=INTERFACE,
             workers=PING_WORKERS, concurrency=CONCURRENCY,
             poll_interval=POLL_INTERVAL)
    try:
        while True:
            try:
                jobs = fetch_jobs()
                if jobs:
                    log.info("ping_agent.got_jobs", count=len(jobs))
                    run_once(jobs)
            except Exception as exc:
                log.warning("ping_agent.poll_error", error=str(exc))
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        log.info("ping_agent.stopped")


if __name__ == "__main__":
    main()
