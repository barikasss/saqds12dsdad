# orchestrator.py — main loop: parallel FIP creation + ICMP/WL verification

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import random
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
import structlog

from src.checkers.icmp_checker import ICMPChecker
from src.checkers.wl_pool import WLKeyPool
from src.config import load_config
from src.notifier import TelegramNotifier
from src.proxy_pool import ProxyPool
from src.selectel_api import SelectelAPIError, SelectelClient, SelectelRateLimitError
from src.subnet_filter import SubnetFilter
from src.subnet_source import SubnetSource, _atomic_write

log = structlog.get_logger(__name__)

MAX_FIPS_PER_ACCOUNT = 12


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ip_to_cidr24(ip: str) -> str:
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def _fmt_elapsed(seconds: float) -> str:
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# ---------------------------------------------------------------------------
# AccountPool
# ---------------------------------------------------------------------------

class AccountPool:
    """Round-robin scheduler over Selectel clients with per-account block windows."""

    def __init__(self, clients: list) -> None:
        if not clients:
            raise ValueError("AccountPool requires at least one client")
        self._clients = clients
        self._blocked_until: dict[int, datetime] = {}
        self._idx = 0

    @property
    def clients(self) -> list:
        return self._clients

    def next(self):
        now = datetime.now(timezone.utc)
        for i in range(len(self._clients)):
            idx = (self._idx + i) % len(self._clients)
            client = self._clients[idx]
            cid = id(client)
            if cid not in self._blocked_until or self._blocked_until[cid] <= now:
                self._idx = (idx + 1) % len(self._clients)
                return client
        raise RuntimeError("All accounts are rate limited")

    def is_blocked(self, client) -> bool:
        cid = id(client)
        if cid not in self._blocked_until:
            return False
        return self._blocked_until[cid] > datetime.now(timezone.utc)

    def mark_rate_limited(self, client, until: datetime) -> None:
        self._blocked_until[id(client)] = until
        log.info("pool.rate_limited",
                 account=getattr(client, "username", "?"),
                 until=until.isoformat())

    def all_blocked(self) -> bool:
        now = datetime.now(timezone.utc)
        return all(
            id(c) in self._blocked_until and self._blocked_until[id(c)] > now
            for c in self._clients
        )

    def next_available_in(self) -> float:
        """Seconds until at least one client is free; 0 if any is free now."""
        now = datetime.now(timezone.utc)
        waits: list[float] = []
        for c in self._clients:
            cid = id(c)
            if cid not in self._blocked_until or self._blocked_until[cid] <= now:
                return 0.0
            waits.append((self._blocked_until[cid] - now).total_seconds())
        return min(waits) if waits else 0.0

    def reset_blocks(self) -> None:
        self._blocked_until.clear()
        log.info("pool.blocks_reset")


# ---------------------------------------------------------------------------
# Dry-run client — synthesises FIPs from priority_subnets
# ---------------------------------------------------------------------------

class _DryRunClient:
    """Stand-in for SelectelClient in --dry-run mode.

    create_floating_ip_safe() returns a fake FIP whose IP is a random host
    drawn from the configured priority subnets (so it lands in the whitelist).
    """

    def __init__(self, username: str, subnets: list[str], region: str = "ru-2") -> None:
        self.username = username
        self._region = region
        self._subnets = list(subnets)
        self._allocated: dict[str, dict] = {}
        self._counter = 0

    def list_floating_ips(self, max_conn_retries: int = 3) -> list[dict]:
        return list(self._allocated.values())

    def list_external_networks(self) -> list[dict]:
        return [{"id": "dry-network"}]

    def create_floating_ip_safe(
        self,
        network_id: str | None = None,
        availability_zone: str | None = None,
    ) -> dict:
        if not self._subnets:
            raise SelectelRateLimitError(429, "dry-run: no priority subnets configured")
        self._counter += 1
        subnet = self._subnets[self._counter % len(self._subnets)]
        net = ipaddress.ip_network(subnet, strict=False)
        host = random.choice(list(net.hosts()))
        fip_id = f"dry-{self.username}-{self._counter}"
        fip = {"id": fip_id, "floating_ip_address": str(host)}
        self._allocated[fip_id] = fip
        log.info("dryrun.fip_created", id=fip_id, ip=str(host), account=self.username)
        return fip

    def delete_floating_ip(self, fip_id: str) -> bool:
        self._allocated.pop(fip_id, None)
        log.info("dryrun.fip_deleted", id=fip_id, account=self.username)
        return True


# ---------------------------------------------------------------------------
# SubnetTask
# ---------------------------------------------------------------------------

@dataclass
class SubnetTask:
    cidr: str
    fip_id: str
    fip_ip: str
    account: str
    client: Any
    icmp_result: bool | None = None
    icmp_enqueued: bool = False
    wl_job_id: str | None = None
    wl_key: str | None = None
    wl_result: bool | None = None
    created_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# PingAgentClient — HTTP client for remote Samsung ICMP via job server
# ---------------------------------------------------------------------------

class PingAgentClient:
    """Talks to job_server HTTP API to enqueue CIDRs and poll results."""

    def __init__(self, url: str, secret: str, timeout_seconds: int = 60) -> None:
        self.url = url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._headers = {"X-Secret": secret}
        self._session = requests.Session()

    def enqueue(self, cidr: str) -> bool:
        try:
            r = self._session.post(
                f"{self.url}/enqueue",
                json={"cidr": cidr},
                headers=self._headers,
                timeout=5,
            )
            return r.status_code in (200, 204)
        except Exception as exc:
            log.warning("ping_client.enqueue_error", cidr=cidr, error=str(exc))
            return False

    def get_result(self, cidr: str) -> int | None:
        try:
            r = self._session.get(
                f"{self.url}/ping-results",
                params={"cidr": cidr},
                headers=self._headers,
                timeout=5,
            )
            if r.status_code == 200:
                return r.json().get("alive")
            return None
        except Exception as exc:
            log.warning("ping_client.result_error", cidr=cidr, error=str(exc))
            return None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    def __init__(
        self,
        config_path: str = "config.yaml",
        dry_run: bool = False,
        no_icmp: bool = False,
    ) -> None:
        self.dry_run = dry_run
        self.no_icmp = no_icmp
        self._running = True
        self._start_time = time.monotonic()
        self._last_progress_notify = time.monotonic()
        self._iteration = 0
        self._pending_tasks: list[SubnetTask] = []
        self.stats: dict = {
            "checked": 0,
            "white_found": 0,
            "dead": 0,
            "deleted_not_in_whitelist": 0,
            "skipped_dead_subnet": 0,
            "total_created": 0,
            "suspects": 0,
            "start_time": datetime.now(timezone.utc).isoformat(),
        }

        self.cfg = load_config(config_path)
        self._init_components()

        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    # ------------------------------------------------------------------

    def _init_components(self) -> None:
        cfg = self.cfg

        sel = cfg.get("selectel", {})
        self._zone: str = sel.get("availability_zone", sel.get("region", "ru-2"))

        sr = cfg.get("search", {})
        priority: list[str] = sr.get("priority_subnets", [])

        # Shared proxy pool for create_floating_ip_safe (split branch)
        proxies_env = os.environ.get("SELECTEL_PROXIES", "").strip()
        proxy_cooldown = int(os.environ.get("SELECTEL_PROXY_COOLDOWN", "0"))
        proxy_pool = ProxyPool.from_env(proxies_env, cooldown_seconds=proxy_cooldown) if proxies_env else None
        if proxy_pool:
            log.info("orch.proxy_pool_loaded", count=len(proxy_pool.proxies))

        if self.dry_run:
            self._clients = [
                _DryRunClient("dry-A", priority, region=self._zone),
                _DryRunClient("dry-B", priority, region=self._zone),
            ]
        else:
            accounts_cfg: list[dict] = cfg.get("selectel_accounts", [])
            enabled = [a for a in accounts_cfg if a.get("enabled", True)]
            if enabled:
                self._clients = [
                    SelectelClient(
                        account_id=a.get("account_id", ""),
                        username=a.get("username", ""),
                        password=os.environ.get(a.get("password_env", ""), ""),
                        project_id=a.get("project_id") or None,
                        region=a.get("availability_zone", self._zone),
                        proxy_url=a.get("proxy_url") or None,
                        proxy_pool=proxy_pool,
                    )
                    for a in enabled
                ]
            else:
                self._clients = [SelectelClient(
                    account_id=os.environ.get(sel.get("account_id_env", "SELECTEL_ACCOUNT_ID"), ""),
                    username=os.environ.get(sel.get("username_env", "SELECTEL_USERNAME"), ""),
                    password=os.environ.get(sel.get("password_env", "SELECTEL_PASSWORD"), ""),
                    project_id=os.environ.get(sel.get("project_id_env", "SELECTEL_PROJECT_ID"), "") or None,
                    region=self._zone,
                    proxy_url=sel.get("proxy_url") or None,
                    proxy_pool=proxy_pool,
                )]

        self._account_pool = AccountPool(self._clients)

        c = cfg.get("checkers", {})
        ic = c.get("icmp", {})
        self.icmp = ICMPChecker(
            timeout=ic.get("timeout", 1.0),
            concurrency=ic.get("concurrency", 32),
            interface=ic.get("interface") or None,
        )

        wc = c.get("wlchecker", {})
        keys_env = os.environ.get("WL_API_KEYS", "").strip()
        keys = [k.strip() for k in keys_env.split(",") if k.strip()]
        self.wl_pool = WLKeyPool(
            keys=keys,
            base_url=wc.get("base_url", "http://150.241.74.147:8082"),
            cooldown_seconds=wc.get("submit_cooldown_seconds", 300),
            proxy_url=wc.get("proxy_url"),
        )
        self._wl_min_alive: int = wc.get("min_alive", 5)

        self.source = SubnetSource(priority_subnets=priority)
        self.filter = SubnetFilter.from_file(
            file_path="data/white_subnets.txt",
            extra_cidrs=priority,
        )

        self._dead_subnets_file = "data/dead_subnets.txt"
        self._dead_subnets: set[str] = set()
        dead_path = Path(self._dead_subnets_file)
        if dead_path.exists():
            self._dead_subnets = {
                line.strip()
                for line in dead_path.read_text().splitlines()
                if line.strip()
            }
            if self._dead_subnets:
                log.info("orch.dead_cache_loaded", count=len(self._dead_subnets))

        nt = cfg.get("notifier", {}).get("telegram", {})
        tg_token = os.environ.get(nt.get("bot_token_env", "TG_BOT_TOKEN"), "")
        tg_chat = os.environ.get(nt.get("chat_id_env", "TG_CHAT_ID"), "")
        proxy_url = nt.get("proxy_url") or os.environ.get("TG_PROXY_URL") or None
        self.notifier = TelegramNotifier(
            bot_token=tg_token or "dummy",
            chat_id=tg_chat or "0",
            enabled=bool(tg_token and tg_chat),
            proxy_url=proxy_url,
        )

        pa_cfg = cfg.get("ping_agent", {})
        if pa_cfg.get("enabled", False):
            pa_secret = os.environ.get(pa_cfg.get("secret_env", "PING_AGENT_SECRET"), "")
            self._ping_client: PingAgentClient | None = PingAgentClient(
                url=pa_cfg.get("url", ""),
                secret=pa_secret,
                timeout_seconds=pa_cfg.get("timeout_seconds", 60),
            )
            log.info("orch.ping_agent_enabled", url=self._ping_client.url)
        else:
            self._ping_client = None

        self.ip_log_file = "data/ip_log.jsonl"

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log_ip(self, ip: str, **kwargs) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "ip": ip, **kwargs}
        path = Path(self.ip_log_file)
        try:
            path.parent.mkdir(exist_ok=True)
            with open(path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as exc:
            log.warning("orch.ip_log_error", error=str(exc))

    def _save_found_ip(self, task: SubnetTask) -> None:
        path = Path("data") / "found_ips.json"
        try:
            path.parent.mkdir(exist_ok=True)
            try:
                existing: list = json.loads(path.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                existing = []
            existing.append({
                "ip": task.fip_ip,
                "cidr": task.cidr,
                "fip_id": task.fip_id,
                "account": task.account,
                "icmp_result": task.icmp_result,
                "wl_result": task.wl_result,
                "found_at": datetime.now(timezone.utc).isoformat(),
            })
            _atomic_write(str(path), existing)
        except Exception as exc:
            log.warning("orch.save_found_failed", error=str(exc))

    def _save_suspect_ip(self, task: SubnetTask, reason: str) -> None:
        """Save FIP that passed ICMP but WL rejected — user must verify manually."""
        path = Path("data") / "suspects.json"
        try:
            path.parent.mkdir(exist_ok=True)
            try:
                existing: list = json.loads(path.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                existing = []
            existing.append({
                "ip": task.fip_ip,
                "cidr": task.cidr,
                "fip_id": task.fip_id,
                "account": task.account,
                "icmp_result": task.icmp_result,
                "wl_result": task.wl_result,
                "reason": reason,
                "found_at": datetime.now(timezone.utc).isoformat(),
            })
            _atomic_write(str(path), existing)
        except Exception as exc:
            log.warning("orch.save_suspect_failed", error=str(exc))

    def _append_dead_subnet(self, cidr: str) -> None:
        try:
            path = Path(self._dead_subnets_file)
            path.parent.mkdir(exist_ok=True)
            with open(path, "a") as f:
                f.write(cidr + "\n")
        except Exception as exc:
            log.warning("orch.dead_cache_write_error", cidr=cidr, error=str(exc))

    @staticmethod
    def _safe_delete(client, fip_id: str) -> None:
        try:
            client.delete_floating_ip(fip_id)
        except Exception as exc:
            log.warning("orch.delete_failed", fip_id=fip_id, error=str(exc))

    def _get_account_fips_counts(self) -> dict[str, int]:
        """Returns {account_name: fips_count} for current FIPs."""
        counts: dict[str, int] = {}
        for client in self._account_pool.clients:
            try:
                fips = client.list_floating_ips()
                counts[client.username] = len(fips)
            except Exception:
                counts[client.username] = 0
        return counts

    # ------------------------------------------------------------------
    # Startup cleanup: reclaim whitelisted FIPs, delete the rest
    # ------------------------------------------------------------------

    def _cleanup_existing_fips(self) -> None:
        log.info("orch.cleanup_start")
        reclaimed = 0
        deleted = 0
        for client in self._account_pool.clients:
            try:
                fips = client.list_floating_ips(max_conn_retries=1)
            except Exception as exc:
                log.warning("orch.cleanup_list_error",
                            account=getattr(client, "username", "?"), error=str(exc))
                # Connection/timeout errors (status=0) are not rate-limits — skip block
                if not (isinstance(exc, SelectelAPIError) and exc.status == 0):
                    self._account_pool.mark_rate_limited(
                        client,
                        datetime.now(timezone.utc) + timedelta(seconds=120),
                    )
                continue

            for fip in fips:
                ip = fip.get("floating_ip_address", "")
                fip_id = fip.get("id", "")
                if not ip or not fip_id:
                    continue

                subnet = ip_to_cidr24(ip)
                if self.filter.is_ip_in_whitelist(ip):
                    already = any(t.fip_id == fip_id for t in self._pending_tasks)
                    if not already:
                        task = SubnetTask(
                            cidr=subnet,
                            fip_id=fip_id,
                            fip_ip=ip,
                            account=client.username,
                            client=client,
                        )
                        self._pending_tasks.append(task)
                        self._log_ip(ip, event="reclaimed", subnet=subnet,
                                     account=client.username, fip_id=fip_id)
                        log.info("orch.fip_reclaimed", ip=ip, subnet=subnet,
                                 account=client.username)
                        reclaimed += 1
                else:
                    self._safe_delete(client, fip_id)
                    self._log_ip(ip, event="cleanup_deleted", subnet=subnet,
                                 account=client.username, fip_id=fip_id)
                    log.info("orch.cleanup_deleted", ip=ip, subnet=subnet,
                             account=client.username)
                    deleted += 1

        log.info("orch.cleanup_done", reclaimed=reclaimed, deleted=deleted)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _handle_shutdown(self, signum, frame) -> None:
        log.warning("orch.shutdown_signal",
                    signal=int(signum), pending=len(self._pending_tasks))
        self._running = False

        # Fire-and-forget: dispatch deletes on daemon threads, give them ~2s to land
        for task in list(self._pending_tasks):
            threading.Thread(
                target=self._safe_delete,
                args=(task.client, task.fip_id),
                daemon=True,
            ).start()
        if self._pending_tasks:
            time.sleep(2)

        # Non-blocking Telegram notify (daemon thread — won't delay exit)
        threading.Thread(
            target=lambda: self.notifier.notify_warning(
                "Остановлено пользователем", context={"signal": int(signum)}
            ),
            daemon=True,
        ).start()

        sys.exit(130)

    # ------------------------------------------------------------------
    # Phase 1: create FIPs up to MAX per account
    # ------------------------------------------------------------------

    def _create_phase(self) -> None:
        for client in self._account_pool.clients:
            if not self._running:
                return
            if self._account_pool.is_blocked(client):
                continue

            try:
                fips_count = len(client.list_floating_ips())
            except Exception as exc:
                log.warning("orch.list_fips_error",
                            account=getattr(client, "username", "?"), error=str(exc))
                # Connection/timeout errors (status=0) are not rate-limits — skip block
                if not (isinstance(exc, SelectelAPIError) and exc.status == 0):
                    self._account_pool.mark_rate_limited(
                        client,
                        datetime.now(timezone.utc) + timedelta(seconds=60),
                    )
                continue

            while fips_count < MAX_FIPS_PER_ACCOUNT and self._running:
                log.info("orch.creating_fip",
                         account=client.username, slot=fips_count + 1)
                try:
                    fip = client.create_floating_ip_safe(
                        availability_zone=getattr(client, "_region", self._zone),
                    )
                except SelectelRateLimitError:
                    self._account_pool.mark_rate_limited(
                        client,
                        datetime.now(timezone.utc) + timedelta(seconds=120),
                    )
                    break
                except Exception as exc:
                    err_str = str(exc)
                    log.warning("orch.fip_create_error",
                                account=client.username, error=err_str)
                    if "ExternalIpAddressExhausted" in err_str:
                        self._account_pool.mark_rate_limited(
                            client,
                            datetime.now(timezone.utc) + timedelta(seconds=30),
                        )
                    break

                fips_count += 1  # counts toward MAX even if we delete below
                self.stats["total_created"] += 1
                ip = fip.get("floating_ip_address", "")
                if not ip:
                    continue

                subnet = ip_to_cidr24(ip)
                self.stats["checked"] += 1
                self._log_ip(ip, event="received", subnet=subnet,
                             account=client.username, fip_id=fip.get("id"))
                log.info("orch.fip_received",
                         ip=ip, subnet=subnet, account=client.username)

                if not self.filter.is_ip_in_whitelist(ip):
                    self._safe_delete(client, fip["id"])
                    self._log_ip(ip, event="deleted", subnet=subnet,
                                 reason="not_in_whitelist", account=client.username)
                    self.stats["deleted_not_in_whitelist"] += 1
                    log.info("orch.deleted_not_in_whitelist",
                             ip=ip, subnet=subnet)
                    continue

                if subnet in self._dead_subnets:
                    self._safe_delete(client, fip["id"])
                    self._log_ip(ip, event="deleted", subnet=subnet,
                                 reason="dead_subnet_cached", account=client.username)
                    self.stats["skipped_dead_subnet"] += 1
                    log.info("orch.skipped_dead_subnet", ip=ip, subnet=subnet)
                    continue

                task = SubnetTask(
                    cidr=subnet,
                    fip_id=fip["id"],
                    fip_ip=ip,
                    account=client.username,
                    client=client,
                )
                self._pending_tasks.append(task)
                self._log_ip(ip, event="task_created", subnet=subnet,
                             account=client.username)
                log.info("orch.task_created", ip=ip, subnet=subnet)

                # Submit to WL immediately — skip if same CIDR already submitted
                already_submitted = any(
                    t.wl_job_id is not None and t.cidr == task.cidr
                    for t in self._pending_tasks
                )
                if not already_submitted:
                    got = self.wl_pool.submit(task.cidr)
                    if got is not None:
                        task.wl_job_id, task.wl_key = got

    # ------------------------------------------------------------------
    # Phase 2: verify — ICMP and WL run in parallel
    # ------------------------------------------------------------------

    def _verify_phase(self) -> None:
        if not self._pending_tasks:
            return

        # Step 1 — ICMP probe (remote via Samsung agent OR local)
        if self._ping_client is not None and not self.no_icmp:
            # Remote ICMP: enqueue — one request per unique CIDR
            enqueued_cidrs = {t.cidr for t in self._pending_tasks if t.icmp_enqueued}
            for task in self._pending_tasks:
                if task.icmp_result is None and not task.icmp_enqueued:
                    if task.cidr not in enqueued_cidrs:
                        if self._ping_client.enqueue(task.cidr):
                            enqueued_cidrs.add(task.cidr)
                            log.info("orch.remote_icmp_enqueued", cidr=task.cidr)
                    if task.cidr in enqueued_cidrs:
                        task.icmp_enqueued = True

            # Poll results — propagate to all tasks with same CIDR
            checked: dict[str, int | None] = {}
            for task in self._pending_tasks:
                if task.icmp_result is None and task.icmp_enqueued:
                    if task.cidr not in checked:
                        checked[task.cidr] = self._ping_client.get_result(task.cidr)
                    result = checked[task.cidr]
                    if result is not None:
                        task.icmp_result = result > 0
                        log.info("orch.remote_icmp_done",
                                 cidr=task.cidr, alive=result)
                    elif time.time() - task.created_at > self._ping_client.timeout_seconds:
                        log.warning("orch.remote_icmp_timeout", cidr=task.cidr)
                        task.icmp_result = False

        elif not self.no_icmp:
            # Local ICMP
            todo = [t for t in self._pending_tasks if t.icmp_result is None]
            if todo:
                with ThreadPoolExecutor(max_workers=min(8, len(todo))) as ex:
                    futures = {ex.submit(self.icmp.ping_subnet, t.cidr): t for t in todo}
                    for fut, task in futures.items():
                        try:
                            res = fut.result()
                        except Exception as exc:
                            log.warning("orch.icmp_error",
                                        cidr=task.cidr, error=str(exc))
                            task.icmp_result = False
                            continue
                        alive = sum(1 for v in res.values() if v)
                        task.icmp_result = alive > 0
                        log.info("orch.icmp_done",
                                 cidr=task.cidr, alive=alive, total=len(res))

        # Step 2 — WL retry for tasks where pool was exhausted at create time
        for task in self._pending_tasks:
            if task.wl_job_id is None:
                got = self.wl_pool.submit(task.cidr)
                if got is not None:
                    task.wl_job_id, task.wl_key = got

        # Step 3 — Poll WL results
        for task in self._pending_tasks:
            if task.wl_job_id and task.wl_key and task.wl_result is None:
                r = self.wl_pool.get_result(task.wl_job_id, task.wl_key)
                if r:
                    alive = sum(1 for x in r.get("results", []) if x.get("alive"))
                    task.wl_result = alive >= self._wl_min_alive
                    event = "wl_confirmed" if task.wl_result else "wl_dead"
                    self._log_ip(task.fip_ip, event=event, subnet=task.cidr,
                                 wl_alive=alive, account=task.account)
                    log.info("orch.wl_done", cidr=task.cidr,
                             alive=alive, result=task.wl_result)

        # --no-icmp: WL result drives the ICMP field (no real pinging)
        if self.no_icmp:
            for task in self._pending_tasks:
                if task.icmp_result is None and task.wl_result is not None:
                    task.icmp_result = task.wl_result

    # ------------------------------------------------------------------
    # Phase 3: decide — OR logic, never stop
    #
    #   icmp=True  OR  wl=True          → WIN: save, notify, continue
    #   icmp=False AND wl=False         → DEAD: delete, add to dead cache
    #   anything else                   → wait for more results
    # ------------------------------------------------------------------

    def _decision_phase(self) -> SubnetTask | None:
        to_remove: list[SubnetTask] = []
        winners: list[SubnetTask] = []

        for task in self._pending_tasks:
            icmp_ok = task.icmp_result is True
            wl_ok = task.wl_result is True
            icmp_done = task.icmp_result is not None
            wl_done = task.wl_result is not None

            # OR: either probe confirms alive → WIN
            if icmp_ok or wl_ok:
                log.info("orch.success",
                         ip=task.fip_ip, cidr=task.cidr, account=task.account,
                         icmp=task.icmp_result, wl=task.wl_result)
                self._log_ip(task.fip_ip, event="kept", subnet=task.cidr,
                             account=task.account,
                             icmp_result=task.icmp_result, wl_result=task.wl_result)
                self.stats["white_found"] += 1
                winners.append(task)
                to_remove.append(task)
                continue

            # Both probes returned — both dead
            if icmp_done and wl_done:
                self._safe_delete(task.client, task.fip_id)
                self._log_ip(task.fip_ip, event="deleted", subnet=task.cidr,
                             reason="icmp_and_wl_dead", account=task.account)
                self.stats["dead"] += 1
                if task.cidr not in self._dead_subnets:
                    self._dead_subnets.add(task.cidr)
                    self._append_dead_subnet(task.cidr)
                to_remove.append(task)
                continue

            # Still waiting for ICMP or WL result

        for t in to_remove:
            try:
                self._pending_tasks.remove(t)
            except ValueError:
                pass

        # Notify and save all winners (no sys.exit — never-stop mode)
        for winner in winners:
            try:
                self.notifier.notify_white_found(
                    ip=winner.fip_ip,
                    subnet=winner.cidr,
                    icmp_alive=254 if winner.icmp_result else 0,
                )
            except Exception:
                pass
            self._save_found_ip(winner)
            log.info("orch.found", ip=winner.fip_ip, cidr=winner.cidr)

        return winners[0] if winners else None

    # ------------------------------------------------------------------

    def _current_stats(self) -> dict:
        account_counts = self._get_account_fips_counts()
        return {
            **self.stats,
            "elapsed": _fmt_elapsed(time.monotonic() - self._start_time),
            "pending": len(self._pending_tasks),
            "account_counts": account_counts,
        }

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        log.info("orch.start",
                 dry_run=self.dry_run, no_icmp=self.no_icmp,
                 accounts=len(self._account_pool.clients),
                 wl_keys=len(self.wl_pool.keys))

        self._cleanup_existing_fips()

        try:
            while self._running:
                self._iteration += 1

                self._create_phase()
                self._verify_phase()
                winner = self._decision_phase()

                if winner:
                    log.info("orch.notify_attempt", type="success")

                elapsed_since_notify = time.monotonic() - self._last_progress_notify
                if elapsed_since_notify >= 600:
                    log.info("orch.progress", **self._current_stats())
                    log.info("orch.notify_attempt", type="progress")
                    try:
                        self.notifier.notify_progress(self._current_stats())
                        self._last_progress_notify = time.monotonic()
                    except Exception:
                        pass

                if not self._pending_tasks and self._account_pool.all_blocked():
                    wait = max(5.0, self._account_pool.next_available_in())
                    sleep_for = min(wait, 120)
                    log.info("orch.rate_limit_sleep", seconds=round(sleep_for, 1))
                    time.sleep(sleep_for)
                    self._account_pool.reset_blocks()
                elif not self._pending_tasks:
                    time.sleep(5)
                else:
                    time.sleep(1)

        except SystemExit:
            raise
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            import traceback as _tb
            log.exception("orch.unhandled")
            try:
                log.info("orch.notify_attempt", type="error")
                self.notifier.notify_error(str(exc), _tb.format_exc())
            except Exception:
                pass
            raise


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="White IP Hunter — orchestrator")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--dry-run", action="store_true",
                        help="Synthesise FIPs from priority_subnets, no Selectel calls")
    parser.add_argument("--no-icmp", action="store_true",
                        help="Use WLChecker as the decision oracle instead of ICMP")
    args = parser.parse_args(argv)

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = Path("data") / f"run_{run_id}.log"
    Path("data").mkdir(exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(str(log_path))],
        force=True,
    )
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
            structlog.stdlib.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
    )

    print(f"Log: {log_path}", flush=True)

    orch = Orchestrator(
        config_path=args.config,
        dry_run=args.dry_run,
        no_icmp=args.no_icmp,
    )
    orch.run()
    return 0


if __name__ == "__main__":
    sys.exit(_main())
