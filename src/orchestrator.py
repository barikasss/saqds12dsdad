# orchestrator.py — main search loop coordinating checkers, source, and notifier

from __future__ import annotations

import json
import os
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import structlog

from src.checkers.icmp_checker import ICMPChecker
from src.checkers.tcp_checker import TCPChecker
from src.checkers.wl_api import WLCheckerClient
from src.config import load_config
from src.notifier import TelegramNotifier
from src.selectel_api import SelectelClient, SelectelRateLimitError
from src.subnet_filter import SubnetFilter
from src.subnet_source import SubnetSource, _atomic_write

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# AccountPool — round-robin over multiple Selectel accounts
# ---------------------------------------------------------------------------

class AccountPool:
    """Round-robin scheduler for SelectelClient instances.

    Tracks per-account rate-limit windows and skips blocked accounts.
    """

    def __init__(self, clients: list[SelectelClient]) -> None:
        if not clients:
            raise ValueError("AccountPool requires at least one client")
        self._clients = clients
        self._blocked_until: dict[int, datetime] = {}
        self._idx = 0

    def next(self) -> SelectelClient:
        """Return the next non-blocked client in round-robin order."""
        now = datetime.now(timezone.utc)
        for i in range(len(self._clients)):
            idx = (self._idx + i) % len(self._clients)
            client = self._clients[idx]
            cid = id(client)
            if cid not in self._blocked_until or self._blocked_until[cid] <= now:
                self._idx = (idx + 1) % len(self._clients)
                return client
        raise RuntimeError("All accounts are rate limited — call all_blocked() first")

    def mark_rate_limited(
        self, client: SelectelClient, until: datetime
    ) -> None:
        self._blocked_until[id(client)] = until
        log.info(
            "pool.account_rate_limited",
            account=client.username,
            until=until.isoformat(),
        )

    def all_blocked(self) -> bool:
        now = datetime.now(timezone.utc)
        return all(
            id(c) in self._blocked_until and self._blocked_until[id(c)] > now
            for c in self._clients
        )

    def reset_blocks(self) -> None:
        self._blocked_until.clear()
        log.info("pool.blocks_reset")


def _fmt_elapsed(seconds: float) -> str:
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# ---------------------------------------------------------------------------

class Orchestrator:
    def __init__(
        self,
        config_path: str = "config.yaml",
        dry_run: bool = False,
        resume: bool = False,
        phase: str = "both",
        no_icmp: bool = False,
    ) -> None:
        self.dry_run = dry_run
        self.resume = resume
        self.phase = phase
        self.no_icmp = no_icmp
        self._running = True
        self._start_time = time.monotonic()

        self.stats: dict = {
            "total_subnets": 0,
            "checked": 0,
            "white_found": 0,
            "dead": 0,
            "ambiguous": 0,
            "start_time": datetime.now(timezone.utc).isoformat(),
        }

        self.cfg = load_config(config_path)
        self._init_components()

        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init_components(self) -> None:
        cfg = self.cfg

        sel = cfg.get("selectel", {})
        self._zone: str = sel.get("availability_zone", sel.get("region", "ru-2"))

        # Build client list from selectel_accounts[] or fall back to single account
        accounts_cfg: list[dict] = cfg.get("selectel_accounts", [])
        enabled_accounts = [a for a in accounts_cfg if a.get("enabled", True)]

        if enabled_accounts:
            clients: list[SelectelClient] = []
            for acc in enabled_accounts:
                clients.append(SelectelClient(
                    account_id=acc.get("account_id", ""),
                    username=acc.get("username", ""),
                    password=os.environ.get(acc.get("password_env", ""), ""),
                    project_id=acc.get("project_id") or None,
                    region=acc.get("availability_zone", self._zone),
                ))
        else:
            # Legacy single-account config
            clients = [SelectelClient(
                account_id=os.environ.get(sel.get("account_id_env", "SELECTEL_ACCOUNT_ID"), ""),
                username=os.environ.get(sel.get("username_env", "SELECTEL_USERNAME"), ""),
                password=os.environ.get(sel.get("password_env", "SELECTEL_PASSWORD"), ""),
                project_id=os.environ.get(
                    sel.get("project_id_env", "SELECTEL_PROJECT_ID"), ""
                ) or None,
                api_token=os.environ.get(
                    sel.get("api_token_env", "SELECTEL_API_TOKEN"), ""
                ),
                region=self._zone,
            )]

        self._account_pool = AccountPool(clients)
        self.selectel = clients[0]  # backward-compat reference

        c = cfg.get("checkers", {})

        ic = c.get("icmp", {})
        self.icmp = ICMPChecker(
            timeout=ic.get("timeout", 1.0),
            concurrency=ic.get("concurrency", 32),
        )

        tc = c.get("tcp", {})
        self.tcp = TCPChecker(
            ports=tc.get("ports", [22, 80, 443]),
            timeout=tc.get("timeout", 2.0),
            concurrency=tc.get("concurrency", 16),
        )

        wc = c.get("wlchecker", {})
        self.wl = WLCheckerClient(
            base_url=wc.get("base_url", "http://150.241.74.147:8082"),
            api_key=os.environ.get(wc.get("api_key_env", "WLCHECKER_API_KEY"), ""),
            submit_cooldown=wc.get("submit_cooldown_seconds", 300),
            poll_interval=wc.get("poll_interval_seconds", 5),
            poll_timeout=wc.get("poll_timeout_seconds", 600),
            proxy_url=wc.get("proxy_url"),
        )

        sr = cfg.get("search", {})
        self.max_iter: int = sr.get("max_iterations", 1000)
        self.shuffle: bool = sr.get("shuffle_after_priority", True)
        self.reroll_attempts: int = sr.get("reroll_attempts_in_subnet", 15)

        self.source = SubnetSource(
            priority_subnets=sr.get("priority_subnets", []),
        )

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

        self.ip_log_file: str = "data/ip_log.jsonl"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _current_stats(self) -> dict:
        return {**self.stats, "elapsed": _fmt_elapsed(time.monotonic() - self._start_time)}

    def _handle_shutdown(self, signum, frame) -> None:
        log.warning("orch.shutdown_signal", signal=int(signum))
        self._running = False
        try:
            self.notifier.notify_warning(
                "Остановлено пользователем",
                context={"signal": int(signum)},
            )
        except Exception:
            pass
        sys.exit(130)

    # ------------------------------------------------------------------
    # Check existing floating IPs before starting the main loop
    # ------------------------------------------------------------------

    def _check_existing_fips(self, sf: SubnetFilter) -> None:
        import ipaddress as _ip

        log.info("orch.check_existing_fips")
        for client in self._account_pool._clients:
            try:
                fips = client.list_floating_ips()
            except Exception as exc:
                log.warning("orch.list_fips_error", account=client.username, error=str(exc))
                continue

            for fip in fips:
                ip = fip.get("floating_ip_address", "")
                if not ip:
                    continue

                try:
                    subnet = str(_ip.ip_network(f"{ip}/24", strict=False))
                except Exception:
                    subnet = ""

                account_name = client.username or "?"
                log.info("orch.existing_fip", ip=ip, account=account_name)

                if sf.is_ip_in_whitelist(ip):
                    self._log_ip(ip, subnet, True, "existing_candidate", account_name, self._zone)
                    self.notifier.notify_progress({
                        **self._current_stats(),
                        "message": f"Существующий IP {ip} в белом списке, проверяю...",
                    })
                    try:
                        wl_res = self.wl.check_subnet(f"{ip}/32")
                        if wl_res.get(ip):
                            ev = {"source": "existing_fip", "wl_confirmed": True}
                            self._success_flow(ip, fip, ev)
                        else:
                            self._log_ip(ip, subnet, True, "deleted_wl_rejected", account_name, self._zone)
                            client.delete_floating_ip(fip["id"])
                    except Exception as exc:
                        log.warning("orch.existing_fip_wl_error", ip=ip, error=str(exc))
                else:
                    self._log_ip(ip, subnet, False, "deleted_not_in_whitelist", account_name, self._zone)
                    try:
                        client.delete_floating_ip(fip["id"])
                    except Exception as exc:
                        log.warning("orch.existing_fip_delete_error", ip=ip, error=str(exc))

    # ------------------------------------------------------------------
    # Main reroll loop
    # ------------------------------------------------------------------

    def _reroll_loop(self, sf: SubnetFilter) -> None:
        import ipaddress as _ip

        log.info("orch.reroll_loop_start")
        attempts = 0

        while self._running:
            if self._account_pool.all_blocked():
                log.info("orch.all_accounts_blocked_sleeping", seconds=120)
                time.sleep(120)
                self._account_pool.reset_blocks()

            client = self._account_pool.next()
            attempts += 1

            if self.dry_run:
                log.info("orch.dry_run_reroll_skipped", attempt=attempts)
                sys.exit(0)

            try:
                fip = client.create_floating_ip_safe(availability_zone=client._region)
            except SelectelRateLimitError:
                self._account_pool.mark_rate_limited(
                    client,
                    datetime.now(timezone.utc) + timedelta(seconds=120),
                )
                continue
            except Exception as exc:
                log.warning("orch.fip_create_error", account=client.username, error=str(exc))
                time.sleep(5)
                continue

            ip = fip.get("floating_ip_address", "")
            account_name = client.username or "?"
            self.stats["checked"] += 1

            try:
                subnet = str(_ip.ip_network(f"{ip}/24", strict=False))
            except Exception:
                subnet = ""

            log.info("orch.fip_received", ip=ip, attempt=attempts, account=account_name)

            if sf.is_ip_in_whitelist(ip):
                self._log_ip(ip, subnet, True, "candidate", account_name, self._zone)
                self.notifier.notify_progress({
                    **self._current_stats(),
                    "message": f"Кандидат {ip}, проверяю через WLChecker...",
                })
                log.info("orch.fip_candidate", ip=ip, attempt=attempts)

                try:
                    wl_res = self.wl.check_subnet(f"{ip}/32")
                    if wl_res.get(ip):
                        self.stats["white_found"] += 1
                        self._log_ip(ip, subnet, True, "kept", account_name, self._zone)
                        ev = {"wl_confirmed": True, "attempts": attempts}
                        self._success_flow(ip, fip, ev)
                        return
                    else:
                        log.info("orch.fip_wl_rejected", ip=ip)
                        self._log_ip(ip, subnet, True, "deleted_wl_rejected", account_name, self._zone)
                        self.stats["dead"] += 1
                except Exception as exc:
                    log.warning("orch.wl_error", ip=ip, error=str(exc))
                    self.stats["dead"] += 1

                try:
                    client.delete_floating_ip(fip["id"])
                except Exception as exc:
                    log.warning("orch.fip_delete_error", fip_id=fip.get("id"), error=str(exc))
            else:
                self._log_ip(ip, subnet, False, "deleted_not_in_whitelist", account_name, self._zone)
                self.stats["dead"] += 1
                try:
                    client.delete_floating_ip(fip["id"])
                except Exception as exc:
                    log.warning("orch.fip_delete_error", fip_id=fip.get("id"), error=str(exc))

            if attempts % 10 == 0:
                self.notifier.notify_progress(self._current_stats())

    # ------------------------------------------------------------------
    # IP logging
    # ------------------------------------------------------------------

    def _log_ip(
        self,
        ip: str,
        subnet: str,
        in_whitelist: bool,
        action: str,
        account: str,
        zone: str,
    ) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "ip": ip,
            "subnet": subnet,
            "in_whitelist": in_whitelist,
            "action": action,
            "account": account,
            "zone": zone,
        }
        path = Path(self.ip_log_file)
        try:
            path.parent.mkdir(exist_ok=True)
            with open(path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as exc:
            log.warning("orch.ip_log_error", error=str(exc))

    # ------------------------------------------------------------------
    # Success flow
    # ------------------------------------------------------------------

    def _success_flow(self, ip: str, fip: dict, evidence: dict) -> None:
        import ipaddress as _ip
        try:
            cidr = str(_ip.ip_network(f"{ip}/24", strict=False))
        except Exception:
            cidr = ip
        log.info("orch.success_flow", ip=ip, cidr=cidr)
        evidence["floating_ip_id"] = fip.get("id", "")
        self.notifier.notify_success(
            ip=ip,
            subnet=cidr,
            evidence=evidence,
            stats=self._current_stats(),
        )
        self._save_found_ip(ip, cidr, fip, evidence)
        log.info("orch.ip_found", ip=ip, cidr=cidr)
        sys.exit(0)

    def _save_found_ip(
        self, ip: str, cidr: str, fip: dict, evidence: dict
    ) -> None:
        path = Path("data") / "found_ips.json"
        try:
            path.parent.mkdir(exist_ok=True)
            try:
                existing: list = json.loads(path.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                existing = []
            existing.append({
                "ip": ip,
                "cidr": cidr,
                "fip_id": fip.get("id"),
                "found_at": datetime.now(timezone.utc).isoformat(),
                "evidence": evidence,
            })
            _atomic_write(str(path), existing)
        except Exception as exc:
            log.warning("orch.save_found_ip_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        log.info("orch.start", dry_run=self.dry_run, resume=self.resume)
        sf = SubnetFilter(self.source.priority_subnets)
        try:
            self._check_existing_fips(sf)
            self._reroll_loop(sf)
            log.info("orch.done", stats=self._current_stats())
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception as exc:
            import traceback as _tb
            tb_str = _tb.format_exc()
            log.exception("orch.unhandled_error")
            try:
                self.notifier.notify_error(str(exc), tb_str)
            except Exception:
                pass
            raise


# ---------------------------------------------------------------------------
# CLI: python -m src.orchestrator [options]
# ---------------------------------------------------------------------------

def _show_ip_log(log_file: str = "data/ip_log.jsonl") -> None:
    path = Path(log_file)
    if not path.exists():
        print("No IP log yet.")
        return
    for raw in path.read_text().splitlines():
        try:
            e = json.loads(raw)
        except json.JSONDecodeError:
            continue
        ts = e.get("ts", "")[:16].replace("T", " ")
        ip = e.get("ip", "?").ljust(15)
        subnet = e.get("subnet", "")
        status = "✅ БЕЛЫЙ  " if e.get("in_whitelist") else "❌ удалён"
        acc = e.get("account", "?")
        print(f"[{ts}] {ip}  subnet={subnet}  {status}  ({acc})")


def _show_accounts(cfg: dict) -> None:
    from src.config import load_config
    print("Selectel accounts:")
    accounts = cfg.get("selectel_accounts", [])
    if not accounts:
        sel = cfg.get("selectel", {})
        import os
        uname = os.environ.get(sel.get("username_env", "SELECTEL_USERNAME"), "<not set>")
        zone = sel.get("availability_zone", sel.get("region", "ru-2"))
        print(f"  {uname:30s} zone={zone}  ✅ enabled (single-account mode)")
        return
    for acc in accounts:
        uname = acc.get("username", "?")
        zone = acc.get("availability_zone", "?")
        enabled = acc.get("enabled", True)
        status = "✅ enabled" if enabled else "❌ disabled"
        print(f"  {uname:30s} zone={zone}  {status}")


if __name__ == "__main__":
    import argparse
    import logging

    parser = argparse.ArgumentParser(
        description="White IP Hunter — main search orchestrator"
    )
    parser.add_argument("--config", default="config.yaml", metavar="PATH")
    parser.add_argument("--dry-run", action="store_true",
                        help="No Selectel create/delete calls")
    parser.add_argument("--resume", action="store_true",
                        help="Continue from existing checked state")
    parser.add_argument("--phase", choices=["1", "2", "both"], default="both")
    parser.add_argument("--no-icmp", action="store_true",
                        help="Skip local ICMP pre-screening")
    parser.add_argument("--zone", metavar="ZONE",
                        help="Override availability zone (e.g. ru-2)")
    parser.add_argument("--show-log", action="store_true",
                        help="Print data/ip_log.jsonl and exit")
    parser.add_argument("--accounts", action="store_true",
                        help="Show configured Selectel accounts and exit")
    args = parser.parse_args()

    # Info-only commands (no orchestrator needed)
    if args.show_log:
        _show_ip_log()
        sys.exit(0)

    if args.accounts:
        from src.config import load_config as _lc
        _show_accounts(_lc(args.config))
        sys.exit(0)

    # Log file: data/run_YYYYMMDD_HHMMSS.log
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
        resume=args.resume,
        phase=args.phase,
        no_icmp=args.no_icmp,
    )
    orch.run()
