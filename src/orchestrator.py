# orchestrator.py — main search loop coordinating checkers, source, and notifier

from __future__ import annotations

import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import structlog

from src.checkers.icmp_checker import ICMPChecker
from src.checkers.tcp_checker import TCPChecker
from src.checkers.wl_api import WLCheckerClient
from src.config import load_config
from src.notifier import TelegramNotifier
from src.selectel_api import SelectelClient
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
    # Phase 1 — Quick Win on priority subnets
    # ------------------------------------------------------------------

    def _phase1_quick_win(self) -> bool:
        import ipaddress as _ip

        priority = self.source.priority_subnets
        if not priority:
            log.info("orch.phase1_skip", reason="no priority subnets in config")
            return False

        log.info("orch.phase1_start", count=len(priority))
        sf = SubnetFilter(priority)

        for cidr in priority:
            try:
                net_addr = str(_ip.ip_network(cidr, strict=False).network_address)
            except Exception:
                continue

            # Step 2: SubnetFilter check — no WLChecker
            if not sf.is_ip_in_whitelist(net_addr):
                self.stats["dead"] += 1
                continue

            self.stats["checked"] += 1
            log.info("orch.phase1_subnet_white", cidr=cidr)

            if self.dry_run:
                log.info("orch.dry_run_fip_skipped", cidr=cidr)
                sys.exit(0)

            # Step 3a: create floating IP
            try:
                fip = self.selectel.create_floating_ip_safe(availability_zone=self._zone)
            except Exception as exc:
                log.warning("orch.phase1_fip_error", cidr=cidr, error=str(exc))
                continue

            ip = fip.get("floating_ip_address", "")

            # Step 3b: check if FIP landed in white subnet
            if sf.is_ip_in_whitelist(ip):
                # Step 3c: WLChecker final confirmation
                try:
                    wl_res = self.wl.check_subnet(cidr)
                    if self.wl.is_subnet_white(wl_res, threshold=0.0):
                        ev = {
                            "wl_alive": sum(1 for v in wl_res.values() if v),
                            "wl_total": len(wl_res),
                        }
                        self.source.mark(cidr, "white", ev)
                        self.stats["white_found"] += 1
                        log.info("orch.phase1_white", cidr=cidr, ip=ip)
                        self._success_flow(ip, cidr, fip, ev)
                        return True
                except Exception as exc:
                    log.warning("orch.phase1_wl_error", cidr=cidr, error=str(exc))

            # Step 4: FIP not in white subnet or WLChecker failed — delete
            try:
                self.selectel.delete_floating_ip(fip["id"])
            except Exception:
                pass
            self.stats["dead"] += 1

        log.info("orch.phase1_all_failed")
        return False

    # ------------------------------------------------------------------
    # Phase 2 — Wide search over all known subnets
    # ------------------------------------------------------------------

    def _phase2_wide_search(self) -> bool:
        import ipaddress as _ip

        log.info("orch.phase2_start")

        try:
            count = self.source.refresh_from_ripe()
            log.info("orch.ripe_refreshed", count=count)
        except Exception as exc:
            log.warning("orch.ripe_failed", error=str(exc))

        # SubnetFilter from known white subnets + priority list
        white_cidrs = list(set(
            (self.source.get_white_subnets() or []) + (self.source.priority_subnets or [])
        ))
        sf = SubnetFilter(white_cidrs)

        unchecked = self.source.get_unchecked(shuffle=self.shuffle)
        total = len(unchecked)
        self.stats["total_subnets"] = total
        limit = min(total, self.max_iter)

        for i, cidr in enumerate(unchecked[:limit], 1):
            if not self._running:
                break

            # Step 2: SubnetFilter check — no WLChecker
            try:
                net_addr = str(_ip.ip_network(cidr, strict=False).network_address)
            except Exception:
                continue

            if not sf.is_ip_in_whitelist(net_addr):
                print(f"[phase=2 i={i}/{limit}] subnet={cidr} filter=skip", flush=True)
                self.source.mark(cidr, "dead", {"reason": "not_in_whitelist"})
                self.stats["dead"] += 1
                self.stats["checked"] += 1
                continue

            print(f"[phase=2 i={i}/{limit}] subnet={cidr} filter=white → FIP...", flush=True)
            self.stats["checked"] += 1

            if self.dry_run:
                log.info("orch.dry_run_fip_skipped", cidr=cidr)
                self.stats["white_found"] += 1
                sys.exit(0)

            # Step 3a: create floating IP
            try:
                fip = self.selectel.create_floating_ip_safe(availability_zone=self._zone)
            except Exception as exc:
                log.warning("orch.phase2_fip_error", cidr=cidr, error=str(exc))
                continue

            ip = fip.get("floating_ip_address", "")

            # Step 3b: check if FIP landed in white subnet
            if sf.is_ip_in_whitelist(ip):
                # Step 3c: WLChecker final confirmation
                try:
                    wl_res = self.wl.check_subnet(cidr)
                    wl_alive = sum(1 for v in wl_res.values() if v)
                    ev = {"wl_alive": wl_alive, "wl_total": len(wl_res)}

                    if self.wl.is_subnet_white(wl_res, threshold=0.05):
                        self.source.mark(cidr, "white", ev)
                        self.stats["white_found"] += 1
                        self._success_flow(ip, cidr, fip, ev)
                        return True
                except Exception as exc:
                    log.warning("orch.phase2_wl_error", cidr=cidr, error=str(exc))

                self.source.mark(cidr, "dead", {"reason": "wl_not_confirmed"})
                self.stats["dead"] += 1
            else:
                self.source.mark(cidr, "dead", {"reason": "fip_not_in_whitelist"})
                self.stats["dead"] += 1

            # Step 4: delete FIP
            try:
                self.selectel.delete_floating_ip(fip["id"])
            except Exception as exc:
                log.warning("orch.fip_delete_error", fip_id=fip.get("id"), error=str(exc))

            if i % 5 == 0:
                self.notifier.notify_progress({**self._current_stats(), "current_subnet": cidr})

        return False

    # ------------------------------------------------------------------
    # IP logging and batch reroll
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

    def _success_flow(self, ip: str, target_cidr: str, fip: dict, evidence: dict) -> None:
        log.info("orch.success_flow", ip=ip, cidr=target_cidr)
        evidence["floating_ip_id"] = fip.get("id", "")
        self.notifier.notify_success(
            ip=ip,
            subnet=target_cidr,
            evidence=evidence,
            stats=self._current_stats(),
        )
        self._save_found_ip(ip, target_cidr, fip, evidence)
        log.info("orch.ip_found", ip=ip, cidr=target_cidr)
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
        log.info(
            "orch.start",
            phase=self.phase,
            dry_run=self.dry_run,
            resume=self.resume,
            no_icmp=self.no_icmp,
        )
        try:
            if self.phase in ("1", "both"):
                if self._phase1_quick_win():
                    return

            if self.phase in ("2", "both"):
                self._phase2_wide_search()

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
