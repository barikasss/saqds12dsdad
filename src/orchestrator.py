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
from src.subnet_source import SubnetSource, _atomic_write

log = structlog.get_logger(__name__)


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
        self.selectel = SelectelClient(
            # password-method (service user) — preferred
            account_id=os.environ.get(sel.get("account_id_env", "SELECTEL_ACCOUNT_ID"), ""),
            username=os.environ.get(sel.get("username_env", "SELECTEL_USERNAME"), ""),
            password=os.environ.get(sel.get("password_env", "SELECTEL_PASSWORD"), ""),
            project_id=os.environ.get(sel.get("project_id_env", "SELECTEL_PROJECT_ID"), "") or None,
            # legacy token fallback
            api_token=os.environ.get(sel.get("api_token_env", "SELECTEL_API_TOKEN"), ""),
            region=sel.get("region", "ru-3"),
        )

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
        self.notifier = TelegramNotifier(
            bot_token=tg_token or "dummy",
            chat_id=tg_chat or "0",
            enabled=bool(tg_token and tg_chat),
        )

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
        priority = self.source.priority_subnets
        if not priority:
            log.info("orch.phase1_skip", reason="no priority subnets in config")
            return False

        log.info("orch.phase1_start", count=len(priority))
        try:
            batch = self.wl.check_subnets_batch(priority)
        except Exception as exc:
            log.warning("orch.phase1_wl_error", error=str(exc))
            return False

        for cidr, ip_results in batch.items():
            self.stats["checked"] += 1
            # Phase-1: any alive IP is enough (we own these subnets)
            if self.wl.is_subnet_white(ip_results, threshold=0.0):
                ev = {
                    "wl_alive": sum(1 for v in ip_results.values() if v),
                    "wl_total": len(ip_results),
                }
                self.source.mark(cidr, "white", ev)
                self.stats["white_found"] += 1
                log.info("orch.phase1_white", cidr=cidr, alive=ev["wl_alive"])
                self._success_flow(cidr, ev)
                return True  # only reached in dry_run, _success_flow exits otherwise
            else:
                self.source.mark(cidr, "dead", {"wl_alive": 0, "wl_total": len(ip_results)})
                self.stats["dead"] += 1

        log.info("orch.phase1_all_dead")
        return False

    # ------------------------------------------------------------------
    # Phase 2 — Wide search over all known subnets
    # ------------------------------------------------------------------

    def _phase2_wide_search(self) -> bool:
        log.info("orch.phase2_start")

        try:
            count = self.source.refresh_from_ripe()
            log.info("orch.ripe_refreshed", count=count)
        except Exception as exc:
            log.warning("orch.ripe_failed", error=str(exc))

        unchecked = self.source.get_unchecked(shuffle=self.shuffle)
        total = len(unchecked)
        self.stats["total_subnets"] = total
        limit = min(total, self.max_iter)

        for i, cidr in enumerate(unchecked[:limit], 1):
            if not self._running:
                break

            icmp_alive = icmp_total = 0

            if not self.no_icmp:
                try:
                    res = self.icmp.ping_subnet(cidr)
                    icmp_alive = sum(1 for v in res.values() if v)
                    icmp_total = len(res)
                except Exception:
                    pass

                print(
                    f"[phase=2 i={i}/{limit}] subnet={cidr} "
                    f"icmp={icmp_alive}/{icmp_total}",
                    flush=True,
                )

                if icmp_total > 0 and icmp_alive == 0:
                    self.source.mark(cidr, "dead", {"icmp_alive": 0, "icmp_total": icmp_total})
                    self.stats["dead"] += 1
                    self.stats["checked"] += 1
                    continue
            else:
                print(f"[phase=2 i={i}/{limit}] subnet={cidr} wl=submitting...", flush=True)

            try:
                wl_res = self.wl.check_subnet(cidr)
            except Exception as exc:
                log.warning("orch.wl_error", cidr=cidr, error=str(exc))
                continue

            wl_alive = sum(1 for v in wl_res.values() if v)
            wl_total = len(wl_res)
            ev = {
                "icmp_alive": icmp_alive, "icmp_total": icmp_total,
                "wl_alive": wl_alive, "wl_total": wl_total,
            }
            self.stats["checked"] += 1

            if self.wl.is_subnet_white(wl_res, threshold=0.05):
                self.source.mark(cidr, "white", ev)
                self.stats["white_found"] += 1
                self._success_flow(cidr, ev)
                return True
            elif wl_alive > 0:
                self.source.mark(cidr, "ambiguous", ev)
                self.stats["ambiguous"] += 1
            else:
                self.source.mark(cidr, "dead", ev)
                self.stats["dead"] += 1

            if i % 5 == 0:
                self.notifier.notify_progress({**self._current_stats(), "current_subnet": cidr})

        return False

    # ------------------------------------------------------------------
    # Success flow
    # ------------------------------------------------------------------

    def _success_flow(self, target_cidr: str, evidence: dict) -> None:
        log.info("orch.success_flow", cidr=target_cidr, dry_run=self.dry_run)
        self.notifier.notify_progress({**self._current_stats(), "current_subnet": target_cidr})

        if self.dry_run:
            log.info("orch.dry_run_reroll_skipped", cidr=target_cidr)
            sys.exit(0)

        fip = self.selectel.reroll_until_in_subnet(
            target_cidr, max_attempts=self.reroll_attempts
        )

        if fip:
            ip = fip.get("floating_ip_address", "")
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
        else:
            self.notifier.notify_warning(
                f"Подсеть {target_cidr} белая, но floating IP не выпал "
                f"за {self.reroll_attempts} попыток",
                context={"cidr": target_cidr, "attempts": self.reroll_attempts},
            )
            log.warning(
                "orch.reroll_exhausted",
                cidr=target_cidr,
                hint="Создай IP вручную в ЛК Selectel или увеличь reroll_attempts_in_subnet в config",
            )
            sys.exit(1)

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
    args = parser.parse_args()

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
