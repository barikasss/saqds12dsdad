# subnet_filter.py — two-level O(1) whitelist index for IP lookups

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)


class SubnetFilter:
    """Fast O(1) check whether an IP belongs to any known white subnet.

    Two-level index:
      _exact  — set of /24 network strings, e.g. {"87.228.90.0/24"}
      _wide   — list of IPv4Network for prefixes shorter than /24 (rare)

    For 99% of real-world cases (all-/24 whitelist), every lookup is O(1).
    """

    def __init__(self, white_cidrs: list[str]) -> None:
        self._exact: set[str] = set()
        self._wide: list[ipaddress.IPv4Network] = []
        self._build_index(white_cidrs)

    def _build_index(self, cidrs: list[str]) -> None:
        for cidr in cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if net.prefixlen > 24:
                # Collapse to parent /24
                parent = self._parent_24(net.network_address)
                self._exact.add(str(parent))
            elif net.prefixlen == 24:
                self._exact.add(str(net))
            else:
                # Wider than /24 — keep in linear list (usually very few)
                self._wide.append(net)

    @staticmethod
    def _parent_24(addr: ipaddress.IPv4Address) -> ipaddress.IPv4Network:
        masked = ipaddress.IPv4Address(int(addr) & 0xFFFFFF00)
        return ipaddress.IPv4Network(f"{masked}/24")

    def is_ip_in_whitelist(self, ip: str) -> bool:
        """Return True if *ip* falls in any indexed subnet."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        # 1. O(1) — derive parent /24 and check exact set
        subnet_24 = str(self._parent_24(ipaddress.IPv4Address(int(addr))))
        if subnet_24 in self._exact:
            return True

        # 2. O(len(_wide)) — usually 0 or a handful
        for net in self._wide:
            if addr in net:
                return True

        return False

    @classmethod
    def from_state(
        cls, state_file: str = "data/checked_state.json"
    ) -> "SubnetFilter":
        """Build filter from subnets marked 'white' in the state file."""
        try:
            state: dict = json.loads(Path(state_file).read_text())
            white = [c for c, e in state.items() if e.get("status") == "white"]
        except (FileNotFoundError, json.JSONDecodeError):
            white = []
        log.info("subnet_filter.loaded", white_count=len(white))
        return cls(white)


# ---------------------------------------------------------------------------
# CLI: python -m src.subnet_filter --check <IP>
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SubnetFilter CLI")
    parser.add_argument("--check", metavar="IP", help="Check if IP is in whitelist")
    parser.add_argument(
        "--state", default="data/checked_state.json", metavar="FILE"
    )
    args = parser.parse_args()

    if args.check:
        sf = SubnetFilter.from_state(args.state)
        if sf.is_ip_in_whitelist(args.check):
            print(f"✅ {args.check} — В белом списке")
        else:
            print(f"❌ {args.check} — Не в белом списке")
    else:
        parser.print_help()
