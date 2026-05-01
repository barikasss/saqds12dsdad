# subnet_source.py — subnet pool management: priority → RIPE cache → seed fallback

from __future__ import annotations

import json
import os
import random
import tempfile
from datetime import datetime, timezone
from typing import Iterable

import requests
import structlog

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Module-level helpers (exported so tests can import them directly)
# ---------------------------------------------------------------------------

def _to_24s(prefix: str) -> list[str]:
    """Normalise a prefix to a list of /24 networks.

    - prefix > /24 (e.g. /25, /32): ignored (too specific).
    - prefix == /24: returned as-is.
    - prefix < /24 (e.g. /22): split into constituent /24s.
    Returns [] on invalid input.
    """
    import ipaddress
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return []
    if net.prefixlen > 24:
        return []
    if net.prefixlen == 24:
        return [str(net)]
    return [str(sn) for sn in net.subnets(new_prefix=24)]


def _atomic_write(path: str, data: dict) -> None:
    """Write *data* to *path* atomically via a sibling tmp file + os.replace.

    If interrupted between the tmp write and the rename, the original file is
    preserved and the tmp file is cleaned up.
    """
    dir_ = os.path.dirname(os.path.abspath(path))
    os.makedirs(dir_, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dir_, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# SubnetSource
# ---------------------------------------------------------------------------

class SubnetSource:
    _RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"

    def __init__(
        self,
        priority_subnets: list[str] | None = None,
        seed_file: str = "data/selectel_subnets_seed.txt",
        cache_file: str = "data/subnets_cache.json",
        state_file: str = "data/checked_state.json",
        cache_ttl_hours: int = 24,
    ) -> None:
        self.priority_subnets: list[str] = list(priority_subnets or [])
        self.seed_file = seed_file
        self.cache_file = cache_file
        self.state_file = state_file
        self.cache_ttl_hours = cache_ttl_hours

    # ------------------------------------------------------------------
    # Private I/O helpers
    # ------------------------------------------------------------------

    def _load_cache(self) -> dict | None:
        try:
            with open(self.cache_file) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def _is_cache_fresh(self, cache: dict) -> bool:
        try:
            fetched_at = datetime.fromisoformat(cache["fetched_at"])
            if fetched_at.tzinfo is None:
                fetched_at = fetched_at.replace(tzinfo=timezone.utc)
            age_h = (datetime.now(timezone.utc) - fetched_at).total_seconds() / 3600
            return age_h < self.cache_ttl_hours
        except (KeyError, ValueError):
            return False

    def _load_seed(self) -> list[str]:
        result: list[str] = []
        try:
            with open(self.seed_file) as f:
                for raw in f:
                    line = raw.strip()
                    if line and not line.startswith("#"):
                        result.append(line)
        except FileNotFoundError:
            log.warning("subnet_source.seed_not_found", path=self.seed_file)
        return result

    def _load_state(self) -> dict:
        try:
            with open(self.state_file) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_state(self, state: dict) -> None:
        _atomic_write(self.state_file, state)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def refresh_from_ripe(self, asn: int = 49505) -> int:
        """Fetch announced prefixes for *asn* from RIPE Stat, normalise to /24, cache.

        Returns the number of unique /24 subnets stored.
        Raises on HTTP or network errors (caller decides on fallback).
        """
        resp = requests.get(
            self._RIPE_URL,
            params={"resource": f"AS{asn}"},
            timeout=30,
        )
        resp.raise_for_status()

        prefixes = resp.json()["data"]["prefixes"]
        seen: set[str] = set()
        unique: list[str] = []
        for item in prefixes:
            for n in _to_24s(item.get("prefix", "")):
                if n not in seen:
                    seen.add(n)
                    unique.append(n)

        cache_data = {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "asn": asn,
            "subnets_24": unique,
        }
        _atomic_write(self.cache_file, cache_data)
        log.info("subnet_source.ripe_refreshed", asn=asn, count=len(unique))
        return len(unique)

    def get_all_subnets(self) -> list[str]:
        """Return deduplicated list of /24 subnets in priority order.

        Order: priority_subnets first, then RIPE cache (or freshly fetched, or seed).
        """
        seen: set[str] = set()
        result: list[str] = []

        def add(prefixes: Iterable[str]) -> None:
            for p in prefixes:
                for n in _to_24s(p):
                    if n not in seen:
                        seen.add(n)
                        result.append(n)

        # 1. Priority subnets
        add(self.priority_subnets)

        # 2. Cache OR refresh OR seed (exclusive fallback chain)
        cache = self._load_cache()
        if cache and self._is_cache_fresh(cache):
            add(cache.get("subnets_24", []))
        else:
            try:
                self.refresh_from_ripe()
                cache = self._load_cache()
                if cache:
                    add(cache.get("subnets_24", []))
            except Exception as exc:
                log.warning("subnet_source.ripe_failed", error=str(exc))
                add(self._load_seed())

        return result

    def get_unchecked(self, shuffle: bool = False) -> list[str]:
        """Subnets not yet marked 'white' or 'dead'.

        Priority subnets always first; the rest optionally shuffled.
        """
        state = self._load_state()
        all_subnets = self.get_all_subnets()

        priority_set: set[str] = set()
        for p in self.priority_subnets:
            for n in _to_24s(p):
                priority_set.add(n)

        priority_q: list[str] = []
        rest_q: list[str] = []

        for s in all_subnets:
            entry = state.get(s)
            if entry and entry.get("status") in ("white", "dead"):
                continue
            (priority_q if s in priority_set else rest_q).append(s)

        if shuffle:
            random.shuffle(rest_q)

        return priority_q + rest_q

    def mark(
        self,
        cidr: str,
        status: str,
        evidence: dict | None = None,
    ) -> None:
        """Record *status* for *cidr*. Persisted atomically to state_file."""
        import ipaddress
        key = str(ipaddress.ip_network(cidr, strict=False))
        state = self._load_state()
        state[key] = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "evidence": evidence or {},
        }
        self._save_state(state)

    def get_state(self, cidr: str) -> dict | None:
        import ipaddress
        key = str(ipaddress.ip_network(cidr, strict=False))
        return self._load_state().get(key)

    def get_white_subnets(self) -> list[str]:
        """Return CIDRs whose state is 'white'."""
        state = self._load_state()
        return [cidr for cidr, entry in state.items() if entry.get("status") == "white"]

    def stats(self) -> dict:
        """{total_known, checked, white, dead, ambiguous, unchecked}"""
        all_subnets = self.get_all_subnets()
        state = self._load_state()

        white = dead = ambiguous = 0
        for s in all_subnets:
            st = state.get(s, {}).get("status")
            if st == "white":
                white += 1
            elif st == "dead":
                dead += 1
            elif st == "ambiguous":
                ambiguous += 1

        checked = white + dead + ambiguous
        return {
            "total_known": len(all_subnets),
            "checked": checked,
            "white": white,
            "dead": dead,
            "ambiguous": ambiguous,
            "unchecked": len(all_subnets) - checked,
        }


# ---------------------------------------------------------------------------
# CLI entry point: python -m src.subnet_source --refresh | --stats
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SubnetSource CLI")
    parser.add_argument("--refresh", action="store_true", help="Fetch subnets from RIPE AS49505")
    parser.add_argument("--stats",   action="store_true", help="Print current pool stats")
    args = parser.parse_args()

    priority: list[str] = []
    try:
        import yaml
        with open("config.yaml") as _f:
            _cfg = yaml.safe_load(_f) or {}
        priority = _cfg.get("search", {}).get("priority_subnets", [])
    except FileNotFoundError:
        pass

    source = SubnetSource(priority_subnets=priority)

    if args.refresh:
        count = source.refresh_from_ripe()
        print(f"Refreshed: {count} /24 subnets from RIPE AS49505")

    if args.stats:
        s = source.stats()
        print("Subnet pool stats:")
        for k, v in s.items():
            print(f"  {k:>15}: {v}")

    if not args.refresh and not args.stats:
        parser.print_help()
