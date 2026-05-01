# config.py — load config.yaml merged with .env overrides

from __future__ import annotations

import os
from typing import Any

import yaml
from dotenv import load_dotenv


def load_config(path: str = "config.yaml") -> dict[str, Any]:
    """Load YAML config. Missing file → {}. Also loads .env into os.environ."""
    load_dotenv()
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        cfg = {}

    tg_proxy = os.environ.get("TG_PROXY_URL") or None
    if tg_proxy:
        cfg.setdefault("checkers", {}).setdefault("wlchecker", {})["proxy_url"] = tg_proxy

    selectel_proxy = os.environ.get("SELECTEL_PROXY_URL") or None
    if selectel_proxy:
        cfg.setdefault("selectel", {})["proxy_url"] = selectel_proxy
        for acc in cfg.get("selectel_accounts", []):
            acc.setdefault("proxy_url", selectel_proxy)

    return cfg
