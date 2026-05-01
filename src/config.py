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

    proxy_url = os.environ.get("TG_PROXY_URL") or None
    if proxy_url:
        cfg.setdefault("checkers", {}).setdefault("wlchecker", {})["proxy_url"] = proxy_url

    return cfg
