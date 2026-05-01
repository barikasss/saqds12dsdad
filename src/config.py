# config.py — load config.yaml merged with .env overrides

from __future__ import annotations

from typing import Any

import yaml
from dotenv import load_dotenv


def load_config(path: str = "config.yaml") -> dict[str, Any]:
    """Load YAML config. Missing file → {}. Also loads .env into os.environ."""
    load_dotenv()
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
