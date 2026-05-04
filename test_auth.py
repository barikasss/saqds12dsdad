import os
import yaml
import requests
from src.proxy_pool import ResellProxyPool
from src.selectel_api import SelectelClient

with open("config.yaml") as f:
    cfg = yaml.safe_load(f)

for a in cfg.get("selectel_accounts", []):
    env_name = a.get("api_key_env", "")
    key = os.environ.get(env_name, "")
    print(f"account={a.get('account_id')} api_key_env={env_name} key_len={len(key)}")

    client = SelectelClient(
        account_id=a.get("account_id", ""),
        username=a.get("username", ""),
        api_key=key,
        project_id=a.get("project_id", ""),
        region=a.get("availability_zone", "ru-2"),
        proxy_pool=ResellProxyPool([]),
    )
    try:
        fips = client.list_floating_ips()
        print(f"  OK — {len(fips)} FIPs")
    except Exception as e:
        print(f"  ERROR — {e}")
