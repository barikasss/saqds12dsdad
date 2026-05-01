import os
import sys

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.selectel_api import SelectelClient

ACCOUNTS = [
    ("Priya", "577991", "Priya", "SELECTEL_PASSWORD_1", "96536fd09a294164aaf5592a79b5356e"),
    ("Alena", "478320", "Alena", "SELECTEL_PASSWORD_2", "15b7b8b8fe9f4b88bd2876cb2aab3565"),
]

for name, acc_id, username, pwd_env, proj_id in ACCOUNTS:
    print(f"\n=== {name} ===")
    print(f"DEBUG: account_id={acc_id} username={username} project_id={proj_id}")
    pwd = os.environ.get(pwd_env, "")
    if not pwd:
        print(f"SKIP: {pwd_env} не задан в .env")
        continue
    try:
        c = SelectelClient(
            account_id=acc_id,
            username=username,
            password=pwd,
            project_id=proj_id,
        )
        token = c._auth()
        print(f"Auth OK: {token[:20]}...")
        fips = c.list_floating_ips()
        print(f"FIPs: {len(fips)} штук")
    except Exception as e:
        print(f"ERROR: {e}")
