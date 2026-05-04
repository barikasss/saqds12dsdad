import requests
import os

key = os.environ.get("SELECTEL_API_KEY_1", "NOT SET")
print(f"Key length: {len(key)}")
r = requests.get(
    "https://api.selectel.ru/vpc/resell/v2/floatingips",
    headers={"X-Token": key},
)
print(r.status_code)
print(r.text[:200])
