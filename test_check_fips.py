import requests
import os

key = os.environ["SELECTEL_API_KEY_1"]
r = requests.get("https://api.selectel.ru/vpc/resell/v2/floatingips", headers={"X-Token": key})
fips = r.json().get("floatingips", [])
targets = {"ff401bf1-a186-4be3-bb62-99c0f0044f77", "fffc03cd-a507-4b40-899d-11d47924d112"}
found = [f for f in fips if f["id"] in targets]
print(f"Total FIPs for Priya: {len(fips)}")
print(f"Zombie FIPs found: {len(found)}")
for f in found:
    print(f"  {f['id']} {f['floating_ip_address']} status={f.get('status')}")
if not found:
    print("  Zombie FIPs NOT in list — they were already deleted!")
