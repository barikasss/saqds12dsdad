import os

from src.checkers.wl_api import WLCheckerClient

client = WLCheckerClient(
    base_url="http://150.241.74.147:8082",
    api_key=os.environ["WLCHECKER_API_KEY"],
)
result = client.check_subnet("158.160.210.0/29")
print(result)
# Expected: .3, .4, .5 — True (UP);  .1, .2, .6 — False (DOWN)
