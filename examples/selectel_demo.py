import os

from src.selectel_api import SelectelClient

client = SelectelClient(
    api_token=os.environ["SELECTEL_API_TOKEN"],
    region="ru-3",
)

print("External networks:", client.list_external_networks())
print("Floating IPs:", client.list_floating_ips())

# Закомментировано по умолчанию — раскомментируй когда готов потратить IP-трафик
# fip = client.create_floating_ip()
# print("Created:", fip)
# client.delete_floating_ip(fip["id"])
