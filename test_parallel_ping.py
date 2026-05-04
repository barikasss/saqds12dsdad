#!/usr/bin/env python3
# test_parallel_ping.py — тест параллельного пинга подсетей на Samsung
# Запуск: sudo python test_parallel_ping.py

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.checkers.icmp_checker import ICMPChecker

INTERFACE = "rmnet0"
CONCURRENCY = 16  # пингов на подсеть (было 32)

# Известные белые подсети — должны дать alive > 0
SUBNETS = [
    "5.188.112.0/24",
    "5.188.113.0/24",
    "5.188.114.0/24",
]

checker = ICMPChecker(interface=INTERFACE, concurrency=CONCURRENCY)


def ping_one_subnet(cidr):
    t0 = time.time()
    results = checker.ping_subnet(cidr)
    alive = sum(1 for v in results.values() if v)
    elapsed = time.time() - t0
    return cidr, alive, elapsed


print("=== Последовательный пинг ===")
t_seq = time.time()
for s in SUBNETS:
    cidr, alive, elapsed = ping_one_subnet(s)
    print(f"  {cidr}: alive={alive}/254  время={elapsed:.1f}с")
seq_total = time.time() - t_seq
print(f"  Итого: {seq_total:.1f}с\n")

print("=== Параллельный пинг (3 подсети одновременно) ===")
t_par = time.time()
with ThreadPoolExecutor(max_workers=3) as ex:
    futures = {ex.submit(ping_one_subnet, s): s for s in SUBNETS}
    for fut in as_completed(futures):
        cidr, alive, elapsed = fut.result()
        print(f"  {cidr}: alive={alive}/254  время={elapsed:.1f}с")
par_total = time.time() - t_par
print(f"  Итого: {par_total:.1f}с")
print(f"\nУскорение: {seq_total/par_total:.1f}x")
