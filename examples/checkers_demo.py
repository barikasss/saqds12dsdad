from src.checkers.icmp_checker import ICMPChecker
from src.checkers.tcp_checker import TCPChecker

icmp = ICMPChecker(timeout=1.0, concurrency=32)
print("ICMP /29:", icmp.ping_subnet("158.160.210.0/29"))

tcp = TCPChecker(ports=[22, 80, 443], timeout=2.0, concurrency=16)
print("TCP  /29:", tcp.probe_subnet_sync("158.160.210.0/29"))
