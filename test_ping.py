from src.checkers.icmp_checker import ICMPChecker
r = ICMPChecker(interface='rmnet0').ping_subnet('5.188.112.0/24')
alive = sum(1 for v in r.values() if v)
print('alive=' + str(alive) + '/254')
