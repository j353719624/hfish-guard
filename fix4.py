import re

gp = '/appc/bin/guard.py'
s = open(gp, encoding='utf-8').read()
n = 0
s2 = re.sub(r"sh\(f'(?=(iptables|ipset))", "sh(f'/usr/sbin/", s)
n = s.count('/usr/sbin/')
open(gp, 'w', encoding='utf-8').write(s)
print('absolute-path calls:', n)
