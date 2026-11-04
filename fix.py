import json, os, re

gp = '/appc/bin/guard.py'
s = open(gp, encoding='utf-8').read()
s = s.replace('SEEN_SET = "hfish_guard_seen"', 'SEEN = "hfish_guard_seen"')
s = s.replace('WHITE_SET = "hfish_guard_white"', 'WHITE = "hfish_guard_white"')
s = s.replace('BLACK_SET = "hfish_guard_black"', 'BLACK = "hfish_guard_black"')
open(gp, 'w', encoding='utf-8').write(s)
print('guard.py constants fixed:', 'SEEN_SET' not in s)

tok = json.load(open('/appdata/config.json'))['token']
for u in ('/appc/ui/config', '/varapp/ui/config'):
    try:
        t = open(u, encoding='utf-8').read()
        t2 = re.sub(r'token=[A-Za-z0-9]+', 'token=' + tok, t)
        if t2 != t:
            open(u, 'w', encoding='utf-8').write(t2)
            print('token synced:', u)
        else:
            print('token already ok:', u)
    except Exception as e:
        print('ui', u, repr(e)[:150])
print('FIXED')
