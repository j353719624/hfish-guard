import json, os

out = {}
p = '/appc/bin/guard.py'
out['guard_exists'] = os.path.exists(p)
s = open(p, encoding='utf-8').read()
s = s.replace('SEEN_SET = "hfish_guard_seen"', 'SEEN = "hfish_guard_seen"')
s = s.replace('WHITE_SET = "hfish_guard_white"', 'WHITE = "hfish_guard_white"')
s = s.replace('BLACK_SET = "hfish_guard_black"', 'BLACK = "hfish_guard_black"')
open(p, 'w', encoding='utf-8').write(s)

tok = json.load(open('/ad/config.json'))['token']
out['token'] = tok[:6] + '...'
uc = '/appc/ui/config'
t = open(uc, encoding='utf-8').read()
out['ui_token_before'] = ('CHANGE_ME' in t) and 'CHANGE_ME' or ('has-token' if 'token=' in t else 'no-token-field')
t2 = re.sub(r'token=[A-Za-z0-9]+', 'token=' + tok, t) if 're' in dir() else t
try:
    import re as _re
    t2 = _re.sub(r'token=[A-Za-z0-9]+', 'token=' + tok, t)
    open(uc, 'w', encoding='utf-8').write(t2)
    out['ui_patched'] = True
except Exception as e:
    out['ui_err'] = repr(e)[:150]

up = '/et/systemd/system/hfish-guard.service'
out['unit_exists'] = os.path.exists(up)
try:
    open('/diag/unit_copy.txt', 'w').write(open(up).read())
except Exception as e:
    out['unit_copy'] = repr(e)[:120]

json.dump(out, open('/diag/probe3.json', 'w'), ensure_ascii=False, indent=1)
print('DONE')
