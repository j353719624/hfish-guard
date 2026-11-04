import json, os

out = {}
# 0) 目录探测（回答 fnOS 到底把 ui 解到哪里）
for d in ('/appc', '/appc/bin', '/appc/ui', '/varapp', '/varapp/ui', '/appdata'):
    try:
        out[d] = sorted(os.listdir(d))
    except Exception as e:
        out[d] = 'ERR ' + repr(e)[:80]

gp = '/appc/bin/guard.py'
s = open(gp, encoding='utf-8').read()
patches = [
    ("""def poll_loop(store: Store):
    guard = Guard(store)
    guard.apply_all()""",
     """def poll_loop():
    GUARD.apply_all()"""),
    ("            guard.poll_once()", "            GUARD.poll_once()"),
    ("    t = threading.Thread(target=poll_loop, args=(STORE,), daemon=True)",
     "    t = threading.Thread(target=poll_loop, daemon=True)"),
    ("""    STORE = Store()
    ensure_sets()""",
     """    STORE = Store()
    GUARD = Guard(STORE)
    ensure_sets()"""),
    ("""    def _static(self):
        idx = os.path.join(UI_DIR, "index.html")
        if not os.path.exists(idx):
            self._json({"error": "ui not found"}, 404)
            return""",
     """    def _static(self):
        idx = None
        for d in (UI_DIR, "/var/apps/hfish-guard/ui", "/vol2/@appcenter/hfish-guard/bin/ui", "/vol2/@appcenter/hfish-guard/ui"):
            c = os.path.join(d, "index.html")
            if os.path.exists(c):
                idx = c
                break
        if not idx:
            self._json({"error": "ui not found"}, 404)
            return"""),
]
res = []
for old, new in patches:
    if old in s:
        s = s.replace(old, new)
        res.append('ok:' + old.splitlines()[0][:40])
    else:
        res.append('MISS:' + old.splitlines()[0][:40])
open(gp, 'w', encoding='utf-8').write(s)
out['patches'] = res

json.dump(out, open('/diag/probe.json', 'w'), ensure_ascii=False, indent=1)
print('PATCHED')
