import json, os, sys, traceback

out = open('/vol2/1000/workspace/work/bootdiag.txt', 'w', encoding='utf-8')

def step(name, fn):
    try:
        r = fn()
        err = ''
        if r is not None and hasattr(r, 'stderr'):
            err = (r.stderr or '')[-400:]
        out.write('[OK] %s %s\n' % (name, err))
    except Exception:
        out.write('[FAIL] %s\n%s\n=== STOP ===\n' % (name, traceback.format_exc()))
        out.flush()
        sys.exit(0)
    out.flush()

out.write('bootdiag start %s\n' % time.strftime('%H:%M:%S'))
out.flush()

step('import sqlite3', lambda: __import__('sqlite3'))
step('makedirs', lambda: os.makedirs('/vol2/@appdata/hfish-guard', exist_ok=True))
step('config.json', lambda: json.load(open('/vol2/@appdata/hfish-guard/config.json')))
step('sqlite open', lambda: sqlite3.connect('/vol2/@appdata/hfish-guard/guard.db').execute('select 1').fetchall())

def ipset_seen():
    r = subprocess.run('ipset create hfish_guard_seen hash:ip counters timeout 120 -exist', shell=True, capture_output=True, text=True)
    return r.stderr[-300:] or 'rc0'
step('ipset create seen', ipset_seen)

def ipset_white():
    r = subprocess.run('ipset create hfish_guard_white hash:ip -exist', shell=True, capture_output=True, text=True)
    return r.stderr[-300:] or 'rc0'
step('ipset create white', ipset_white)

def ipset_black():
    r = subprocess.run('ipset create hfish_guard_black hash:ip -exist', shell=True, capture_output=True, text=True)
    return r.stderr[-300:] or 'rc0'
step('ipset create black', ipset_black)

def ipt_trap():
    r = subprocess.run('iptables -C INPUT -p tcp -m multiport --dports 6379,9200,9000,8080,8081,9198,9080,9092,2022,7878 -m set ! --match-set hfish_guard_white src -j SET --add-set hfish_guard_seen src', shell=True, capture_output=True, text=True)
    return 'rc%d %s' % (r.returncode, (r.stderr or '')[-300:])
step('iptables trap check', ipt_trap)

from http.server import ThreadingHTTPServer
step('bind 9705', lambda: ThreadingHTTPServer(('0.0.0.0', 9705), None))
out.write('ALL OK\n')
out.close()
sys.exit(0)
