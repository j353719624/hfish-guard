import json, os, subprocess, traceback

def run(c, t=90):
    try:
        r = subprocess.run(c, capture_output=True, text=True, timeout=t)
        return {'rc': r.returncode, 'out': ((r.stdout or '') + (r.stderr or ''))[-5000:]}
    except Exception as e:
        return {'rc': -1, 'err': repr(e)[:300]}

out = {}
try:
    p = '/vol2/@appcenter/hfish-guard/bin/guard.py'
    out['unit_exists'] = os.path.exists('/etc/systemd/system/hfish-guard.service')
    out['guard_exists'] = os.path.exists(p)
    out['bin_ls'] = sorted(os.listdir('/vol2/@appcenter/hfish-guard/bin')) if os.path.isdir('/vol2/@appcenter/hfish-guard/bin') else 'MISSING'
    out['data_ls'] = sorted(os.listdir('/vol2/@appdata/hfish-guard')) if os.path.isdir('/vol2/@appdata/hfish-guard') else 'MISSING'
    try:
        out['cfg'] = open('/vol2/@appdata/hfish-guard/config.json').read()[:700]
    except Exception as e:
        out['cfg'] = 'ERR:' + repr(e)[:200]
    out['pysyntax'] = run(['/usr/bin/python3', '-m', 'py_compile', p], 60)
    out['svc'] = run(['/usr/bin/systemctl', 'status', 'hfish-guard', '-l', '--no-pager'], 30)
    out['journal'] = run(['/usr/bin/journalctl', '-u', 'hfish-guard', '-n', '40', '--no-pager'], 60)
    out['ss'] = run(['/usr/bin/ss', '-tlnp'], 30)
except Exception:
    out['fatal'] = traceback.format_exc()[-1500:]

json.dump(out, open('/vol2/1000/workspace/work/diag.json', 'w'), ensure_ascii=False, indent=1)
print('DIAG_DONE')
