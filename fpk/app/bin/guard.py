#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""蜜罐守卫 HFish Guard v1.1 —— 蜜罐联动自动封禁守护进程

数据面：每个蜜罐端口一条 iptables 陷阱，命中包按 (IP, 端口) 记入独立
        ipset hfish_guard_seen_<端口>（hash:ip counters timeout 300），白名单内核侧豁免。
控制面：守护轮询各 seen 集合的包计数增量，按 (IP, 端口) 滑动窗口汇总：
        enforce 模式：超阈值源 IP 写入 hfish_guard_black + INPUT 全端口 DROP（TTL 自动过期）
        observe 模式：仅记录事件（最安全默认值）
接口面：:9705 REST API + 单页值守控制台
存储面：/vol2/@appdata/hfish-guard/{config.json, guard.db}
"""
import json
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.environ.get("HFISH_GUARD_DATA", "/vol2/@appdata/hfish-guard")
CFG_PATH = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "guard.db")
PORT = int(os.environ.get("HFISH_GUARD_PORT", "9705"))

IPS = "/usr/sbin/ipset"
IPT = "/usr/sbin/iptables"

UI_CANDIDATES = (
    "/var/apps/hfish-guard/ui",
    "/vol2/@appcenter/hfish-guard/ui",
    "/vol2/@appcenter/hfish-guard/bin/ui",
)

DEFAULT_CONFIG = {
    "mode": "observe",
    "threshold": 40,
    "window": 60,
    "poll": 10,
    "ttl": 3600,
    "ports": ["6379", "9200", "9000", "8080", "8081", "9198", "9080", "9092", "2022", "7878"],
    "whitelist": [],
    "token": "hfish-guard-demo",
}


def sh(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return -1, repr(e)[:200]


def set_name(port):
    return "hfish_guard_seen_%s" % port


# ---------------------------------------------------------------- 配置与存储
class Store:
    def __init__(self):
        os.makedirs(BASE_DIR, exist_ok=True)
        if not os.path.exists(CFG_PATH):
            self._write_cfg(dict(DEFAULT_CONFIG))
        self.cfg = self._load_cfg()
        self.lock = threading.Lock()
        self.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        with self.db:
            self.db.execute("""CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip TEXT,
                port INTEGER, packets INTEGER, verdict TEXT, action TEXT, detail TEXT)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS blocks(
                ip TEXT PRIMARY KEY, ts INTEGER, expire INTEGER, port INTEGER,
                packets INTEGER, ttl INTEGER, reason TEXT, active INTEGER DEFAULT 1)""")
            self.db.execute("CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT)")

    def _read_cfg(self):
        try:
            with open(CFG_PATH, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _load_cfg(self):
        raw = self._read_cfg()
        cfg = dict(DEFAULT_CONFIG)
        for k, v in raw.items():
            if k in cfg:
                cfg[k] = v
        if isinstance(cfg["ports"], str):
            cfg["ports"] = [p.strip() for p in cfg["ports"].split(",") if p.strip().isdigit()]
        wl = []
        for w in cfg["whitelist"]:
            if isinstance(w, str):
                wl.append({"cidr": w.strip(), "note": "", "at": int(time.time())})
            elif isinstance(w, dict) and w.get("cidr"):
                wl.append(w)
        cfg["whitelist"] = wl
        if cfg["mode"] not in ("observe", "enforce"):
            cfg["mode"] = "observe"
        return cfg

    def save_cfg(self):
        with self.lock:
            self._write_cfg(self.cfg)

    def event(self, ip, port, packets, verdict, action, detail=""):
        with self.lock:
            with self.db:
                self.db.execute(
                    "INSERT INTO events(ts, ip, port, packets, verdict, action, detail) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (int(time.time()), ip, port, packets, verdict, action, detail))

    def add_block(self, ip, port, packets, ttl, reason):
        ttl = int(ttl or self.cfg.get("ttl", 3600))
        expire = int(time.time()) + ttl
        with self.lock:
            with self.db:
                self.db.execute(
                    "INSERT INTO blocks(ip, ts, expire, port, packets, ttl, reason, active) "
                    "VALUES(?,?,?,?,?,?,?,1) "
                    "ON CONFLICT(ip) DO UPDATE SET ts=excluded.ts, expire=excluded.expire, "
                    "port=excluded.port, packets=excluded.packets, ttl=excluded.ttl, "
                    "reason=excluded.reason, active=1",
                    (ip, int(time.time()), expire, port, packets, ttl, reason))

    def unblock(self, ip):
        with self.lock:
            with self.db:
                self.db.execute("UPDATE blocks SET active=0 WHERE ip=?", (ip,))

    def active_blocks(self):
        with self.lock:
            return self.db.execute(
                "SELECT ip, ts, expire, port, packets, ttl, reason FROM blocks "
                "WHERE active=1 ORDER BY ts DESC").fetchall()

    def events(self, limit=200):
        with self.lock:
            return self.db.execute(
                "SELECT id, ts, ip, port, packets, verdict, action, detail FROM events "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def kv_get(self, k, d=None):
        with self.lock:
            r = self.db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
            return json.loads(r[0]) if r else d

    def kv_set(self, k, v):
        with self.lock:
            with self.db:
                self.db.execute(
                    "INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    (k, json.dumps(v)))


# ---------------------------------------------------------------- ipset / iptables
def sh(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return -1, repr(e)[:200]


def set_name(port):
    return "hfish_guard_seen_%s" % port


def ensure_sets(ports):
    for p in ports:
        sh(f"{IPS} create hfish_guard_seen_{p} hash:ip counters timeout 300 -exist")
    sh(f"{IPS} create hfish_guard_white hash:ip -exist")
    sh(f"{IPS} create hfish_guard_black hash:ip -exist")


def sync_whitelist(wl):
    sh(f"{IPS} flush hfish_guard_white")
    for w in wl:
        cidr = w["cidr"] if isinstance(w, dict) else w
        sh(f"{IPS} add hfish_guard_white {cidr} -exist 2>/dev/null")


def trap_rule(port, op):
    return (f"{IPT} {op} INPUT -p tcp --dport {port} "
            f"-m set ! --match-set hfish_guard_white src "
            f"-j SET --add-set {set_name(port)} src")


def apply_traps(ports, prev_ports=None):
    ensure_sets(ports)
    for p in (prev_ports or []):
        if p not in ports:
            sh(trap_rule(p, "-D") + " 2>/dev/null")
            sh(f"{IPS} destroy hfish_guard_seen_{p} 2>/dev/null")
    for p in ports:
        rc, _ = sh(trap_rule(p, "-C") + " 2>/dev/null")
        if rc != 0:
            sh(trap_rule(p, "-I"))
    rc, _ = sh(f"{IPT} -C INPUT -m set --match-set hfish_guard_black src -j DROP 2>/dev/null")
    if rc != 0:
        sh(f"{IPT} -I INPUT 2 -m set --match-set hfish_guard_black src -j DROP")


def trap_present(ports):
    if not ports:
        return False
    return all(sh(trap_rule(p, "-C") + " 2>/dev/null")[0] == 0 for p in ports)


def ipset_members(name):
    rc, out = sh(f"{IPS} list {name} 2>/dev/null")
    if rc != 0:
        return {}
    members, in_m = {}, False
    for line in out.splitlines():
        s = line.strip()
        if s == "Members:":
            in_m = True
            continue
        if in_m and s:
            parts = s.split()
            pk = 0
            if "packets" in parts:
                try:
                    pk = int(parts[parts.index("packets") + 1])
                except (ValueError, IndexError):
                    pk = 0
            members[parts[0]] = pk
    return members


# ---------------------------------------------------------------- Guard 核心
class Guard:
    def __init__(self, store):
        self.store = store
        self.prev = {}          # (port, ip) -> 上次包计数
        self.sec = {}           # epoch 秒 -> 全局命中包数（UI 脉冲图）
        self.ports_applied = []
        self.last_poll = 0
        self.tick = 0

    def apply_all(self):
        cfg = self.store.cfg
        ports = [str(x) for x in cfg["ports"]]
        ensure_sets(ports)
        sync_whitelist(cfg["whitelist"])
        apply_traps(ports, self.ports_applied)
        self.ports_applied = list(ports)

    def apply_traps(self, ports, prev_ports=None):
        ensure_sets(ports)
        for p in (prev_ports or []):
            if p not in ports:
                sh(trap_rule(p, "-D") + " 2>/dev/null")
                sh(f"{IPS} destroy hfish_guard_seen_{p} 2>/dev/null")
        for p in ports:
            rc, _ = sh(trap_rule(p, "-C") + " 2>/dev/null")
            if rc != 0:
                sh(trap_rule(p, "-I"))
        rc, _ = sh(f"{IPT} -C INPUT -m set --match-set hfish_guard_black src -j DROP 2>/dev/null")
        if rc != 0:
            sh(f"{IPT} -I INPUT 2 -m set --match-set hfish_guard_black src -j DROP")
        self.ports_applied = list(ports)

    def poll_once(self):
        global window_hits
        cfg = self.store.cfg
        ports = [str(x) for x in cfg["ports"]]
        window = int(cfg.get("window", 60))
        threshold = int(cfg.get("threshold", 40))
        whitelist = set(w["cidr"] for w in cfg.get("whitelist", []))
        now = int(time.time())
        self.last_poll = now

        per_ip, per_port = {}, {}
        for p in ports:
            members = ipset_members("hfish_guard_seen_%s" % p)
            if members is None:
                continue
            for ip, pk in members.items():
                key = (p, ip)
                prev = self.prev.get(key)
                delta = pk - prev if (prev is not None and pk >= prev) else pk
                self.prev[key] = pk
                if delta <= 0 or ip in whitelist:
                    continue
                hk = (ip, p, int(now // window))
                window_hits[hk] = window_hits.get(hk, 0) + delta
                per_ip[ip] = per_ip.get(ip, 0) + delta
                per_port_delta[p] = per_port_delta.get(p, 0) + delta
        # 消失的 (port, ip) 清理
        live = set()
        for p in ports:
            for ip in ipset_members("hfish_guard_seen_%s" % p):
                live.add((p, ip))
        for key in list(self.prev):
            if key not in live:
                self.prev.pop(key, None)
        for hk in [k for k in window_hits if k[2] < int(now // window) - 2]:
            window_hits.pop(hk, None)
        if per_ip:
            self.store.kv_set("total_packets",
                              int(self.store.kv_get("total_packets", 0)) + sum(per_ip.values()))
        if per_port:
            pt = self.store.kv_get("port_totals", {})
            for p, d in per_port.items():
                pt[p] = pt.get(p, 0) + d
            self.store.kv_set("port_totals", pt)
            pl = self.store.kv_get("port_last", {})
            for p in per_port:
                pl[p] = now
            self.store.kv_set("port_last", pl)

        # 判定
        blocked = set(r[0] for r in self.store.active_blocks())
        wl_cidr = set(w["cidr"] for w in cfg.get("whitelist", []))
        for ip, total in per_ip.items():
            if total < threshold or ip in blocked or ip in wl_cidr:
                continue
            hits_by_port = {}
            for (i2, p2, s2), v in window_hits.items():
                if i2 == ip:
                    hits_by_port[p2] = hits_by_port.get(p2, 0) + v
            top_port = max(hits_by_port, key=lambda x: hits_by_port[x]) if hits_by_port else int(ports[0])
            mode = cfg.get("mode", "observe")
            verdict = "over"
            if mode == "enforce":
                action = "自动封禁"
                sh(f"{IPS} add hfish_guard_black {ip} -exist")
                self.store.add_block(ip, top_port, total, cfg.get("ttl", 3600), "超阈值自动封禁")
                for pp in ports:
                    sh(f"{IPS} del hfish_guard_seen_{pp} {ip} 2>/dev/null")
                for hk in [k for k in window_hits if k[0] == ip]:
                    window_hits.pop(hk, None)
                self.prev = {k: v for k, v in self.prev.items() if k[1] != ip}
            else:
                action = "观察记录"
            self.store.event(ip, top_port, total, verdict, action, "滑动窗口 %ds" % window)

        # TTL 过期
        self.tick += 1
        if self.tick % 3 == 0:
            for ip, ts, expire, port, packets, ttl, reason in self.store.active_blocks():
                if expire and 0 < expire < now:
                    sh(f"{IPS} del hfish_guard_black {ip} 2>/dev/null")
                    self.store.unblock(ip)
                    self.store.event(ip, port, packets, "expired", "TTL 到期自动解封", "")

    def window_series(self):
        """最近 60 个轮询周期的全局命中增量（供 UI 脉冲图）"""
        return sorted(sec_series.items())[-60:]

    def top_src(self):
        now = int(time.time())
        per_ip = {}
        for (ip, p, slot), v in window_hits.items():
            if slot >= int(now // window) - 1:
                per_ip[ip] = per_ip.get(ip, 0) + v
        return max(per_ip.values()) if per_ip else 0


window_hits = {}
sec_series = {}
STORE = None
GUARD = None


def poll_loop():
    GUARD.apply_all()
    while True:
        try:
            GUARD.poll_once()
        except Exception as e:
            try:
                STORE.event("system", 0, 0, 0, "error", "守护异常 " + str(e)[:200])
            except Exception:
                pass
        time.sleep(int(STORE.cfg.get("poll", 10)))


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "HFishGuard/1.1"

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _static(self):
        idx = None
        for d in UI_CANDIDATES:
            c = os.path.join(d, "index.html")
            if os.path.exists(c):
                idx = c
                break
        if not idx:
            self._json({"error": "ui not found"}, 404)
            return
        with open(idx, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path, _, _ = self.path.partition("?")
        if path in ("/", "/web", "/web/", "/index.html"):
            self._static()
            return
        if path == "/api/status":
            cfg = STORE.cfg
            evs = STORE.events(10000)
            over = [e for e in evs if e[5] == "over"]
            self._json({
                "mode": cfg["mode"],
                "threshold": cfg["threshold"],
                "window": cfg["window"],
                "poll": cfg.get("poll", 10),
                "ttl": cfg["ttl"],
                "ports": cfg["ports"],
                "whitelist": cfg["whitelist"],
                "blacklist_count": len(STORE.active_blocks()),
                "events_count": len(over),
                "trap": trap_present([str(x) for x in cfg["ports"]]),
                "last_poll": GUARD.last_poll if GUARD else 0,
                "total_packets": int(STORE.kv_get("total_packets", 0)),
                "per_port": STORE.kv_get("port_totals", {}),
                "port_last": STORE.kv_get("port_last", {}),
                "window_series": GUARD.window_series() if GUARD else [],
                "top_src": GUARD.top_src() if GUARD else 0,
                "recent": [{"ts": r[1] * 1000, "ip": r[2], "port": r[3], "packets": r[4],
                            "verdict": r[5], "action": r[6]} for r in STORE.events(5)],
            })
        elif path == "/api/events":
            evs = STORE.events(500)
            self._json([{"id": "EV-%d" % r[0], "ts": r[1] * 1000, "ip": r[2], "port": r[3],
                         "packets": r[4], "verdict": r[5], "action": r[6]} for r in evs])
        elif path == "/api/blacklist":
            self._json([{"ip": r[0], "at": r[1] * 1000, "expire": r[2] * 1000, "port": r[3],
                         "packets": r[4], "ttl": r[5], "reason": r[6]}
                        for r in STORE.active_blocks()])
        elif path == "/api/whitelist":
            self._json(STORE.cfg.get("whitelist", []))
        elif path == "/api/config":
            self._json(STORE.cfg)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        path, _, _ = self.path.partition("?")
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            body = {}
        if path == "/api/config":
            cfg = STORE.cfg
            for k in ("mode", "threshold", "window", "poll", "ttl", "ports", "whitelist"):
                if k in body:
                    cfg[k] = body[k]
            if isinstance(cfg["ports"], str):
                cfg["ports"] = [p.strip() for p in cfg["ports"].split(",") if p.strip().isdigit()]
            wl = []
            for w in cfg["whitelist"]:
                if isinstance(w, dict) and w.get("cidr"):
                    wl.append(w)
                elif isinstance(w, str):
                    wl.append({"cidr": w.strip(), "note": "", "at": int(time.time())})
            cfg["whitelist"] = wl
            if cfg["mode"] not in ("observe", "enforce"):
                cfg["mode"] = "observe"
            STORE.save_cfg()
            sync_whitelist(cfg["whitelist"])
            if GUARD:
                GUARD.apply_traps([str(x) for x in cfg["ports"]], GUARD.ports_applied)
                GUARD.ports_applied = list(cfg["ports"])
            STORE.event("system", 0, 0, 0, "config", "配置热加载 mode=%s" % cfg["mode"])
            self._json({"ok": True, "config": cfg})
        elif path == "/api/blacklist":
            ip = (body.get("ip") or "").strip()
            if not re.match(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$", ip):
                self._json({"error": "bad ip"}, 400)
                return
            sh(f"{IPS} add hfish_guard_black {ip} -exist")
            STORE.add_block(ip, int(body.get("port") or 0), 0,
                            int(body.get("ttl") or 0), body.get("reason") or "手动封禁")
            STORE.event(ip, int(body.get("port") or 0), 0, "manual", "手动封禁", body.get("note") or "")
            self._json({"ok": True})
        elif path == "/api/blacklist/delete":
            ip = (body.get("ip") or "").strip()
            sh(f"{IPS} del hfish_guard_black {ip} 2>/dev/null")
            STORE.unblock(ip)
            STORE.event(ip, 0, 0, "manual", "手动解封", "")
            self._json({"ok": True})
        elif path == "/api/whitelist":
            cidr = (body.get("cidr") or "").strip()
            if not re.match(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$", cidr):
                self._json({"error": "bad cidr"}, 400)
                return
            wl = STORE.cfg["whitelist"]
            if not any((w.get("cidr") == cidr) for w in wl):
                wl.append({"cidr": cidr, "note": body.get("note") or "", "at": int(time.time())})
                STORE.save_cfg()
                sync_whitelist(wl)
            self._json({"ok": True, "whitelist": wl})
        elif path == "/api/whitelist/delete":
            cidr = (body.get("cidr") or "").strip()
            cfg = STORE.cfg
            cfg["whitelist"] = [w for w in cfg["whitelist"] if w.get("cidr") != cidr]
            STORE.save_cfg()
            sync_whitelist(cfg["whitelist"])
            self._json({"ok": True})
        elif path == "/api/token":
            tok = "hg-" + secrets.token_hex(12)
            cfg = STORE.cfg
            cfg["token"] = tok
            STORE.save_cfg()
            STORE.event("system", 0, 0, 0, "token", "接口凭证已重新生成")
            self._json({"ok": True, "token": tok})
        else:
            self._json({"error": "not found"}, 404)

    def do_DELETE(self):
        path, _, _ = self.path.partition("?")
        if path.startswith("/api/blacklist/"):
            ip = path.rsplit("/", 1)[-1]
            sh(f"{IPS} del hfish_guard_black {ip} 2>/dev/null")
            STORE.unblock(ip)
            STORE.event(ip, 0, 0, "manual", "手动解封", "")
            self._json({"ok": True})
        elif path.startswith("/api/whitelist/"):
            cidr = path.rsplit("/", 1)[-1]
            cfg = STORE.cfg
            cfg["whitelist"] = [w for w in cfg["whitelist"] if w.get("cidr") != cidr]
            STORE.save_cfg()
            sync_whitelist(cfg["whitelist"])
            self._json({"ok": True})
        else:
            self._json({"error": "not found"}, 404)


def poll_loop():
    GUARD.apply_all()
    while True:
        try:
            GUARD.poll_once()
        except Exception as e:
            try:
                STORE.event("system", 0, 0, 0, "error", "守护异常 " + str(e)[:200])
            except Exception:
                pass
        time.sleep(int(STORE.cfg.get("poll", 10)))


def main():
    global STORE, GUARD
    STORE = Store()
    GUARD = Guard(STORE)
    GUARD.apply_all()
    t = threading.Thread(target=poll_loop, daemon=True)
    t.start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("HFish Guard listening on :%d" % PORT, flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
