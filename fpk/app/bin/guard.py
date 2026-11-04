#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HFish Guard —— 蜜罐联动自动封禁守护进程

数据面：iptables 陷阱把「碰蜜罐端口」的来源 IP 记入 ipset hfish_guard_seen（hash:ip counters）
控制面：本守护轮询 seen 集合，按滑动窗口阈值判定攻击行为：
        封禁模式 → 源 IP 进 hfish_guard_black 黑名单，iptables 全端口 DROP
        观察模式 → 只记录事件不封禁（最安全默认值）
接口面：:9705 提供 REST API 与单页可视化管理界面（token 鉴权）
存储面：/vol2/@appdata/hfish-guard/{config.json, guard.db}
"""
import json
import os
import random
import re
import sqlite3
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.environ.get("HFISH_GUARD_DATA", "/vol2/@appdata/hfish-guard")
CFG_PATH = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "guard.db")
UI_DIR = os.environ.get("HFISH_GUARD_UI", "/vol2/@appcenter/hfish-guard/bin/ui")
PORT = int(os.environ.get("HFISH_GUARD_PORT", "9705"))

SEEN = "hfish_guard_seen"
WHITE = "hfish_guard_white"
BLACK = "hfish_guard_black"

POLL_INTERVAL = 10          # 轮询 seen 集合周期（秒）
EXPIRY_TICKS = 6            # 每 N 个轮询周期跑一次过期清理

DEFAULT_CONFIG = {
    "mode": "observe",        # observe=观察(只记录) | block=封禁
    "threshold": 40,          # 窗口期内命中包数阈值
    "window": 60,             # 滑动窗口（秒）
    "ttl": 86400,             # 黑名单过期秒数；0=永久
    "ports": ["6379", "9200", "9000", "8080", "8081", "9198", "9080", "9092", "2022", "7878"],
    "whitelist": ["127.0.0.1", "192.168.110.97", "192.168.110.1", "192.168.110.36"],
    "token": "CHANGE_ME",
}


def sh(cmd):
    """执行 shell 命令，返回 (rc, stdout+stderr)"""
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


# ---------------------------------------------------------------- 配置与存储
class Store:
    def __init__(self):
        os.makedirs(BASE_DIR, exist_ok=True)
        if not os.path.exists(CFG_PATH):
            cfg = dict(DEFAULT_CONFIG)
            cfg["token"] = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(24))
            with open(CFG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
        self.cfg = self._load_cfg()
        self.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.lock = threading.Lock()
        with self.db:
            self.db.execute("""CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER, ip TEXT, hits INTEGER, action TEXT, detail TEXT)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS blocks(
                ip TEXT PRIMARY KEY, ts INTEGER, expire INTEGER,
                reason TEXT, hits INTEGER, active INTEGER DEFAULT 1)""")

    def _load_cfg(self):
        try:
            with open(CFG_PATH, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
        merged = dict(DEFAULT_CONFIG)
        merged.update({k: v for k, v in cfg.items() if k in DEFAULT_CONFIG})
        if isinstance(merged["ports"], str):
            merged["ports"] = [p.strip() for p in merged["ports"].split(",") if p.strip()]
        return merged

    def save_cfg(self):
        with self.lock:
            with open(CFG_PATH, "w", encoding="utf-8") as f:
                json.dump(self.cfg, f, ensure_ascii=False, indent=2)

    def event(self, ip, hits, action, detail=""):
        with self.lock:
            with self.db:
                self.db.execute(
                    "INSERT INTO events(ts, ip, hits, action, detail) VALUES(?,?,?,?,?)",
                    (int(time.time()), ip, hits, action, detail))

    def add_block(self, ip, hits, reason):
        ttl = int(self.cfg.get("ttl", 0))
        expire = 0 if ttl <= 0 else int(time.time()) + ttl
        with self.lock:
            with self.db:
                self.db.execute(
                    "INSERT INTO blocks(ip, ts, expire, reason, hits, active) VALUES(?,?,?,?,?,1) "
                    "ON CONFLICT(ip) DO UPDATE SET ts=excluded.ts, expire=excluded.expire, "
                    "reason=excluded.reason, hits=excluded.hits, active=1",
                    (ip, int(time.time()), expire, reason, hits))

    def unblock(self, ip):
        with self.lock:
            with self.db:
                self.db.execute("UPDATE blocks SET active=0 WHERE ip=?", (ip,))

    def active_blocks(self):
        with self.lock:
            cur = self.db.execute(
                "SELECT ip, ts, expire, reason, hits FROM blocks WHERE active=1 ORDER BY ts DESC")
            return cur.fetchall()

    def events(self, limit=100):
        with self.lock:
            cur = self.db.execute(
                "SELECT ts, ip, hits, action, detail FROM events ORDER BY id DESC LIMIT ?", (limit,))
            return cur.fetchall()


# ---------------------------------------------------------------- ipset / iptables
def ipset_members(name):
    """返回 {ip: packets}，解析 ipset list 输出（counters 模式）"""
    rc, out = sh(f"ipset list {name} 2>/dev/null")
    members = {}
    in_members = False
    for line in out.splitlines():
        s = line.strip()
        if s == "Members:":
            in_members = True
            continue
        if in_members and s:
            parts = s.split()
            ip = parts[0]
            packets = 0
            if "packets" in parts:
                try:
                    packets = int(parts[parts.index("packets") + 1])
                except (ValueError, IndexError):
                    packets = 0
            members[ip] = packets
    return members


def ensure_sets():
    sh(f"ipset create {SEEN} hash:ip counters timeout 120 -exist")
    sh(f"ipset create {WHITE} hash:ip -exist")
    sh(f"ipset create {BLACK} hash:ip -exist")


def sync_whitelist(whitelist):
    sh(f"ipset flush {WHITE}")
    for ip in whitelist:
        sh(f"ipset add {WHITE} {ip} -exist 2>/dev/null")


def apply_trap(ports, prev_ports=None):
    """（重）应用陷阱与封禁规则；端口列表变化时先撤旧规则"""
    port_str = ",".join(ports)
    for p in (prev_ports or []):
        if p and ",".join(p) != port_str:
            old = ",".join(p)
            sh(f'iptables -D INPUT -p tcp -m multiport --dports {old} -m set ! --match-set {WHITE} src -j SET --add-set {SEEN} src 2>/dev/null')
    rc, _ = sh(f'iptables -C INPUT -p tcp -m multiport --dports {port_str} -m set ! --match-set {WHITE} src -j SET --add-set {SEEN} src 2>/dev/null')
    if rc != 0:
        sh(f'iptables -I INPUT 1 -p tcp -m multiport --dports {port_str} -m set ! --match-set {WHITE} src -j SET --add-set {SEEN} src')
    rc, _ = sh(f'iptables -C INPUT -m set --match-set {BLACK} src -j DROP 2>/dev/null')
    if rc != 0:
        sh(f'iptables -I INPUT 2 -m set --match-set {BLACK} src -j DROP')


def remove_rules(ports):
    port_str = ",".join(ports)
    sh(f'iptables -D INPUT -p tcp -m multiport --dports {port_str} -m set ! --match-set {WHITE} src -j SET --add-set {SEEN} src 2>/dev/null')
    sh(f'iptables -D INPUT -m set --match-set {BLACK} src -j DROP 2>/dev/null')
    for s in (SEEN, WHITE, BLACK):
        sh(f"ipset destroy {s} 2>/dev/null")


def trap_present(ports):
    rc, _ = sh(f'iptables -C INPUT -p tcp -m multiport --dports {",".join(ports)} -m set ! --match-set {WHITE} src -j SET --add-set {SEEN} src 2>/dev/null')
    return rc == 0


# ---------------------------------------------------------------- 守护核心
class Guard:
    def __init__(self, store: Store):
        self.store = store
        self.prev = {}        # ip -> 上次轮询的包计数（累计值）
        self.last_poll = 0
        self.tick = 0

    def apply_all(self):
        ensure_sets()
        sync_whitelist(self.store.cfg["whitelist"])
        apply_trap(self.store.cfg["ports"])

    def poll_once(self):
        global window_hits
        self.tick += 1
        cfg = self.store.cfg
        window = int(cfg.get("window", 60))
        threshold = int(cfg.get("threshold", 40))
        whitelist = set(cfg.get("whitelist", []))
        now = time.time()

        members = ipset_members(SEEN)
        # 更新窗口计数
        for ip, packets in members.items():
            prev_pk = self.prev.get(ip)
            delta = packets - prev_pk if (prev_pk is not None and packets >= prev_pk) else packets
            self.prev[ip] = packets
            if delta <= 0:
                continue
            key = (ip, int(now // window))
            hist = window_hits.setdefault(key, 0)
            window_hits[key] = hist + delta
        # 清理已消失的 IP 与过期窗口
        for ip in list(self.prev):
            if ip not in members:
                self.prev.pop(ip, None)
        cutoff = now - window * 2
        for key in [k for k in window_hits if k[1] * window < cutoff]:
            window_hits.pop(key, None)

        # 判定
        for ip in list(members):
            if ip in whitelist:
                continue
            total = sum(v for (wip, wslot), v in window_hits.items() if wip == ip)
            if total < threshold:
                continue
            already = any(r[0] == ip for r in self.store.active_blocks())
            if already:
                window_hits = {k: v for k, v in window_hits.items() if k[0] != ip}
                continue
            mode = cfg.get("mode", "observe")
            action = "封禁" if mode == "block" else "观察"
            detail = "命中蜜罐端口 %s，%ds 内 %d 包" % (",".join(cfg["ports"]), window, total)
            self.store.event(ip, total, action, detail)
            if mode == "block":
                sh(f"ipset add {BLACK} {ip} -exist")
                self.store.add_block(ip, total, detail)
                sh(f"ipset del {SEEN} {ip} 2>/dev/null")
                self.prev.pop(ip, None)
            window_hits = {k: v for k, v in window_hits.items() if k[0] != ip}

        # 黑名单过期
        if self.tick % EXPIRY_TICKS == 0:
            for ip, ts, expire, reason, hits in self.store.active_blocks():
                if expire and expire > 0 and time.time() > expire:
                    sh(f"ipset del {BLACK} {ip} 2>/dev/null")
                    self.store.unblock(ip)
                    self.store.event(ip, hits, "过期解封", "TTL 到期自动解封")
        self.last_poll = now


window_hits = {}   # (ip, 窗口槽) -> 包数


def poll_loop(store: Store):
    guard = Guard(store)
    guard.apply_all()
    while True:
        try:
            guard.poll_once()
        except Exception as e:
            try:
                store.event("system", 0, "守护异常", str(e)[:200])
            except Exception:
                pass
        time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------- HTTP 服务
class Handler(BaseHTTPRequestHandler):
    server_version = "HFishGuard/1.0"

    def log_message(self, *a):
        pass

    def _auth(self):
        q = self.path.split("?token=")
        token = None
        if len(q) > 1:
            token = q[1].split("&")[0]
        if not token:
            token = self.headers.get("X-Token")
        return token == STORE.cfg.get("token")

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _static(self):
        idx = os.path.join(UI_DIR, "index.html")
        if not os.path.exists(idx):
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
        path, _, qs = self.path.partition("?")
        if not self._auth():
            self._json({"error": "unauthorized"}, 401)
            return
        if path in ("/", "/web", "/web/", "/index.html"):
            self._static()
        elif path == "/api/status":
            cfg = STORE.cfg
            blocks = STORE.active_blocks()
            ev = STORE.events(1)
            self._json({
                "mode": cfg.get("mode"),
                "threshold": cfg.get("threshold"),
                "window": cfg.get("window"),
                "ttl": cfg.get("ttl"),
                "ports": cfg.get("ports"),
                "whitelist": cfg.get("whitelist"),
                "blacklist_count": len(blocks),
                "events_count": STORE.events(1000).__len__(),
                "trap": trap_present(cfg["ports"]),
                "last_poll": int(GUARD.last_poll) if GUARD.last_poll else 0,
                "last_event": ev[0] if ev else None,
            })
        elif path == "/api/events":
            self._json([{"ts": r[0], "ip": r[1], "hits": r[2], "action": r[3], "detail": r[4]}
                        for r in STORE.events(100)])
        elif path == "/api/blacklist":
            self._json([{"ip": r[0], "ts": r[1], "expire": r[2], "reason": r[3], "hits": r[4]}
                        for r in STORE.active_blocks()])
        elif path == "/api/config":
            self._json({k: v for k, v in STORE.cfg.items()})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        path, _, qs = self.path.partition("?")
        if not self._auth():
            self._json({"error": "unauthorized"}, 401)
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            body = {}
        if path == "/api/config":
            cfg = STORE.cfg
            for k in ("mode", "threshold", "window", "ttl", "ports", "whitelist"):
                if k in body:
                    cfg[k] = body[k]
            if isinstance(cfg["ports"], str):
                cfg["ports"] = [p.strip() for p in cfg["ports"].split(",") if p.strip()]
            if isinstance(cfg["whitelist"], str):
                cfg["whitelist"] = [p.strip() for p in cfg["whitelist"].split(",") if p.strip()]
            if cfg["mode"] not in ("observe", "block"):
                cfg["mode"] = "observe"
            STORE.save_cfg()
            sync_whitelist(cfg["whitelist"])
            apply_trap(cfg["ports"])
            STORE.event("system", 0, "配置更新", "mode=%s threshold=%s/%ss" % (cfg["mode"], cfg["threshold"], cfg["window"]))
            self._json({"ok": True, "config": cfg})
        elif path == "/api/blacklist":
            ip = (body.get("ip") or "").strip()
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                self._json({"error": "bad ip"}, 400)
                return
            sh(f"ipset add {BLACK} {ip} -exist")
            STORE.add_block(ip, 0, "手动添加")
            STORE.event(ip, 0, "手动封禁", body.get("reason", ""))
            self._json({"ok": True})
        elif path == "/api/blacklist/delete":
            ip = (body.get("ip") or "").strip()
            sh(f"ipset del {BLACK} {ip} 2>/dev/null")
            STORE.unblock(ip)
            STORE.event(ip, 0, "手动解封", "")
            self._json({"ok": True})
        else:
            self._json({"error": "not found"}, 404)

    def do_DELETE(self):
        path, _, _ = self.path.partition("?")
        if not self._auth():
            self._json({"error": "unauthorized"}, 401)
            return
        if path.startswith("/api/blacklist/"):
            ip = path.rsplit("/", 1)[-1]
            sh(f"ipset del {BLACK} {ip} 2>/dev/null")
            STORE.unblock(ip)
            STORE.event(ip, 0, "手动解封", "")
            self._json({"ok": True})
            return
        self._json({"error": "not found"}, 404)


STORE = None
GUARD = None


def main():
    global STORE, GUARD
    STORE = Store()
    ensure_sets()
    t = threading.Thread(target=poll_loop, args=(STORE,), daemon=True)
    t.start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("HFish Guard listening on :%d, data=%s" % (PORT, BASE_DIR), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
