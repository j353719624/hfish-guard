#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""蜜罐守卫 HFish Guard · 守护进程 v1.2.0

四层结构（与 README / docs/ARCHITECTURE.md 对应）：

  数据面  每个监视端口一条 iptables 陷阱规则，命中的源 IP 记入
          ipset hfish_guard_seen_<port>（hash:ip counters timeout 300）。
          白名单在**内核侧**用 `! --match-set hfish_guard_white src` 豁免，
          自家扫描流量不会进入计数，也不会产生日志洪水。
  控制面  每 poll 秒轮询各 seen 集合的 packets 计数，取增量；
          按 (源IP, 端口) 做滑动窗口汇总，超阈值触发判定：
              enforce 模式 → 写 hfish_guard_black + INPUT DROP（TTL 到期自动解封）
              observe 模式 → 只记录事件（默认，最安全）
  接口面  :9705 REST API（Bearer / ?token= 鉴权）+ 单文件控制台 UI
  存储面  $HFISH_GUARD_DATA（默认 /vol2/@appdata/hfish-guard）：
          config.json（配置与凭证）、guard.db（事件/黑名单，sqlite3）

本地联调（Windows / 无 root 的开发机）：
    python guard.py --fake --port 9706 --data ./tmp
  --fake 用内存态内核替代 ipset/iptables，并启动攻击模拟器，
  整条判定链路（计数→窗口→阈值→封禁→TTL）与线上完全一致。

注意：本进程只读 ipset 计数器，不调用 HFish / Cowrie 的 API 与数据库，
蜜罐侧升级、重装、换端口都不影响守卫；端口面通过配置同步联动。
"""
import argparse
import ipaddress
import json
import os
import re
import secrets
import shlex
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.4.3"
APP_NAME = "hfish-guard"

BASE_DIR = os.environ.get("HFISH_GUARD_DATA", "/vol2/@appdata/hfish-guard")
CFG_PATH = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "guard.db")
GEO_PATH = os.path.join(BASE_DIR, "geo.json")
PORT = int(os.environ.get("HFISH_GUARD_PORT", "9705"))
POLL_DEFAULT = int(os.environ.get("HFISH_GUARD_POLL", "10"))
FAKE = os.environ.get("HFISH_GUARD_FAKE", "").strip().lower() in ("1", "true", "yes", "on")
VERBOSE = os.environ.get("HFISH_GUARD_VERBOSE", "").strip().lower() in ("1", "true", "yes", "on")
# fake 模式下是否启动攻击模拟器（跑单测时用 HFISH_GUARD_SIM=0 关掉，避免干扰断言）
SIMULATE = os.environ.get("HFISH_GUARD_SIM", "1").strip().lower() not in ("0", "false", "no", "off")

IPS = os.environ.get("HFISH_GUARD_IPSET", "/usr/sbin/ipset")
IPT = os.environ.get("HFISH_GUARD_IPTABLES", "/usr/sbin/iptables")
IP6T = os.environ.get("HFISH_GUARD_IP6TABLES", "/usr/sbin/ip6tables")

# fnOS 把应用解到 /vol2/@appcenter/<app>/bin，同时在 /var/apps/<app>/ 下挂符号链接
UI_CANDIDATES = (
    "/var/apps/hfish-guard/ui",
    "/vol2/@appcenter/hfish-guard/ui",
    "/vol2/@appcenter/hfish-guard/bin/ui",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ui"),
)
# 蜜罐应用（fnos-hive）的安装位置，用于状态页展示联动情况；只做存在性判断
HIVE_DIRS = ("/vol2/@appcenter/hive", "/var/apps/hive")

SEEN_PREFIX = "hfish_guard_seen_"
SET_WHITE = "hfish_guard_white"
SET_BLACK = "hfish_guard_black"
SET_ALERT = "hfish_guard_alert"     # 观察模式下内核判定的命中池
SET_WHITE6 = "hfish_guard_white6"   # IPv6 对应集合（ipset family inet6）
SET_BLACK6 = "hfish_guard_black6"
SET_ALERT6 = "hfish_guard_alert6"
SEEN_TIMEOUT = 300                      # seen 集合成员兜底过期时间（秒）
ALERT_TIMEOUT = 900                     # 观察命中池保留时长（供用户态取走事件）

# 旧版本（v1.0.0 的 UI 与接口）用过这些取值，升级时映射到当前语义，
# 避免已部署的配置被静默降级成 observe（旧 UI 的「封禁模式」= block）
LEGACY_MODE = {"block": "enforce", "ban": "enforce", "drop": "enforce",
               "enforcing": "enforce", "record": "observe",
               "monitor": "observe", "log": "observe"}

DEFAULT_CONFIG = {
    "mode": "observe",                  # observe | enforce
    "threshold": 40,                    # 窗口内命中包数阈值
    "window": 60,                       # 窗口秒数
    "poll": POLL_DEFAULT,               # 轮询间隔
    "ttl": 3600,                        # 黑名单过期秒数，0 = 永久
    "ports": ["6379", "9200", "9000", "8080", "8081", "9198", "9080", "9092", "2022", "7878"],
    "whitelist": [],
    "token": "",                        # 空 = 首次启动自动生成
    # HFish 联动（官方三种出口：开放 API / syslog / webhook），可全部留空只用内核计数
    "udp": True,                        # 同时 trap UDP（蜜罐端口上的 UDP 扫描）
    "scan_ports": 6,                    # 同源在窗口内命中多少个不同蜜罐端口算端口扫描
    "scan_block": True,                 # 判定为端口扫描时是否直接封禁（仅 enforce 生效）
    "hfish": {
        "enabled": False,               # 总开关：开启后才监听 syslog / 接受 webhook
        "syslog_port": 5514,            # HFish「告警策略 → syslog」指向本机此端口（UDP+TCP）
        "api_base": "",                 # 形如 https://127.0.0.1:4433（HFish 管理端，自签证书）
        "api_key": "",                  # HFish「系统设置 → API 配置」里生成的 key
        "verify_tls": False,            # HFish 默认自签证书，保持 False
        "webhook_token": "",            # 自定义 webhook 的校验串；空则要求主 token
        "auto_block_level": "",         # "" 不自动封禁；high / critical 时按告警等级直接封禁
    },
}

# 归属地：无 mmdb 时的粗粒度兜底表（与 UI 内置表一致，标注 approx）。
# 生产环境请放置 GeoLite2-City.mmdb 或自建 geo.json，见 docs/ARCHITECTURE.md。
GEO_APPROX = (
    ("5.", "RU", "俄罗斯", "东欧段", 59.93, 30.34),
    ("23.", "US", "美国", "北美段", 39.00, -98.00),
    ("45.", "NL", "荷兰", "西欧段", 52.30, 4.90),
    ("89.", "NL", "荷兰", "西欧段", 51.90, 4.50),
    ("91.", "RU", "俄罗斯", "东欧段", 55.70, 37.60),
    ("103.", "SG", "新加坡", "亚太段", 1.35, 103.80),
    ("172.104.", "JP", "日本", "东京", 35.68, 139.69),
    ("185.", "DE", "德国", "西欧段", 50.10, 8.68),
    ("194.", "DE", "德国", "西欧段", 52.50, 13.40),
    ("198.", "US", "美国", "北美段", 34.00, -118.20),
)

IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
CIDR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")


# --------------------------------------------------------------------- 基础工具
def log(msg, level="info"):
    if level == "debug" and not VERBOSE:
        return
    if FAKE and level == "debug":
        return
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    sys.stdout.write("%s [%s] %s\n" % (ts, level, msg))
    sys.stdout.flush()


def sh(cmd, timeout=15):
    """执行内核命令，返回 (rc, stdout+stderr)。失败不抛异常，由调用方判定。"""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:                                # noqa: BLE001
        return -1, repr(e)[:200]


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def valid_ip(s):
    """接受 IPv4 与 IPv6 单地址（双栈后不能再只认点分十进制）。"""
    try:
        ipaddress.ip_address(str(s or "").strip())
        return True
    except ValueError:
        return False


def valid_cidr(s):
    """接受 IPv4/IPv6 网段（白名单要能写 ::1、2409:.../64 这类条目）。"""
    try:
        ipaddress.ip_network(str(s or "").strip(), strict=False)
        return True
    except ValueError:
        return False


def ip_int(s):
    n = 0
    for part in s.split("."):
        n = (n << 8) + int(part)
    return n


def _truthy(val, default=False):
    """把用户传的 true/"1"/"on" 之类统一成布尔。"""
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    return str(val).strip().lower() in ("1", "true", "yes", "on", "enable", "enabled")


def _is_v6(addr):
    """判断地址/网段是否 IPv6（用于选集合与 iptables 分支）。"""
    try:
        return ipaddress.ip_network(str(addr).strip(), strict=False).version == 6
    except ValueError:
        return ":" in str(addr)


def set_name(port, v6=False):
    return "%s%s%s" % (SEEN_PREFIX, "6_" if v6 else "", port)


def rate_spec(threshold, window):
    """把「threshold 包 / window 秒」翻译成 hashlimit 认的速率写法。

    iptables 只接受 /second /minute /hour /day 这几种单位，
    写 "40/60sec" 会直接 hashlimit: Bad value 被拒。
    """
    threshold = max(1, int(threshold))
    window = max(1, int(window))
    for unit, secs in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if window >= secs:
            amount = int(round(threshold * secs / float(window)))
            return "%d/%s" % (max(1, amount), unit)
    return "%d/second" % max(1, int(round(threshold / float(window))))


class Whitelist:
    """CIDR 匹配缓存；每次热加载重建，避免轮询里反复解析。"""

    def __init__(self, entries=None):
        self.nets = []
        self.raw = set()
        for e in entries or []:
            cidr = e.get("cidr") if isinstance(e, dict) else e
            if not cidr:
                continue
            self.raw.add(cidr)
            try:
                self.nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log("忽略非法白名单条目 %r" % cidr, "warn")

    def __contains__(self, ip):
        if not ip:
            return False
        if ip in self.raw:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.nets)


# --------------------------------------------------------------------- 内核层
class RealKernel:
    """ipset + iptables / ip6tables 真实实现（IPv4 + IPv6 双栈）。

    每个蜜罐端口挂两类规则：
      1) 记名：命中的源 IP 进 seen_<port>（IPv6 用 seen6_<port>），白名单内核侧豁免，
         这条规则自己的包计数器就是该端口的真实流量；
      2) 判定：-m hashlimit 按源 IP 计速率，超过 threshold/window 写命中池
         （enforce→black，observe→alert）。
    TCP 与 UDP 各挂一套（蜜罐端口上的 UDP 扫描同样要计）。

    为什么不用 ipset 的 packets 计数：真机实测该计数器只在条目创建时记 1，
    后续同源包不累加（`ipset add -exist` 也保持 0），拿它做增量永远是 1。
    """

    kind = "netfilter"

    def __init__(self):
        self.reason = ""
        self.v6 = False
        self.v6_reason = ""
        if FAKE:
            self.available = False
            self.reason = "fake mode"
            return
        if not os.path.exists(IPS):
            self.available = False
            self.reason = "未找到 %s（ipset 未安装？）" % IPS
            return
        if not is_root():
            self.available = False
            self.reason = "非 root 运行，无法操作 netfilter"
            return
        rc, out = sh("%s version" % IPS)
        self.available = rc == 0
        self.reason = "" if rc == 0 else out.strip()[:120]
        # IPv6：ip6tables 存在 + 能建 inet6 集合，才算可用
        if self.available:
            if not os.path.exists(IP6T):
                self.v6_reason = "未找到 %s" % IP6T
            else:
                rc2, out2 = sh("%s -w 3 -L INPUT -n" % IP6T)
                if rc2 != 0:
                    self.v6_reason = (out2 or "ip6tables 不可用").strip()[:120]
                else:
                    rc3, _ = sh("%s create hfish_guard_probe6 hash:ip family inet6 -exist" % IPS)
                    if rc3 != 0:
                        self.v6_reason = "内核不支持 inet6 集合"
                    else:
                        sh("%s destroy hfish_guard_probe6" % IPS)
                        self.v6 = True

    # -- 集合
    def ensure_sets(self, ports):
        for p in ports:
            sh("%s create %s hash:ip timeout %d -exist" % (IPS, set_name(p), SEEN_TIMEOUT))
            if self.v6:
                sh("%s create %s hash:ip family inet6 timeout %d -exist"
                   % (IPS, set_name(p, True), SEEN_TIMEOUT))
        sh("%s create %s hash:ip -exist" % (IPS, SET_WHITE))
        sh("%s create %s hash:ip -exist" % (IPS, SET_BLACK))
        sh("%s create %s hash:ip timeout %d -exist" % (IPS, SET_ALERT, ALERT_TIMEOUT))
        if self.v6:
            sh("%s create %s hash:ip family inet6 -exist" % (IPS, SET_WHITE6))
            sh("%s create %s hash:ip family inet6 -exist" % (IPS, SET_BLACK6))
            sh("%s create %s hash:ip family inet6 timeout %d -exist"
               % (IPS, SET_ALERT6, ALERT_TIMEOUT))

    def members(self, port):
        out = {}
        for v6 in ((False, True) if self.v6 else (False,)):
            rc, txt = sh("%s list %s" % (IPS, set_name(port, v6)))
            if rc != 0:
                continue
            in_members = False
            for line in txt.splitlines():
                t = line.strip()
                if t == "Members:":
                    in_members = True
                    continue
                if in_members and t:
                    out[t.split()[0]] = 0
        return out

    def del_member(self, port, ip):
        sh("%s del %s %s 2>/dev/null" % (IPS, set_name(port, _is_v6(ip)), ip))

    def destroy_set(self, port):
        sh("%s destroy %s 2>/dev/null" % (IPS, set_name(port)))
        if self.v6:
            sh("%s destroy %s 2>/dev/null" % (IPS, set_name(port, True)))

    # -- 黑名单 / 命中池（按地址族选择集合）
    def add_black(self, ip):
        name = SET_BLACK6 if _is_v6(ip) else SET_BLACK
        if _is_v6(ip) and not self.v6:
            return False
        return sh("%s add %s %s -exist" % (IPS, name, ip))[0] == 0

    def del_black(self, ip):
        name = SET_BLACK6 if _is_v6(ip) else SET_BLACK
        if _is_v6(ip) and not self.v6:
            return
        sh("%s del %s %s 2>/dev/null" % (IPS, name, ip))

    def black_members(self):
        out = set(self.members_raw(SET_BLACK))
        if self.v6:
            out |= set(self.members_raw(SET_BLACK6))
        return out

    def alert_members(self):
        out = set(self.members_raw(SET_ALERT))
        if self.v6:
            out |= set(self.members_raw(SET_ALERT6))
        return out

    def del_alert(self, ip):
        name = SET_ALERT6 if _is_v6(ip) else SET_ALERT
        if _is_v6(ip) and not self.v6:
            return
        sh("%s del %s %s 2>/dev/null" % (IPS, name, ip))

    def members_raw(self, name):
        rc, out = sh("%s list %s" % (IPS, name))
        if rc != 0:
            return []
        ips, in_members = [], False
        for line in out.splitlines():
            t = line.strip()
            if t == "Members:":
                in_members = True
                continue
            if in_members and t:
                ips.append(t.split()[0])
        return ips

    # -- 白名单（按地址族分流，v6 条目进 inet6 集合）
    def sync_whitelist(self, entries):
        sh("%s flush %s" % (IPS, SET_WHITE))
        if self.v6:
            sh("%s flush %s" % (IPS, SET_WHITE6))
        for e in entries:
            cidr = e.get("cidr") if isinstance(e, dict) else e
            if not cidr:
                continue
            v6 = _is_v6(cidr)
            if v6 and not self.v6:
                continue
            sh("%s add %s %s -exist 2>/dev/null"
               % (IPS, SET_WHITE6 if v6 else SET_WHITE, cidr))

    # -- 规则片段
    def seen_rule(self, port, v6=False, proto="tcp"):
        return ("-p %s --dport %s -m set ! --match-set %s src "
                "-j SET --add-set %s src"
                % (proto, port, SET_WHITE6 if v6 else SET_WHITE, set_name(port, v6)))

    def hlimit_rule(self, port, threshold, window, target, v6=False, proto="tcp"):
        rate = rate_spec(threshold, window)
        return ("-p %s --dport %s -m set ! --match-set %s src "
                "-m hashlimit --hashlimit-name hg%s%s%s --hashlimit-mode srcip "
                "--hashlimit-above %s --hashlimit-burst %d "
                "--hashlimit-htable-expire %d --hashlimit-htable-size 2048 "
                "-j SET --add-set %s src"
                % (proto, port, SET_WHITE6 if v6 else SET_WHITE,
                   "6" if v6 else "", "" if proto == "tcp" else "u", port,
                   rate, threshold, window * 2000, target))

    def hlimit_drop(self, port, threshold, window, v6=False, proto="tcp"):
        rate = rate_spec(threshold, window)
        return ("-p %s --dport %s -m set ! --match-set %s src "
                "-m hashlimit --hashlimit-name hg%s%s%s --hashlimit-mode srcip "
                "--hashlimit-above %s --hashlimit-burst %d "
                "--hashlimit-htable-expire %d --hashlimit-htable-size 2048 -j DROP"
                % (proto, port, SET_WHITE6 if v6 else SET_WHITE,
                   "6" if v6 else "", "" if proto == "tcp" else "u", port,
                   rate, threshold, window * 2000))

    def drop_rule(self, v6=False):
        return "-m set --match-set %s src -j DROP" % (SET_BLACK6 if v6 else SET_BLACK)

    def flush_ours(self):
        """删掉本应用在 INPUT 上的全部规则（含旧版本、含 v6），保证重下发幂等。"""
        for cmd in ([IPT] + ([IP6T] if self.v6 else [])):
            rc, out = sh("%s -S INPUT" % cmd)
            if rc != 0:
                continue
            for line in out.splitlines():
                if not line.startswith("-A "):
                    continue
                if "hfish_guard_" not in line and "hashlimit-name hg" not in line:
                    continue
                try:
                    parts = shlex.split(line)
                except ValueError:
                    continue
                parts[0] = "-D"
                sh("%s %s 2>/dev/null" % (cmd, " ".join(parts)))

    def apply_traps(self, ports, prev_ports=(), threshold=40, window=60,
                    mode="observe", udp=True):
        self.ensure_sets(ports)
        for p in prev_ports:
            if p not in ports:
                self.destroy_set(p)
        self.flush_ours()
        target = SET_BLACK if mode == "enforce" else SET_ALERT
        target6 = SET_BLACK6 if mode == "enforce" else SET_ALERT6
        for p in ports:
            specs = [(IPT, self.seen_rule(p), "tcp4"),
                     (IPT, self.hlimit_rule(p, threshold, window, target), "tcp4")]
            if mode == "enforce":
                specs.append((IPT, self.hlimit_drop(p, threshold, window), "tcp4"))
            if udp:
                specs.append((IPT, self.seen_rule(p, False, "udp"), "udp4"))
                specs.append((IPT, self.hlimit_rule(p, threshold, window, target,
                                                    False, "udp"), "udp4"))
            if self.v6:
                specs.append((IP6T, self.seen_rule(p, True), "tcp6"))
                specs.append((IP6T, self.hlimit_rule(p, threshold, window, target6,
                                                     True), "tcp6"))
                if mode == "enforce":
                    specs.append((IP6T, self.hlimit_drop(p, threshold, window, True), "tcp6"))
                if udp:
                    specs.append((IP6T, self.seen_rule(p, True, "udp"), "udp6"))
                    specs.append((IP6T, self.hlimit_rule(p, threshold, window, target6,
                                                         True, "udp"), "udp6"))
            for cmd, spec, tag in specs:
                rc, out = sh("%s -I INPUT %s" % (cmd, spec))
                if rc != 0:                   # 规则没挂上就等于没防护，必须可见
                    log("下发 %s 规则失败（端口 %s）：%s"
                        % (tag, p, (out or "").strip()[:160]), "error")
        # 黑名单 DROP 永远压在最前面
        sh("%s -I INPUT 1 %s" % (IPT, self.drop_rule()))
        if self.v6:
            sh("%s -I INPUT 1 %s" % (IP6T, self.drop_rule(True)))

    def trap_present(self, ports):
        if not ports:
            return False
        rc, out = sh("%s -S INPUT" % IPT)
        if rc != 0:
            return False
        if not all(("hfish_guard_seen_%s " % p) in out for p in ports):
            return False
        if self.v6:
            rc6, out6 = sh("%s -S INPUT" % IP6T)
            if rc6 == 0 and not all(("%s " % set_name(p, True)) in out6 for p in ports):
                return False
        return True

    # -- 读计数：每条端口规则自己的包计数器（-x 精确值），v4+v6 求和
    def port_counters(self, ports):
        result = {}
        for cmd in ([IPT] + ([IP6T] if self.v6 else [])):
            rc, out = sh("%s -vnxL INPUT" % cmd)
            if rc != 0:
                continue
            for line in out.splitlines():
                m = re.search(r"add-set (hfish_guard_seen(?:_6)?_\d+) src", line)
                if not m:
                    continue
                port = m.group(1).rsplit("_", 1)[-1]
                parts = line.split()
                try:
                    result[port] = result.get(port, 0) + int(parts[0])
                except (IndexError, ValueError):
                    continue
        return result

    def stats(self):
        """给 /api/status 用的规则统计。"""
        out = {"v6": self.v6, "v6_reason": self.v6_reason, "rules": {}}
        for name, cmd in (("v4", IPT), ("v6", IP6T)):
            if name == "v6" and not self.v6:
                continue
            rc, txt = sh("%s -S INPUT" % cmd)
            if rc == 0:
                out["rules"][name] = sum(1 for line in txt.splitlines()
                                         if "hfish_guard_" in line)
        return out


class FakeKernel:
    """内存态内核：没有 ipset/iptables 也能跑通整条判定链路（本地联调 / 单测）。

    行为与 RealKernel 对齐：按 (端口, 源 IP) 累计包数，超过阈值就写命中池
    （enforce 写 black，observe 写 alert），白名单与已封禁源不计数。
    """

    kind = "fake"
    available = True
    reason = ""
    v6 = False                  # 内存模拟不区分地址族
    v6_reason = "fake 内核不模拟 IPv6"

    def __init__(self):
        self._lock = threading.Lock()
        self.seen = {}          # port -> {ip: 1}
        self.traffic = {}       # port -> 累计包数（等价于规则计数器）
        self.hits = {}          # (port, ip) -> 窗口内包数
        self.white = set()
        self.white_net = Whitelist([])
        self.black = set()
        self.alert = set()
        self.traps = set()
        self.threshold = 40
        self.window = 60
        self.mode = "observe"

    # -- 用于模拟器 / 自测注入
    def hit(self, ip, port, packets=1):
        with self._lock:
            if ip in self.white_net or ip in self.black:
                return False
            p = str(port)
            packets = max(1, int(packets))
            self.seen.setdefault(p, {})[ip] = 1
            self.traffic[p] = self.traffic.get(p, 0) + packets
            key = (p, ip)
            self.hits[key] = self.hits.get(key, 0) + packets
            if self.hits[key] > self.threshold:
                (self.black if self.mode == "enforce" else self.alert).add(ip)
            return True

    def ensure_sets(self, ports):
        with self._lock:
            for p in ports:
                self.seen.setdefault(str(p), {})
                self.traffic.setdefault(str(p), 0)

    def members(self, port):
        with self._lock:
            return {ip: 0 for ip in self.seen.get(str(port), {})}

    def del_member(self, port, ip):
        with self._lock:
            self.seen.get(str(port), {}).pop(ip, None)

    def destroy_set(self, port):
        with self._lock:
            self.seen.pop(str(port), None)
            self.traffic.pop(str(port), None)
            self.hits = {k: v for k, v in self.hits.items() if k[0] != str(port)}

    def add_black(self, ip):
        with self._lock:
            self.black.add(ip)
        return True

    def del_black(self, ip):
        with self._lock:
            self.black.discard(ip)

    def black_members(self):
        with self._lock:
            return set(self.black)

    def alert_members(self):
        with self._lock:
            return set(self.alert)

    def del_alert(self, ip):
        with self._lock:
            self.alert.discard(ip)
        return True

    def sync_whitelist(self, entries):
        with self._lock:
            self.white = set(e.get("cidr") if isinstance(e, dict) else e for e in entries)
            self.white_net = Whitelist(entries)

    def apply_traps(self, ports, prev_ports=(), threshold=40, window=60,
                    mode="observe", udp=True):
        with self._lock:
            self.udp = bool(udp)
            self.threshold = max(1, int(threshold))
            self.window = max(5, int(window))
            self.mode = mode if mode in ("observe", "enforce") else "observe"
            for p in prev_ports:
                if p not in ports:
                    self.seen.pop(str(p), None)
                    self.traffic.pop(str(p), None)
            for p in ports:
                self.seen.setdefault(str(p), {})
                self.traffic.setdefault(str(p), 0)
            self.traps = set(str(p) for p in ports)
            self.hits = {}

    def trap_present(self, ports):
        return bool(ports) and all(str(p) in self.traps for p in ports)

    def port_counters(self, ports):
        with self._lock:
            return {str(p): int(self.traffic.get(str(p), 0)) for p in ports}

    def stats(self):
        return {"v6": False, "v6_reason": self.v6_reason,
                "rules": {"v4": len(self.traps) * 2}}


# --------------------------------------------------------------------- 存储层
class Store:
    def __init__(self):
        os.makedirs(BASE_DIR, exist_ok=True)
        self.lock = threading.Lock()
        if not os.path.exists(CFG_PATH):
            cfg = dict(DEFAULT_CONFIG)
            cfg["token"] = "hg-" + secrets.token_hex(12)
            self._write_cfg(cfg)
        self.cfg = self._load_cfg()
        if not self.cfg.get("token"):
            self.cfg["token"] = "hg-" + secrets.token_hex(12)
            self._write_cfg(self.cfg)
        self.db = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
        self.db.row_factory = None
        with self.db:
            self.db.execute("""CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip TEXT,
                port INTEGER, packets INTEGER, verdict TEXT, action TEXT, detail TEXT)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS blocks(
                ip TEXT PRIMARY KEY, ts INTEGER, expire INTEGER, port INTEGER,
                packets INTEGER, ttl INTEGER, reason TEXT, active INTEGER DEFAULT 1)""")
            self.db.execute("CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT)")
            self._migrate_db()
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC)")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip)")

    def _migrate_db(self):
        """把旧版本（v1.0.0 及更早）的库结构补齐到当前版本。

        v1.0.0 的两张表字段完全不同：
            events(id, ts, ip, hits, action, detail)
            blocks(ip, ts, expire, reason, hits, active)
        直接升级会让所有查询报 "no such column: port" 把进程崩掉，
        所以这里按缺失列补齐，并把旧列 hits 的数值搬到 packets。
        """
        want = {
            "events": [("port", "INTEGER DEFAULT 0"), ("packets", "INTEGER DEFAULT 0"),
                       ("verdict", "TEXT DEFAULT ''"), ("action", "TEXT DEFAULT ''"),
                       ("detail", "TEXT DEFAULT ''"), ("ts", "INTEGER DEFAULT 0")],
            "blocks": [("ts", "INTEGER DEFAULT 0"), ("expire", "INTEGER DEFAULT 0"),
                       ("port", "INTEGER DEFAULT 0"), ("packets", "INTEGER DEFAULT 0"),
                       ("ttl", "INTEGER DEFAULT 0"), ("reason", "TEXT DEFAULT ''"),
                       ("active", "INTEGER DEFAULT 1")],
        }
        for table, cols in want.items():
            try:
                have = {row[1] for row in self.db.execute("PRAGMA table_info(%s)" % table)}
            except sqlite3.Error as e:
                log("探查表结构失败 %s：%r" % (table, e), "warn")
                continue
            if not have:
                continue
            added = []
            for name, decl in cols:
                if name in have:
                    continue
                try:
                    self.db.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, name, decl))
                    added.append(name)
                except sqlite3.Error as e:
                    log("补列失败 %s.%s：%r" % (table, name, e), "warn")
            # 旧列名 hits 等价于现在的 packets
            if "hits" in have and "packets" in added:
                try:
                    self.db.execute("UPDATE %s SET packets=COALESCE(hits,0)" % table)
                except sqlite3.Error:
                    pass
            if added:
                log("数据库结构已升级：%s 新增列 %s" % (table, ",".join(added)), "warn")

    # -- 配置
    def _write_cfg(self, cfg):
        tmp = CFG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CFG_PATH)
        try:
            os.chmod(CFG_PATH, 0o600)
        except OSError:
            pass

    def _load_cfg(self):
        try:
            with open(CFG_PATH, encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:                            # noqa: BLE001
            log("读取配置失败，使用默认值：%r" % e, "warn")
            raw = {}
        cfg = dict(DEFAULT_CONFIG)
        cfg.update({k: v for k, v in raw.items() if k in cfg})
        cfg["ports"] = normalize_ports(cfg["ports"])
        cfg["whitelist"] = normalize_whitelist(cfg["whitelist"])
        cfg["hfish"] = normalize_hfish(cfg.get("hfish"))
        # 旧版（v1.0.0 UI）把封禁模式写成 "block"，升级时必须迁移，
        # 否则会被静默降级成 observe，用户的封禁设置悄悄失效
        cfg["mode"] = LEGACY_MODE.get(str(cfg.get("mode") or "").strip().lower(),
                                      cfg.get("mode"))
        if cfg["mode"] not in ("observe", "enforce"):
            cfg["mode"] = "observe"
        cfg["udp"] = _truthy(cfg.get("udp"), True)
        cfg["scan_block"] = _truthy(cfg.get("scan_block"), True)
        try:
            cfg["scan_ports"] = max(0, min(64, int(cfg.get("scan_ports"))))
        except (TypeError, ValueError):
            cfg["scan_ports"] = DEFAULT_CONFIG["scan_ports"]
        return cfg

    def save_cfg(self):
        with self.lock:
            self._write_cfg(self.cfg)

    def apply_patch(self, body):
        """热更新配置；返回规范化后的配置。非法值保持原值。"""
        cfg = self.cfg
        if "ports" in body:
            ports = normalize_ports(body["ports"])
            if ports:
                cfg["ports"] = ports
        if "whitelist" in body:
            cfg["whitelist"] = normalize_whitelist(body["whitelist"])
        for key, lo, hi in (("threshold", 1, 1000000), ("window", 5, 86400),
                            ("poll", 1, 3600), ("ttl", 0, 31536000)):
            if key in body:
                try:
                    val = int(body[key])
                except (TypeError, ValueError):
                    continue
                if lo <= val <= hi:
                    cfg[key] = val
        if "udp" in body:
            cfg["udp"] = _truthy(body.get("udp"), cfg.get("udp", True))
        if "scan_block" in body:
            cfg["scan_block"] = _truthy(body.get("scan_block"), cfg.get("scan_block", True))
        if "scan_ports" in body:
            try:
                val = int(body["scan_ports"])
                if 0 <= val <= 64:
                    cfg["scan_ports"] = val
            except (TypeError, ValueError):
                pass
        want = LEGACY_MODE.get(str(body.get("mode") or "").strip().lower(),
                               body.get("mode"))
        if want in ("observe", "enforce"):
            cfg["mode"] = want
        if isinstance(body.get("hfish"), dict):
            merged = dict(cfg.get("hfish") or {})
            merged.update(body["hfish"])
            cfg["hfish"] = normalize_hfish(merged)
        self.save_cfg()
        return cfg

    # -- 事件 / 黑名单
    def event(self, ip, port, packets, verdict, action, detail=""):
        with self.lock:
            with self.db:
                self.db.execute(
                    "INSERT INTO events(ts, ip, port, packets, verdict, action, detail) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (int(time.time()), ip, int(port or 0), int(packets or 0), verdict, action, detail))

    def events(self, limit=200):
        with self.lock:
            return self.db.execute(
                "SELECT id, ts, ip, port, packets, verdict, action, detail FROM events "
                "WHERE verdict NOT IN ('config','system','token','error') "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def events_count(self, verdict="over"):
        with self.lock:
            row = self.db.execute("SELECT COUNT(*) FROM events WHERE verdict=?", (verdict,)).fetchone()
            return row[0] if row else 0

    def prune(self, keep=20000):
        with self.lock:
            with self.db:
                self.db.execute(
                    "DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?", (keep,))

    def add_block(self, ip, port, packets, ttl, reason):
        ttl = int(ttl if ttl is not None else self.cfg.get("ttl", 3600))
        now = int(time.time())
        expire = 0 if ttl <= 0 else now + ttl
        with self.lock:
            with self.db:
                self.db.execute(
                    "INSERT INTO blocks(ip, ts, expire, port, packets, ttl, reason, active) "
                    "VALUES(?,?,?,?,?,?,?,1) "
                    "ON CONFLICT(ip) DO UPDATE SET ts=excluded.ts, expire=excluded.expire, "
                    "port=excluded.port, packets=excluded.packets, ttl=excluded.ttl, "
                    "reason=excluded.reason, active=1",
                    (ip, now, expire, int(port or 0), int(packets or 0), ttl, reason))

    def unblock(self, ip):
        with self.lock:
            with self.db:
                self.db.execute("UPDATE blocks SET active=0 WHERE ip=?", (ip,))

    def active_blocks(self):
        with self.lock:
            return self.db.execute(
                "SELECT ip, ts, expire, port, packets, ttl, reason FROM blocks "
                "WHERE active=1 ORDER BY ts DESC").fetchall()

    def kv_get(self, key, default=None):
        with self.lock:
            row = self.db.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def kv_set(self, key, value):
        with self.lock:
            with self.db:
                self.db.execute(
                    "INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    (key, json.dumps(value)))


def normalize_ports(raw):
    if isinstance(raw, str):
        raw = re.split(r"[,\s]+", raw)
    out = []
    for item in raw or []:
        s = str(item).strip()
        if s.isdigit() and 1 <= int(s) <= 65535:
            p = int(s)
            if p not in out:
                out.append(p)
    return out


def normalize_whitelist(raw):
    out = []
    for item in raw or []:
        if isinstance(item, str):
            cidr, note, at = item.strip(), "", int(time.time())
        elif isinstance(item, dict) and item.get("cidr"):
            cidr = str(item["cidr"]).strip()
            note = item.get("note") or ""
            at = int(item.get("at") or time.time())
        else:
            continue
        if not valid_cidr(cidr):
            continue
        out.append({"cidr": cidr, "note": note, "at": at})
    return out


LEVEL_RANK = {"": 0, "low": 1, "mid": 2, "medium": 2, "high": 3, "critical": 4,
              "低": 1, "中": 2, "高": 3, "严重": 4}


def normalize_hfish(raw):
    """HFish 联动配置的合并与校验：非法值回落默认，不抛异常。"""
    base = dict(DEFAULT_CONFIG["hfish"])
    if isinstance(raw, dict):
        for k, v in raw.items():
            if k not in base:
                continue
            if k in ("enabled", "verify_tls"):
                base[k] = bool(v)
            elif k == "syslog_port":
                try:
                    port = int(v)
                    if 1 <= port <= 65535:
                        base[k] = port
                except (TypeError, ValueError):
                    pass
            elif k == "auto_block_level":
                lv = str(v or "").strip().lower()
                base[k] = lv if lv in ("low", "mid", "medium", "high", "critical") else ""
            else:
                base[k] = str(v or "").strip()
    return base


# --------------------------------------------------------------------- 归属地
class Geo:
    """归属地解析：geo.json 自定义表 > MaxMind mmdb > 内置粗粒度表。

    mmdb 需要 geoip2 包与数据库文件；两者缺一不会报错，只是精度下降，
    响应里用 source 字段标明结果来源（custom / mmdb / approx / private / none）。
    """

    MMDB_CANDIDATES = (
        os.path.join(BASE_DIR, "GeoLite2-City.mmdb"),
        "/usr/share/GeoIP/GeoLite2-City.mmdb",
        "/var/lib/GeoIP/GeoLite2-City.mmdb",
    )

    def __init__(self):
        self.custom = {}
        try:
            with open(GEO_PATH, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.custom = data
        except FileNotFoundError:
            pass
        except Exception as e:                            # noqa: BLE001
            log("geo.json 解析失败：%r" % e, "warn")
        self.reader = None
        self.mmdb_path = ""
        for path in self.MMDB_CANDIDATES:
            if os.path.exists(path):
                try:
                    import geoip2.database                     # type: ignore
                    self.reader = geoip2.database.Reader(path)
                    self.mmdb_path = path
                    break
                except Exception as e:                         # noqa: BLE001
                    log("mmdb 加载失败（%s）：%r" % (path, e), "warn")
        self.cache = {}

    def source(self):
        if self.reader:
            return "mmdb"
        if self.custom:
            return "custom"
        return "approx"

    def lookup(self, ip):
        ip = (ip or "").split("/")[0].strip()
        if not valid_ip(ip):
            return {"ip": ip, "cc": "--", "cn": "未知", "city": "-",
                    "lat": None, "lon": None, "org": "-", "source": "none"}
        if ip in self.cache:
            return self.cache[ip]
        result = self._lookup(ip)
        if len(self.cache) > 4096:
            self.cache.clear()
        self.cache[ip] = result
        return result

    def _lookup(self, ip):
        if ip in self.custom:
            c = self.custom[ip]
            return {"ip": ip, "cc": c.get("cc", "--"), "cn": c.get("cn", "未知"),
                    "city": c.get("city", "-"), "lat": c.get("lat"), "lon": c.get("lon"),
                    "org": c.get("org", "-"), "source": "custom"}
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return {"ip": ip, "cc": "LAN", "cn": "内网地址", "city": "RFC1918",
                        "lat": None, "lon": None, "org": "私有网段 · 不投影", "source": "private"}
            if addr.is_reserved or addr.is_multicast:
                return {"ip": ip, "cc": "RSV", "cn": "保留地址", "city": "-",
                        "lat": None, "lon": None, "org": "非公网", "source": "private"}
        except ValueError:
            pass
        if self.reader:
            try:
                rec = self.reader.city(ip)
                return {"ip": ip,
                        "cc": rec.country.iso_code or "--",
                        "cn": rec.country.names.get("zh-CN") or rec.country.name or "未知",
                        "city": (rec.city.names.get("zh-CN") or rec.city.name or "-") if rec.city else "-",
                        "lat": rec.location.latitude, "lon": rec.location.longitude,
                        "org": "mmdb", "source": "mmdb"}
            except Exception:                                # noqa: BLE001
                pass
        for prefix, cc, cn, city, lat, lon in GEO_APPROX:
            if ip.startswith(prefix):
                return {"ip": ip, "cc": cc, "cn": cn, "city": city, "lat": lat,
                        "lon": lon, "org": "网段推算", "source": "approx", "approx": True}
        return {"ip": ip, "cc": "--", "cn": "未收录", "city": "-", "lat": None,
                "lon": None, "org": "未知", "source": "none"}


# --------------------------------------------------------------------- HFish 联动
# 官方文档：https://hfish.net/#/api-config 、 https://hfish.net/#/syslog 、 https://hfish.net/#/detail-alarm
# HFish 对外只有三种出口，且都是「读」或「推」，没有封禁写接口：
#   1) 开放 API   POST /api/v1/attack/ip?api_key=…  取攻击来源/详情（拉）
#   2) syslog     TCP/UDP，最多 5 路，字段见官方 syslog 表（推）
#   3) webhook    钉钉/飞书/企微/自定义（推）
# 守卫消费 2)/3) 做事件富化与可选的按等级封禁，消费 1) 做情报补充；
# 判定与封禁仍然走内核计数，因为 HFish 不知道"没被它记录的端口触碰"。

def _pick(data, *keys):
    for k in keys:
        v = data.get(k)
        if v not in (None, "", "N/A", "n/a", "N/a"):
            return v
    return ""


def _strip_syslog_header(text):
    """去掉 RFC3164/5424 头：<pri>时间 主机 应用[pid]: 正文。"""
    body = re.sub(r"^<\d{1,3}>", "", str(text or "").strip())
    # 例：2026-11-06T08:12:44+08:00 fnOS HFish[942440]: {...}
    body = re.sub(r"^\S+\s+\S+\s+[^:\s]+\s+", "", body, count=1)
    return body.strip()


def parse_hfish_payload(raw):
    """把 syslog 行或 webhook JSON 归一成事件字段；容忍 JSON / key:value / 纯文本三种形态。"""
    data, text = {}, ""
    if isinstance(raw, dict):
        data = raw
    else:
        text = str(raw or "").strip()
        if not text:
            return {}
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                data = obj
        except ValueError:
            data = {}
    if not data:
        # HFish 走标准 syslog 通道时，正文前面带 RFC3164/5424 头：
        #   <4>2026-11-06T08:12:44+08:00 fnOS HFish[942440]: {"src_ip":"...", ...}
        # 必须先剥掉，否则后面的 key:value 正则会把时间戳 "T08:12:44" 当成字段，
        # 字典被写脏后就再也取不到 src_ip —— 真机上表现为「全量 skipped」。
        body = _strip_syslog_header(text)
        m = re.search(r"\{.*\}", body, re.S)
        if m:
            try:
                obj = json.loads(m.group(0))
                if isinstance(obj, dict):
                    data = obj
            except ValueError:
                data = {}
    if not data:
        # HFish 自定义 webhook / 老格式：client: node1, src_ip: 1.2.3.4, ...
        for m in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*("([^"]*)"|[^,;\n]+)',
                             _strip_syslog_header(text)):
            data[m.group(1)] = (m.group(3) if m.group(3) is not None else m.group(2)).strip().strip('"')
        if not data:
            m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
            if not m:
                return {}
            data = {"src_ip": m.group(1), "info": text[:300]}
    # 自定义 webhook 可能把事件塞在 data / content / event 里
    for nest in ("data", "content", "event", "events"):
        if isinstance(data.get(nest), dict):
            data = data[nest]
            break
    ip = str(_pick(data, "src_ip", "attack_ip", "source_ip", "remote_ip", "ip") or "").strip()
    port_raw = str(_pick(data, "scan_port", "dst_port", "port") or "").split("/")[0].strip()
    try:
        port = int(port_raw)
    except ValueError:
        port = 0
    return {
        "ip": ip,
        "port": port,
        "attack_type": str(_pick(data, "attack_type", "type") or ""),
        "pot": str(_pick(data, "class", "pot", "service") or ""),
        "client": str(_pick(data, "client", "client_ip", "node") or ""),
        "account": str(_pick(data, "account", "user") or ""),
        "level": str(_pick(data, "threat_level", "level") or "").lower(),
        "threat": str(_pick(data, "threat_name", "labels") or ""),
        "geo": str(_pick(data, "geo", "location") or ""),
        "count": int(str(_pick(data, "count", "times", "attack_count") or 0).strip() or 0)
        if str(_pick(data, "count", "times", "attack_count") or "0").strip().isdigit() else 0,
        "info": str(_pick(data, "info", "detail") or "")[:300],
    }


class Ingest:
    """HFish 告警接入：去重、可选按等级封禁、落库。"""

    def __init__(self, store, monitor):
        self.store = store
        self.monitor = monitor
        self.lock = threading.Lock()
        self.seen = {}
        self.counts = {"syslog": 0, "webhook": 0, "skipped": 0, "last": 0}
        self.last_bad_log = 0.0
        self.last_raw = ""          # 最近一条解析失败的原始报文（排查格式用）

    def push(self, payload, via="syslog"):
        data = parse_hfish_payload(payload)
        ip = data.get("ip") or ""
        if not valid_ip(ip):
            with self.lock:
                self.counts["skipped"] += 1
                self.counts["last_raw"] = str(payload)[:400]
                now = time.time()
                noisy = now - self.last_bad_log > 60
                if noisy:
                    self.last_bad_log = now
            if noisy:   # 每分钟只打一条，免得把 journald 刷爆
                log("syslog 无法解析（缺 src_ip），原样：%r" % (str(payload)[:300],), "warn")
            return None
        cfg = self.store.cfg
        # 扫描感知的噪声：HFish 把「扫描感知」传感器端口上的广播/组播也算成 scan 告警，
        # 真机上 11 万条里绝大多数是同网段 IPv6 的 mDNS/SSDP/BT 流量，不是打蜜罐的。
        # 判定：attack_type=scan 且目标端口不在我们监视的蜜罐端口列表里 → 丢弃。
        if data.get("attack_type") == "scan":
            try:
                watched = set(int(p) for p in cfg.get("ports", []))
            except (TypeError, ValueError):
                watched = set()
            if data.get("port") and int(data["port"]) not in watched:
                with self.lock:
                    self.counts["skipped"] += 1
                    self.counts["noise"] = self.counts.get("noise", 0) + 1
                return None
        if ip in Whitelist(cfg.get("whitelist", [])):
            with self.lock:
                self.counts["skipped"] += 1
            return None
        # 同一 (IP, 攻击类型, 蜜罐) 60s 内只记一条，挡住告警洪水
        key = (ip, data.get("attack_type"), data.get("pot"))
        now = time.time()
        with self.lock:
            if now - self.seen.get(key, 0) < 60:
                self.counts["skipped"] += 1
                return None
            self.seen[key] = now
            if len(self.seen) > 4000:
                self.seen = {k: v for k, v in self.seen.items() if now - v < 60}
            if via in self.counts:
                self.counts[via] += 1
            self.counts["last"] = int(now)

        hf = cfg.get("hfish", {})
        need = hf.get("auto_block_level") or ""
        level = data.get("level") or ""
        action = "蜜罐告警"
        if need and LEVEL_RANK.get(level, 0) >= LEVEL_RANK.get(need, 99) and cfg.get("mode") == "enforce":
            self.monitor.kernel.add_black(ip)
            self.store.add_block(ip, data.get("port") or 0, data.get("count") or 0,
                                 cfg.get("ttl", 3600), "HFish %s 级告警" % (level or "high"))
            self.monitor.forget(ip)
            action = "自动封禁（HFish 告警）"
            log("HFish 高危告警，封禁 %s（%s / %s）" % (ip, data.get("attack_type"), data.get("pot")), "warn")

        detail = " · ".join(x for x in (
            ("类型 " + data["attack_type"]) if data.get("attack_type") else "",
            ("蜜罐 " + data["pot"]) if data.get("pot") else "",
            ("账号 " + data["account"]) if data.get("account") else "",
            ("等级 " + level) if level else "",
            ("来源 " + via)) if x)
        self.store.event(ip, data.get("port") or 0, data.get("count") or 0, "hfish", action, detail)
        return {"ip": ip, "action": action, "detail": detail}


class SyslogReceiver(threading.Thread):
    """同时监听 UDP 与 TCP 的 syslog 端口：HFish 告警策略里两种协议都支持。"""

    def __init__(self, port, ingest):
        super().__init__(daemon=True)
        self.port = int(port)
        self.ingest = ingest
        self.bound = {"udp": False, "tcp": False}
        self.stop_flag = threading.Event()
        self._socks = []

    def stop(self):
        """停接收器：置标志并关掉套接字，让阻塞中的 recvfrom/accept 立刻返回。"""
        self.stop_flag.set()
        while self._socks:
            sock = self._socks.pop()
            try:
                sock.close()
            except OSError:
                pass

    def run(self):
        threading.Thread(target=self._udp, daemon=True).start()
        self._tcp()

    def _udp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", self.port))
        except OSError as e:
            log("syslog UDP 绑定 :%d 失败：%s" % (self.port, e), "warn")
            return
        self._socks.append(sock)
        self.bound["udp"] = True
        sock.settimeout(1.0)
        while not self.stop_flag.is_set():
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.ingest.push(data.decode("utf-8", "replace"), "syslog")
            except Exception as e:                     # noqa: BLE001
                log("syslog 解析失败：%r" % e, "warn")

    def _tcp(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", self.port))
            srv.listen(8)
        except OSError as e:
            log("syslog TCP 绑定 :%d 失败：%s" % (self.port, e), "warn")
            return
        self._socks.append(srv)
        self.bound["tcp"] = True
        srv.settimeout(1.0)
        while not self.stop_flag.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._conn, args=(conn,), daemon=True).start()

    def _conn(self, conn):
        conn.settimeout(60)
        buf = b""
        try:
            while not self.stop_flag.is_set():
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._line(line)
        except OSError:
            pass
        finally:
            try:
                if buf.strip():
                    self._line(buf)
                conn.close()
            except OSError:
                pass

    def _line(self, raw):
        text = raw.decode("utf-8", "replace").strip()
        m = re.match(r"^(\d{1,6})\s(\{.*)$", text, re.S)     # RFC6587 八位组计数帧
        if m:
            text = m.group(2)[: int(m.group(1))]
        if text:
            try:
                self.ingest.push(text, "syslog")
            except Exception as e:                     # noqa: BLE001
                log("syslog 行解析失败：%r" % e, "warn")


class HfishApi(threading.Thread):
    """按官方开放 API 拉攻击来源，只做情报补充，不参与阈值判定。

    接口：POST {base}/api/v1/attack/ip?api_key=…（HFish 3.3.x）
    自签证书场景默认不校验证书；返回结构在不同版本略有差异，这里做兼容解析。
    """

    def __init__(self, store):
        super().__init__(daemon=True)
        self.store = store
        self.stop_flag = threading.Event()
        self.ok = False
        self.error = ""
        self.last_pull = 0
        self.intel = {}

    def run(self):
        while not self.stop_flag.wait(60):
            try:
                self.pull()
            except Exception as e:                     # noqa: BLE001
                self.ok = False
                self.error = repr(e)[:160]

    def pull(self):
        hf = self.store.cfg.get("hfish", {})
        base, key = hf.get("api_base") or "", hf.get("api_key") or ""
        if not base or not key:
            return False
        url = base.rstrip("/") + "/api/v1/attack/ip?api_key=" + urllib.parse.quote(key)
        body = json.dumps({"start_time": 0, "end_time": 0, "intranet": 0,
                           "threat_label": []}).encode()
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            ctx = None
            if not hf.get("verify_tls", False):
                ctx = ssl._create_unverified_context()      # HFish 默认自签证书
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace") or "{}")
        except Exception as e:                         # noqa: BLE001
            self.ok = False
            self.error = repr(e)[:160]
            return False
        items = payload
        if isinstance(payload, dict):
            for k in ("data", "list", "items", "result"):
                if isinstance(payload.get(k), (list, dict)):
                    items = payload[k]
                    break
        if isinstance(items, dict):
            items = items.get("list") or items.get("items") or []
        intel = {}
        for row in items if isinstance(items, list) else []:
            if not isinstance(row, dict):
                continue
            ip = str(_pick(row, "src_ip", "attack_ip", "ip") or "")
            if not valid_ip(ip):
                continue
            intel[ip] = {
                "count": _pick(row, "count", "attack_count", "times") or 0,
                "labels": _pick(row, "threat_label", "labels") or [],
                "last": int(time.time()),
            }
        self.intel = dict(list(intel.items())[:500])
        self.ok = True
        self.error = ""
        self.last_pull = int(time.time())
        return True


# --------------------------------------------------------------------- 控制面
class Monitor:
    """控制面：读内核计数做流量统计，读命中池做事件记录与 TTL 处置。

    判定已下沉到内核（hashlimit），用户态不再算阈值——因为 ipset 的
    packets 计数器只在条目创建时记 1，靠它算增量在真机上永远拿不到真实包数。
    """

    def __init__(self, store, kernel, geo):
        self.store = store
        self.kernel = kernel
        self.geo = geo
        self.prev = {}              # port -> 上次规则包计数
        self.series = []            # [(ts, delta)] 最近若干次轮询的全局增量
        self.port_hits = {}         # port -> 本次启动以来累计
        self.ports_applied = []
        self.last_poll = 0
        self.last_expire = 0
        self.started_at = int(time.time())
        self.window = int(store.cfg.get("window", 60))
        self.poll_interval = int(store.cfg.get("poll", POLL_DEFAULT))
        self.last_error = ""
        self.alert_last = {}        # ip -> 上次记录观察事件的时间（去抖）
        self.scan_last = {}         # ip -> 上次记「端口扫描」事件的时间（去抖）
        self.recent_hits = []       # [(ts, ip)] 最近命中（供 top_src 用）
        self.whitelist = Whitelist(store.cfg.get("whitelist"))
        self.stats = {"polls": 0, "blocked": 0, "events": 0}

    # -- 规则下发
    def apply_all(self):
        cfg = self.store.cfg
        ports = [str(p) for p in cfg["ports"]]
        self.reload_runtime()
        self.kernel.ensure_sets(ports)
        self.kernel.sync_whitelist(cfg["whitelist"])
        self.kernel.apply_traps(ports, self.ports_applied,
                                threshold=int(cfg.get("threshold", 40)),
                                window=self.window, mode=cfg.get("mode", "observe"),
                                udp=bool(cfg.get("udp", True)))
        self.ports_applied = list(ports)
        # 重启后把仍有效的封禁写回内核（幂等），并作为基线避免重复出事件
        for row in self.store.active_blocks():
            self.kernel.add_black(row[0])

    def reload_runtime(self):
        cfg = self.store.cfg
        self.window = max(5, int(cfg.get("window", 60)))
        self.poll_interval = max(1, int(cfg.get("poll", POLL_DEFAULT)))
        self.whitelist = Whitelist(cfg.get("whitelist"))

    # -- 单次轮询
    def poll_once(self):
        cfg = self.store.cfg
        ports = [str(p) for p in cfg["ports"]]
        now = int(time.time())
        threshold = int(cfg.get("threshold", 40))
        self.last_poll = now
        self.stats["polls"] += 1

        counters = self.kernel.port_counters(ports) or {}
        total_delta, per_port = 0, {}
        for port in ports:
            cur = int(counters.get(port, 0))
            prev = self.prev.get(port)
            self.prev[port] = cur
            if prev is None:            # 首次见到，只做基线，不当作流量
                continue
            delta = cur - prev if cur >= prev else cur    # 规则被重下发后计数归零
            if delta <= 0:
                continue
            per_port[port] = delta
            total_delta += delta
            self.port_hits[port] = self.port_hits.get(port, 0) + delta

        self.series.append((now, total_delta))
        self.series = self.series[-240:]

        if total_delta:
            self.store.kv_set("total_packets",
                              int(self.store.kv_get("total_packets", 0)) + total_delta)
            totals = self.store.kv_get("port_totals", {})
            last = self.store.kv_get("port_last", {})
            for port, delta in per_port.items():
                totals[port] = int(totals.get(port, 0)) + delta
                last[port] = now
            self.store.kv_set("port_totals", totals)
            self.store.kv_set("port_last", last)

        self.collect_blocks(now, threshold)
        self.collect_alerts(now, threshold)
        self.detect_scans(now)
        self.expire_blocks(now)
        cut = now - self.window
        self.recent_hits = [h for h in self.recent_hits if h[0] >= cut][-200:]
        self.alert_last = {k: v for k, v in self.alert_last.items() if now - v < self.window}
        self.scan_last = {k: v for k, v in self.scan_last.items() if now - v < self.window}

    def port_map(self, ports):
        """IP -> 端口：靠 seen 集合归属，事件里显示「打了哪个端口」。"""
        out = {}
        for p in ports:
            try:
                for ip in (self.kernel.members(p) or {}):
                    out.setdefault(ip, int(p))
            except Exception:                                # noqa: BLE001
                continue
        return out

    # -- 内核已判定封禁的 IP：落库 + 记事件（TTL 由用户态管）
    def collect_blocks(self, now, threshold):
        cfg = self.store.cfg
        ttl = int(cfg.get("ttl", 3600))
        ports = [str(p) for p in cfg["ports"]]
        try:
            cur = self.kernel.black_members()
        except Exception:                                    # noqa: BLE001
            return
        known = self.blocked
        new = cur - known
        if not new:
            return
        port_of = self.port_map(ports)
        for ip in new:
            if ip in self.whitelist:
                self.kernel.del_black(ip)
                continue
            port = int(port_of.get(ip, 0) or 0)
            self.store.add_block(ip, port, threshold, ttl, "内核 hashlimit 判定")
            self.store.event(ip, port, threshold, "over", "自动封禁",
                             "内核判定 ≥%d 包/%ds（hashlimit）" % (threshold, self.window))
            self.stats["blocked"] += 1
            self.recent_hits.append((now, ip))
            log("封禁 %s（内核判定 ≥%d 包/%ds，端口 %s）" % (ip, threshold, self.window, port or "-"),
                "warn")

    # -- 观察模式：内核只写命中池，用户态取走记录后清掉，允许再次触发
    def collect_alerts(self, now, threshold):
        try:
            ips = self.kernel.alert_members()
        except Exception:                                    # noqa: BLE001
            return
        if not ips:
            return
        ports = [str(p) for p in self.store.cfg["ports"]]
        port_of = self.port_map(ports)
        for ip in ips:
            self.kernel.del_alert(ip)
            if ip in self.whitelist:
                continue
            if now - self.alert_last.get(ip, 0) < self.window:
                continue
            self.alert_last[ip] = now
            port = int(port_of.get(ip, 0) or 0)
            self.store.event(ip, port, threshold, "over", "观察记录",
                             "内核判定 ≥%d 包/%ds（hashlimit，仅记录）" % (threshold, self.window))
            self.stats["events"] += 1
            self.recent_hits.append((now, ip))
            log("命中阈值 %s（内核判定，端口 %s）观察模式仅记录" % (ip, port or "-"))

    # -- 端口扫描面：同一源在窗口内命中多少个不同蜜罐端口
    def detect_scans(self, now):
        cfg = self.store.cfg
        need = int(cfg.get("scan_ports", 0) or 0)
        if need <= 0:
            return
        ports = [str(p) for p in cfg["ports"]]
        touched = {}
        for p in ports:
            try:
                for ip in (self.kernel.members(p) or {}):
                    if ip in self.whitelist:
                        continue
                    touched.setdefault(ip, set()).add(int(p))
            except Exception:                                # noqa: BLE001
                continue
        if not touched:
            return
        mode = cfg.get("mode", "observe")
        block = bool(cfg.get("scan_block", True)) and mode == "enforce"
        ttl = int(cfg.get("ttl", 3600))
        for ip, hit_ports in touched.items():
            if len(hit_ports) < need:
                continue
            if now - self.scan_last.get(ip, 0) < self.window:
                continue
            self.scan_last[ip] = now
            detail = "命中 %d 个蜜罐端口：%s" % (
                len(hit_ports), ",".join(str(p) for p in sorted(hit_ports)[:10]))
            if block and ip not in self.blocked:
                self.kernel.add_black(ip)
                self.store.add_block(ip, 0, len(hit_ports), ttl, "端口扫描（%d 端口）" % len(hit_ports))
                self.store.event(ip, 0, len(hit_ports), "scan", "自动封禁（端口扫描）", detail)
                self.stats["blocked"] += 1
                self.recent_hits.append((now, ip))
                log("封禁 %s（端口扫描，%d 个端口）" % (ip, len(hit_ports)), "warn")
            else:
                self.store.event(ip, 0, len(hit_ports), "scan", "扫描探测", detail)
                self.stats["events"] += 1
                self.recent_hits.append((now, ip))
                log("检测到端口扫描 %s（%d 个端口）" % (ip, len(hit_ports)))

    def forget(self, ip):
        """外部（如 HFish 告警）处置后，清掉该 IP 的去抖状态。"""
        self.alert_last.pop(ip, None)

    # -- TTL 过期
    def expire_blocks(self, now):
        if now - self.last_expire < 15:
            return
        self.last_expire = now
        for ip, _ts, expire, port, packets, _ttl, _reason in self.store.active_blocks():
            if expire and expire <= now:
                self.kernel.del_black(ip)
                self.store.unblock(ip)
                self.store.event(ip, port, packets, "expired", "TTL 到期自动解封", "")
                log("自动解封 %s（TTL 到期）" % ip)

    # -- 对外快照
    @property
    def blocked(self):
        return set(row[0] for row in self.store.active_blocks())

    def window_series(self):
        return [[ts, delta] for ts, delta in self.series[-60:]]

    def window_sum(self):
        cut = int(time.time()) - self.window
        return sum(d for ts, d in self.series if ts >= cut)

    def top_src(self):
        cut = int(time.time()) - self.window
        if any(ts >= cut for ts, _ip in self.recent_hits):
            return int(self.store.cfg.get("threshold", 40))
        return max([d for ts, d in self.series if ts >= cut] or [0])


# --------------------------------------------------------------------- 模拟器
class Simulator(threading.Thread):
    """--fake 下的攻击流量发生器：让整条链路在没有内核的机器上也能跑起来。"""

    ATTACKERS = ("185.220.101.42", "45.155.205.17", "91.240.118.203", "103.144.137.9",
                 "194.26.29.88", "198.98.51.34", "23.129.64.118", "172.104.93.77",
                 "89.248.167.13", "5.188.206.204")

    def __init__(self, kernel, store, monitor):
        super().__init__(daemon=True)
        self.kernel = kernel
        self.store = store
        self.monitor = monitor
        self.stop_flag = threading.Event()
        self.burst_ip = ""

    def run(self):
        round_no = 0
        while not self.stop_flag.wait(1.5):
            round_no += 1
            ports = [str(p) for p in self.store.cfg["ports"]]
            if not ports:
                continue
            try:
                # 常态噪声：随机源打随机端口，少量包
                for _ in range(2):
                    ip = self.ATTACKERS[int(time.time() * 1000 + round_no) % len(self.ATTACKERS)]
                    self.kernel.hit(ip, ports[int(time.time() + round_no) % len(ports)], 1)
                # 每 5 轮造一次突发，足以跨过阈值
                if round_no % 5 == 0:
                    self.burst_ip = self.ATTACKERS[round_no // 5 % len(self.ATTACKERS)]
                    port = ports[round_no % len(ports)]
                    self.kernel.hit(self.burst_ip, port, 48)
                    log("模拟突发 %s → :%s 48 包" % (self.burst_ip, port), "debug")
                # 白名单源也来凑热闹：内核侧应当直接丢掉
                for entry in self.store.cfg.get("whitelist", []):
                    cidr = entry.get("cidr", "")
                    if "/" not in cidr and valid_ip(cidr):
                        self.kernel.hit(cidr, ports[0], 99)
            except Exception as e:                            # noqa: BLE001
                log("模拟器异常：%r" % e, "warn")


# --------------------------------------------------------------------- 接口面
class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class Handler(BaseHTTPRequestHandler):
    server_version = "HFishGuard/" + VERSION
    protocol_version = "HTTP/1.1"

    # -- 基础响应
    def log_message(self, fmt, *args):                    # 静默：由 log() 统一输出
        if VERBOSE:
            log("%s %s" % (self.address_string(), fmt % args), "debug")

    def _headers(self, code=200, ctype="application/json; charset=utf-8", length=0):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._headers(code, length=len(data))
        if self.command != "HEAD":
            self.wfile.write(data)

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        if length > 1 << 20:
            raise ApiError(413, "请求体过大")
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "请求体不是合法 JSON")
        return body if isinstance(body, dict) else {}

    # -- 鉴权
    def _token(self):
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        if auth:
            return auth.strip()
        query = urllib.parse.urlparse(self.path).query
        return (urllib.parse.parse_qs(query).get("token") or [""])[0]

    def _authorized(self):
        expected = STORE.cfg.get("token") or ""
        given = self._token()
        return bool(expected) and bool(given) and secrets.compare_digest(given, expected)

    def _require_auth(self):
        if not self._authorized():
            raise ApiError(401, "凭证无效或缺失")

    # -- 静态资源
    def _ui_dir(self):
        for d in UI_CANDIDATES:
            path = os.path.abspath(d)
            if os.path.isdir(path):
                return path
        return ""

    def _static(self, rel="index.html"):
        root = self._ui_dir()
        if not root:
            raise ApiError(404, "UI 目录不存在")
        target = os.path.abspath(os.path.join(root, rel))
        if not target.startswith(root + os.sep) and target != root:
            raise ApiError(403, "禁止越界访问")
        if not os.path.isfile(target):
            raise ApiError(404, "文件不存在")
        ext = os.path.splitext(target)[1].lower()
        ctype = {".html": "text/html; charset=utf-8",
                 ".css": "text/css; charset=utf-8",
                 ".js": "application/javascript; charset=utf-8",
                 ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml",
                 ".ico": "image/x-icon", ".json": "application/json; charset=utf-8"}.get(
                     ext, "application/octet-stream")
        with open(target, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # 升级后必须拿到新 UI：静态页不允许缓存（曾经因为浏览器缓存旧 HTML 导致新功能"消失"）
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # -- 路由
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        parsed = urllib.parse.urlparse(self.path)
        path = urllib.parse.unquote(parsed.path)
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if method == "GET":
                self._route_get(path, query)
            elif method in ("POST", "PUT"):
                self._route_write(method, path)
            else:
                self._route_delete(path)
        except ApiError as e:
            self._json({"error": e.message}, e.status)
        except BrokenPipeError:
            pass
        except Exception as e:                            # noqa: BLE001
            log("请求异常 %s %s：%r" % (method, path, e), "error")
            try:
                self._json({"error": "内部错误"}, 500)
            except Exception:                              # noqa: BLE001
                pass

    def _route_get(self, path, query=None):
        query = query or {}
        first = lambda k, d="": (query.get(k) or [d])[0]      # noqa: E731
        if path in ("/", "/web", "/web/", "/index.html"):
            self._static("index.html")
            return
        if path == "/favicon.ico":
            self._static("images/icon_64.png")
            return
        if path.startswith("/api/"):
            if path == "/api/health":
                self._json(health())
                return
            self._require_auth()
            if path == "/api/status":
                self._json(status())
            elif path == "/api/events":
                self._json(events(limit=first("limit", 500) or 500,
                                  verdict=first("filter", "all") or "all",
                                  q=first("q"), offset=first("offset", 0) or 0))
            elif path == "/api/blacklist":
                self._json(blacklist())
            elif path == "/api/whitelist":
                self._json(STORE.cfg.get("whitelist", []))
            elif path == "/api/config":
                self._json(public_config())
            elif path == "/api/geo":
                self._json(geo_lookup(ips=first("ips"), ip=first("ip")))
            elif path == "/api/ports":
                self._json(port_state())
            elif path == "/api/hfish/intel":
                api = HFISH.get("api")
                self._json({"ok": bool(api and api.ok), "error": api.error if api else "",
                            "last_pull": int(api.last_pull) if api else 0,
                            "items": api.intel if api else {}})
            else:
                raise ApiError(404, "未知接口")
            return
        # 静态资源（images/* 等）
        rel = path.lstrip("/")
        if rel and ".." not in rel:
            self._static(rel)
            return
        raise ApiError(404, "not found")

    def _route_write(self, method, path):
        # 自定义 webhook 是 HFish 主动推过来的，鉴权方式单独处理
        if path == "/api/hfish/webhook":
            self._webhook()
            return
        self._require_auth()
        body = self._read_body()
        if path == "/api/config":
            cfg = STORE.apply_patch(body)
            MONITOR.apply_all()
            hfish_reload()
            STORE.event("system", 0, 0, "config", "配置热加载",
                        "mode=%s threshold=%s window=%s ports=%d" % (
                            cfg["mode"], cfg["threshold"], cfg["window"], len(cfg["ports"])))
            self._json({"ok": True, "config": public_config()})
            return
        if path == "/api/blacklist":
            ip = (body.get("ip") or "").strip()
            if not valid_ip(ip):
                raise ApiError(400, "IP 不合法")
            ttl = body.get("ttl", STORE.cfg.get("ttl", 3600))
            try:
                ttl = int(ttl)
            except (TypeError, ValueError):
                ttl = int(STORE.cfg.get("ttl", 3600))
            MONITOR.kernel.add_black(ip)
            STORE.add_block(ip, int(body.get("port") or 0), int(body.get("packets") or 0), ttl,
                            body.get("reason") or "手动封禁")
            STORE.event(ip, int(body.get("port") or 0), 0, "manual", "手动封禁",
                        body.get("note") or "")
            self._json({"ok": True, "ip": ip, "ttl": ttl})
            return
        if path in ("/api/blacklist/delete", "/api/blacklist/unblock"):
            ip = (body.get("ip") or "").strip()
            if not valid_ip(ip):
                raise ApiError(400, "IP 不合法")
            MONITOR.kernel.del_black(ip)
            STORE.unblock(ip)
            STORE.event(ip, 0, 0, "manual", "手动解封", "")
            self._json({"ok": True})
            return
        if path == "/api/whitelist":
            cidr = (body.get("cidr") or "").strip()
            if not valid_cidr(cidr):
                raise ApiError(400, "CIDR 不合法")
            wl = STORE.cfg["whitelist"]
            if not any(w.get("cidr") == cidr for w in wl):
                wl.append({"cidr": cidr, "note": body.get("note") or "", "at": int(time.time())})
                STORE.save_cfg()
                MONITOR.apply_all()
            self._json({"ok": True, "whitelist": wl})
            return
        if path == "/api/whitelist/delete":
            cidr = (body.get("cidr") or "").strip()
            STORE.cfg["whitelist"] = [w for w in STORE.cfg["whitelist"] if w.get("cidr") != cidr]
            STORE.save_cfg()
            MONITOR.apply_all()
            self._json({"ok": True})
            return
        if path == "/api/token":
            tok = "hg-" + secrets.token_hex(12)
            STORE.cfg["token"] = tok
            STORE.save_cfg()
            STORE.event("system", 0, 0, "token", "接口凭证已重新生成", "")
            self._json({"ok": True, "token": tok})
            return
        if path == "/api/simulate":
            # 仅 fake 内核可用：注入一次攻击流量，方便自测与演示
            if not isinstance(MONITOR.kernel, FakeKernel):
                raise ApiError(400, "仅 --fake 模式支持流量注入")
            ip = (body.get("ip") or "").strip()
            if not valid_ip(ip):
                raise ApiError(400, "IP 不合法")
            port = int(body.get("port") or 0)
            packets = int(body.get("packets") or 1)
            ok = MONITOR.kernel.hit(ip, port, packets)
            self._json({"ok": ok, "injected": packets if ok else 0})
            return
        raise ApiError(404, "未知接口")

    def _webhook(self):
        """接收 HFish「告警策略 → webhook（自定义）」推来的威胁告警。"""
        hf = STORE.cfg.get("hfish", {})
        if not hf.get("enabled"):
            raise ApiError(403, "HFish 联动未启用")
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        given = (query.get("k") or query.get("token")
                 or [self.headers.get("X-Guard-Token") or ""])[0]
        secret = hf.get("webhook_token") or ""
        if secret:
            if not secrets.compare_digest(given, secret):
                raise ApiError(401, "webhook 校验串无效")
        elif not self._authorized():
            raise ApiError(401, "凭证无效或缺失")
        body = self._read_body()
        items = body.get("events") if isinstance(body.get("events"), list) else [body]
        ingest = HFISH.get("ingest")
        accepted = 0
        for item in items[:200]:
            if isinstance(item, dict) and ingest and ingest.push(item, "webhook"):
                accepted += 1
        self._json({"ok": True, "accepted": accepted, "received": len(items)})

    def _route_delete(self, path):
        self._require_auth()
        if path.startswith("/api/blacklist/"):
            # 路径里的 IPv6 字面量会被客户端百分号编码（2409%3A...），必须解码
            ip = urllib.parse.unquote(path[len("/api/blacklist/"):]).strip()
            if not valid_ip(ip):
                raise ApiError(400, "IP 不合法")
            MONITOR.kernel.del_black(ip)
            STORE.unblock(ip)
            STORE.event(ip, 0, 0, "manual", "手动解封", "")
            self._json({"ok": True})
            return
        if path.startswith("/api/whitelist/"):
            cidr = urllib.parse.unquote(path[len("/api/whitelist/"):]).strip()
            if not valid_cidr(cidr):
                raise ApiError(400, "CIDR 不合法")
            STORE.cfg["whitelist"] = [w for w in STORE.cfg["whitelist"] if w.get("cidr") != cidr]
            STORE.save_cfg()
            MONITOR.apply_all()
            self._json({"ok": True})
            return
        raise ApiError(404, "未知接口")


# --------------------------------------------------------------------- 快照函数
def public_config():
    cfg = dict(STORE.cfg)
    cfg["token_set"] = bool(cfg.get("token"))
    return cfg


def listening_ports():
    """从 /proc/net/tcp{,6} 读 LISTEN 端口；非 Linux 返回空集合。"""
    ports = set()
    for name in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(name, "r", encoding="utf-8") as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) < 4 or parts[3] != "0A":
                        continue
                    local = parts[1]
                    if ":" in local:
                        ports.add(int(local.rsplit(":", 1)[1], 16))
        except (OSError, ValueError):
            continue
    return ports


def hive_info():
    installed = any(os.path.isdir(d) for d in HIVE_DIRS)
    return {"installed": installed, "dirs": [d for d in HIVE_DIRS if os.path.isdir(d)]}


def hfish_reload():
    """按当前配置启停/重绑 HFish 通路：syslog 端口改了即时重绑，不用重启进程。"""
    hf = STORE.cfg.get("hfish", {})
    try:
        want_port = int(hf.get("syslog_port") or 0)
    except (TypeError, ValueError):
        want_port = 0
    if HFISH.get("ingest") is None:
        HFISH["ingest"] = Ingest(STORE, MONITOR)
    cur = HFISH.get("receiver")
    if hf.get("enabled") and want_port:
        if cur is None or cur.port != want_port or cur.stop_flag.is_set():
            if cur is not None:
                cur.stop()
            rec = SyslogReceiver(want_port, HFISH["ingest"])
            rec.start()
            HFISH["receiver"] = rec
            log("HFish syslog 接收器监听 :%d（UDP/TCP）" % want_port)
    elif cur is not None:
        cur.stop()
        HFISH["receiver"] = None
        log("HFish 联动已关闭，syslog 接收器停止")
    api = HFISH.get("api")
    if api is None:
        api = HFISH["api"] = HfishApi(STORE)
    if hf.get("api_key") and not api.is_alive():
        api.start()
        log("HFish 开放 API 情报同步已启动（每 60s 拉一次 /api/v1/attack/ip）")


def hfish_link():
    """HFish 联动状态快照，直接在 UI 的「联动」区域展示。"""
    hf = STORE.cfg.get("hfish", {})
    api = HFISH.get("api")
    rec = HFISH.get("receiver")
    ing = HFISH.get("ingest")
    return {
        "enabled": bool(hf.get("enabled")),
        "syslog_port": hf.get("syslog_port"),
        "syslog_bound": dict(rec.bound) if rec else {"udp": False, "tcp": False},
        "api_configured": bool(hf.get("api_base") and hf.get("api_key")),
        "api_ok": bool(api.ok) if api else False,
        "api_error": (api.error if api else ""),
        "last_pull": int(api.last_pull) if api else 0,
        "intel_count": len(api.intel) if api else 0,
        "auto_block_level": hf.get("auto_block_level") or "",
        "received": dict(ing.counts) if ing else {},
    }


def port_state():
    cfg = STORE.cfg
    listen = listening_ports()
    totals = STORE.kv_get("port_totals", {})
    last = STORE.kv_get("port_last", {})
    out = []
    for p in cfg["ports"]:
        key = str(p)
        out.append({
            "port": int(p),
            "listening": (int(p) in listen) if listen else None,
            "hits": int(totals.get(key, 0)),
            "live_hits": int(MONITOR.port_hits.get(key, 0)),
            "last": int(last.get(key, 0)) * 1000,
            "trapped": key in MONITOR.ports_applied,
        })
    return out


def health():
    return {
        "ok": True,
        "app": APP_NAME,
        "version": VERSION,
        "auth": True,
        "kernel": dict({"kind": MONITOR.kernel.kind, "available": MONITOR.kernel.available,
                        "reason": MONITOR.kernel.reason},
                       **MONITOR.kernel.stats()),
        "fake": FAKE,
        "time": int(time.time()),
    }


def status():
    cfg = STORE.cfg
    ports = port_state()
    return {
        "app": APP_NAME,
        "version": VERSION,
        "mode": cfg["mode"],
        "threshold": cfg["threshold"],
        "window": cfg["window"],
        "poll": cfg["poll"],
        "ttl": cfg["ttl"],
        "udp": bool(cfg.get("udp", True)),
        "scan_ports": int(cfg.get("scan_ports", 0) or 0),
        "scan_block": bool(cfg.get("scan_block", True)),
        "ports": cfg["ports"],
        "whitelist": cfg["whitelist"],
        "blacklist_count": len(STORE.active_blocks()),
        "events_count": STORE.events_count("over"),
        "trap": MONITOR.kernel.trap_present([str(p) for p in cfg["ports"]]),
        "kernel": dict({"kind": MONITOR.kernel.kind,
                        "available": MONITOR.kernel.available,
                        "reason": MONITOR.kernel.reason},
                       **MONITOR.kernel.stats()),
        "degraded": not MONITOR.kernel.available,
        "fake": FAKE,
        "last_poll": MONITOR.last_poll,
        "uptime": int(time.time()) - MONITOR.started_at,
        "total_packets": int(STORE.kv_get("total_packets", 0)),
        "window_sum": MONITOR.window_sum(),
        "top_src": MONITOR.top_src(),
        "window_series": MONITOR.window_series(),
        "per_port": STORE.kv_get("port_totals", {}),
        "port_last": STORE.kv_get("port_last", {}),
        "port_state": ports,
        "link": {
            "hive": hive_info(),
            "hfish": hfish_link(),
            "ports_watched": len(cfg["ports"]),
            "ports_listening": sum(1 for p in ports if p["listening"]),
        },
        "geo_source": MONITOR.geo.source(),
        "recent": [row for row in events(limit=5)],
    }


def events(limit=500, verdict=None, q=None, offset=0):
    """事件列表。verdict 过滤在 SQL 之外做，方便与 UI 的筛选语义对齐。"""
    try:
        limit = max(1, min(2000, int(limit)))
    except (TypeError, ValueError):
        limit = 500
    rows = STORE.events(limit + max(0, int(offset or 0)))
    items = []
    for r in rows:
        if verdict and verdict != "all" and r[5] != verdict:
            continue
        if q:
            needle = str(q).lower()
            hay = "%s %s %s %s" % (r[2], r[3], r[5], MONITOR.geo.lookup(r[2]).get("cn", "") if r[2] else "")
            if needle not in hay.lower():
                continue
        items.append(r)
    items = items[:limit]
    return [{
        "id": "EV-%d" % r[0],
        "ts": r[1] * 1000,
        "ip": r[2],
        "port": r[3],
        "packets": r[4],
        "verdict": r[5],
        "action": r[6],
        "detail": r[7] or "",
        "geo": MONITOR.geo.lookup(r[2]) if r[2] else None,
    } for r in items]


def blacklist():
    now = int(time.time())
    out = []
    for ip, ts, expire, port, packets, ttl, reason in STORE.active_blocks():
        out.append({
            "ip": ip,
            "at": ts * 1000,
            "expire": expire * 1000 if expire else 0,
            "port": port,
            "packets": packets,
            # 永久封禁用 ttl=0 表示，UI 侧按 10 年渲染进度条
            "ttl": ttl if ttl > 0 else 315360000,
            "permanent": ttl <= 0,
            "left": max(0, expire - now) if expire else None,
            "reason": reason,
            "geo": MONITOR.geo.lookup(ip),
        })
    return out


def geo_lookup(ips=None, ip=""):
    if ips:
        return {"source": MONITOR.geo.source(),
                "items": [MONITOR.geo.lookup(x.strip()) for x in ips.split(",")[:200] if x.strip()]}
    return MONITOR.geo.lookup(ip)


# --------------------------------------------------------------------- 启动
STORE = None
MONITOR = None
HFISH = {}


def serve(port=PORT):
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    srv.daemon_threads = True
    srv.allow_reuse_address = True
    log("接口面就绪：http://0.0.0.0:%d（%s 内核，%s）" % (
        port, MONITOR.kernel.kind, "已挂载规则" if MONITOR.kernel.trap_present(
            [str(p) for p in STORE.cfg["ports"]]) else "规则未生效"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


def poll_loop():
    while True:
        try:
            MONITOR.poll_once()
        except Exception as e:                            # noqa: BLE001
            log("轮询异常：%r" % e, "error")
            try:
                STORE.event("system", 0, 0, "error", "守护异常", str(e)[:180])
            except Exception:                              # noqa: BLE001
                pass
        time.sleep(max(1, int(STORE.cfg.get("poll", POLL_DEFAULT))))


def prune_loop():
    while True:
        time.sleep(600)
        try:
            STORE.prune()
        except Exception as e:                            # noqa: BLE001
            log("清理历史事件失败：%r" % e, "warn")


def main(argv=None):
    global BASE_DIR, CFG_PATH, DB_PATH, GEO_PATH, PORT, FAKE, STORE, MONITOR
    parser = argparse.ArgumentParser(description="HFish Guard daemon")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--data", default=BASE_DIR)
    parser.add_argument("--fake", action="store_true", default=FAKE,
                        help="内存态内核 + 攻击模拟器，用于本地联调")
    parser.add_argument("--verbose", action="store_true", default=VERBOSE)
    args = parser.parse_args(argv)

    PORT = args.port
    BASE_DIR = os.path.abspath(args.data)
    CFG_PATH = os.path.join(BASE_DIR, "config.json")
    DB_PATH = os.path.join(BASE_DIR, "guard.db")
    GEO_PATH = os.path.join(BASE_DIR, "geo.json")
    FAKE = args.fake or FAKE

    log("HFish Guard v%s 启动（数据目录 %s）" % (VERSION, BASE_DIR))
    STORE = Store()
    if FAKE:
        kernel = FakeKernel()
        log("内核层：fake（内存态，不触碰 iptables/ipset）", "warn")
    else:
        kernel = RealKernel()
        if not kernel.available:
            log("内核层不可用：%s —— 守护以降级模式运行（只读接口，不下发规则）" % kernel.reason, "warn")
    MONITOR = Monitor(STORE, kernel, Geo())
    MONITOR.apply_all()

    if FAKE and SIMULATE:
        Simulator(kernel, STORE, MONITOR).start()
        log("攻击模拟器已启动（--fake）", "warn")

    # HFish 联动：syslog 接收器（UDP/TCP）+ 开放 API 情报同步，按配置启停
    hf_cfg = STORE.cfg.get("hfish", {})
    if not hf_cfg.get("enabled"):
        log("HFish 联动未启用（只用内核计数）；需要事件富化请在配置里开启 hfish.enabled")
    hfish_reload()

    threading.Thread(target=poll_loop, daemon=True).start()
    threading.Thread(target=prune_loop, daemon=True).start()

    def _shutdown(_signum, _frame):
        log("收到退出信号，正在停止")
        os._exit(0)

    for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
        if sig is not None:
            try:
                signal.signal(sig, _shutdown)
            except (ValueError, OSError):
                pass

    serve(PORT)


if __name__ == "__main__":
    main()
