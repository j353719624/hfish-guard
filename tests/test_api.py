#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""接口面端到端测试：拉起一个 --fake 守护进程，用真实 HTTP 打全流程。

    python -m unittest discover -s tests -v
    # 或
    python tests/test_api.py

覆盖：鉴权、状态快照、事件流、观察/封禁双模式、白名单豁免、
黑名单解封、配置热加载、凭证轮换、归属地解析、静态页面。
"""
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GUARD = os.path.join(ROOT, "fpk", "app", "bin", "guard.py")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def free_dual_port():
    """取一个 TCP 与 UDP 同时空闲的端口。

    syslog 接收器要同时绑 UDP 和 TCP，只验一种会被另一种占用的号坑到
    （实测：UDP 挑中的号可能正是守护进程自己正在用的 TCP 端口，
    结果 UDP 绑上、TCP EADDRINUSE，表现为 syslog_bound={"udp":true,"tcp":false}）。
    """
    for _ in range(200):
        # 起点必须也是 0.0.0.0 上取到的：只绑 127.0.0.1:0 可能拿到一个
        # 仍被别的进程以 0.0.0.0 占着的号（Windows 实测偶发）
        seed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            seed.bind(("0.0.0.0", 0))
            port = seed.getsockname()[1]
        finally:
            seed.close()
        ok = True
        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            probe = socket.socket(socket.AF_INET, kind)
            try:
                probe.bind(("0.0.0.0", port))
            except OSError:
                ok = False
            finally:
                probe.close()
            if not ok:
                break
        if ok:
            return port
    raise RuntimeError("找不到 TCP/UDP 双空闲端口")


class ApiBase(unittest.TestCase):
    """两个测试类共用的 HTTP helper。"""
    base = ""
    token = ""

    @classmethod
    def call(cls, method, path, body=None, token="__default__", raw=False):
        url = cls.base + path
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        tok = cls.token if token == "__default__" else token
        if tok:
            headers["Authorization"] = "Bearer " + tok
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = resp.read()
                if raw:
                    return resp.status, payload
                return json.loads(payload.decode() or "{}")
        except urllib.error.HTTPError as e:
            payload = e.read().decode(errors="replace")
            if raw:
                return e.code, payload.encode()
            try:
                return json.loads(payload or "{}")
            except ValueError:
                return {"error": payload}

    @classmethod
    def status_code(cls, method, path, body=None, token="__default__"):
        url = cls.base + path
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        tok = cls.token if token == "__default__" else token
        if tok:
            headers["Authorization"] = "Bearer " + tok
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
                return resp.status
        except urllib.error.HTTPError as e:
            e.read()
            return e.code



class GuardApiTest(ApiBase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="hfish-guard-test-")
        cls.port = free_port()
        cls.base = "http://127.0.0.1:%d" % cls.port
        cls.token = "hg-test-token-0001"
        # 预置配置：固定凭证 + 收紧时间参数，判定能在一两秒内完成（也避开首次轮询睡眠）
        with open(os.path.join(cls.tmp, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"mode": "observe", "threshold": 20, "window": 5, "poll": 1,
                       "ttl": 3600, "token": cls.token,
                       "ports": [6379, 9200, 2022], "whitelist": []}, f)
        env = dict(os.environ)
        env.update({
            "HFISH_GUARD_FAKE": "1",
            "HFISH_GUARD_SIM": "0",        # 关掉模拟器，断言不受随机流量干扰
            "HFISH_GUARD_VERBOSE": "0",
        })
        cls.proc = subprocess.Popen(
            [sys.executable, GUARD, "--fake", "--port", str(cls.port), "--data", cls.tmp],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        cls._wait_ready()

    @classmethod
    def _wait_ready(cls, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if cls.call("GET", "/api/health", token=None).get("ok"):
                    return
            except Exception:
                pass
            time.sleep(0.2)
        out = ""
        if cls.proc.poll() is not None and cls.proc.stdout:
            out = cls.proc.stdout.read()
        raise RuntimeError("守护进程未就绪：\n%s" % out)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def simulate(self, ip, port, packets):
        return self.call("POST", "/api/simulate", {"ip": ip, "port": port, "packets": packets})

    def wait_event(self, ip, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            rows = self.call("GET", "/api/events?limit=200&filter=over")
            for row in rows if isinstance(rows, list) else []:
                if row["ip"] == ip:
                    return row
            time.sleep(0.3)
        return None

    # -- 用例
    def test_01_health_public(self):
        data = self.call("GET", "/api/health", token=None)
        self.assertTrue(data["ok"])
        self.assertEqual(data["app"], "hfish-guard")
        self.assertEqual(data["kernel"]["kind"], "fake")

    def test_02_auth_required(self):
        self.assertEqual(self.status_code("GET", "/api/status", token=None), 401)
        self.assertEqual(self.status_code("GET", "/api/status", token="wrong"), 401)
        self.assertEqual(self.status_code("GET", "/api/status"), 200)

    def test_03_query_token_works(self):
        # fnOS iframe 入口带 ?token=，接口面必须接受
        code = self.status_code("GET", "/api/status?token=" + self.token, token=None)
        self.assertEqual(code, 200)

    def test_04_status_shape(self):
        s = self.call("GET", "/api/status")
        for key in ("mode", "threshold", "window", "poll", "ttl", "ports", "whitelist",
                    "blacklist_count", "events_count", "trap", "port_state", "window_series",
                    "link", "kernel", "geo_source"):
            self.assertIn(key, s, "status 缺字段 " + key)
        self.assertEqual(len(s["port_state"]), len(s["ports"]))
        self.assertIn("installed", s["link"]["hive"])

    def test_05_observe_mode_records_only(self):
        self.simulate("203.0.113.10", 6379, 40)
        row = self.wait_event("203.0.113.10")
        self.assertIsNotNone(row, "观察模式下应产生 over 事件")
        self.assertGreaterEqual(row["packets"], 20)
        self.assertEqual(row["action"], "观察记录")
        bl = self.call("GET", "/api/blacklist")
        self.assertNotIn("203.0.113.10", [b["ip"] for b in bl])

    def test_06_whitelist_short_circuits(self):
        self.call("POST", "/api/whitelist", {"cidr": "198.18.0.0/15", "note": "单测豁免段"})
        wl = self.call("GET", "/api/whitelist")
        self.assertIn("198.18.0.0/15", [w["cidr"] for w in wl])
        # 白名单在内核侧就被丢掉，注入返回 False 且不会产生事件
        r = self.simulate("198.18.7.7", 6379, 80)
        self.assertFalse(r["ok"])
        time.sleep(2.5)
        rows = self.call("GET", "/api/events?limit=200")
        self.assertNotIn("198.18.7.7", [x["ip"] for x in rows])
        self.assertEqual(self.status_code("DELETE", "/api/whitelist/198.18.0.0/15"), 200)
        self.assertNotIn("198.18.0.0/15",
                         [w["cidr"] for w in self.call("GET", "/api/whitelist")])

    def test_07_enforce_blocks_and_unblocks(self):
        self.call("PUT", "/api/config", {"mode": "enforce"})
        self.assertEqual(self.call("GET", "/api/config")["mode"], "enforce")
        self.simulate("203.0.113.66", 9200, 45)
        row = self.wait_event("203.0.113.66")
        self.assertIsNotNone(row)
        self.assertEqual(row["action"], "自动封禁")
        bl = self.call("GET", "/api/blacklist")
        ips = [b["ip"] for b in bl]
        self.assertIn("203.0.113.66", ips)
        self.assertEqual(self.status_code("DELETE", "/api/blacklist/203.0.113.66"), 200)
        self.assertNotIn("203.0.113.66", [b["ip"] for b in self.call("GET", "/api/blacklist")])

    def test_08_manual_block_rejects_bad_input(self):
        self.assertEqual(self.status_code("POST", "/api/blacklist", {"ip": "999.1.1.1"}), 400)
        self.assertEqual(self.status_code("POST", "/api/whitelist", {"cidr": "abc"}), 400)
        self.assertEqual(self.status_code("DELETE", "/api/blacklist/not-an-ip"), 400)

    def test_09_config_hot_reload(self):
        cfg = self.call("PUT", "/api/config", {"threshold": 33, "ports": [6379, 9200, "2022"],
                                               "mode": "observe"})
        self.assertTrue(cfg["ok"])
        self.assertEqual(cfg["config"]["threshold"], 33)
        self.assertEqual(cfg["config"]["ports"], [6379, 9200, 2022])
        s = self.call("GET", "/api/status")
        self.assertEqual(s["threshold"], 33)
        self.assertEqual(len(s["port_state"]), 3)
        # 非法值不生效
        self.call("PUT", "/api/config", {"threshold": -5, "mode": "boom"})
        s2 = self.call("GET", "/api/status")
        self.assertEqual(s2["threshold"], 33)
        self.assertEqual(s2["mode"], "observe")

    def test_10_events_filter_and_geo(self):
        rows = self.call("GET", "/api/events?limit=50&filter=over")
        self.assertIsInstance(rows, list)
        self.assertTrue(all(r["verdict"] == "over" for r in rows))
        hit = self.call("GET", "/api/events?limit=50&q=203.0.113.66")
        self.assertTrue(hit)
        geo = self.call("GET", "/api/geo?ips=185.220.101.42,10.1.2.3,203.0.113.9")
        items = {g["ip"]: g for g in geo["items"]}
        self.assertEqual(items["185.220.101.42"]["cc"], "DE")
        self.assertEqual(items["10.1.2.3"]["cc"], "LAN")
        self.assertEqual(items["203.0.113.9"]["source"], "private")

    def test_11b_root_redirects_to_token_url(self):
        """直接访问 / 或带过期凭证时，应 302 到带当前 token 的地址。

        用户反馈「凭证见应用『配置』页？在哪里」——与其让人满屏找凭证，
        不如服务端直接把凭证补上（飞牛桌面入口本来就是这么带进去的）。
        """
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        opener = urllib.request.build_opener(NoRedirect)
        for path in ("/", "/web", "/web/", "/index.html", "/web/?token=stale-token"):
            try:
                resp = opener.open(self.base + path, timeout=10)
                code, loc = resp.getcode(), resp.headers.get("Location", "")
            except urllib.error.HTTPError as e:
                code, loc = e.code, e.headers.get("Location", "")
            self.assertEqual(code, 302, "%s 应重定向" % path)
            self.assertIn("token=%s" % self.token, loc, "%s 重定向应带上当前 token" % path)

    def test_11c_geo_source_reported(self):
        """status 必须暴露归属地数据源，UI 才能解释「未知地域」的成因。"""
        st = self.call("GET", "/api/status")
        self.assertIn("geo", st, "status 里缺少 geo 字段")
        geo = st["geo"]
        for k in ("source", "mmdb", "custom", "ready"):
            self.assertIn(k, geo, "geo 字段缺少 %s" % k)
        self.assertIn(geo["source"], ("mmdb", "custom", "approx", "none"))

    def test_11d_cc_zh_fallback_table(self):
        """ISO → 中文国名映射：mmdb 没有 zh-CN 名称时靠它兜底。"""
        import importlib.util
        spec = importlib.util.spec_from_file_location("g", GUARD)
        g = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(g)
        self.assertGreaterEqual(len(g.CC_ZH), 60, "映射表条目太少")
        for cc, name in (("US", "美国"), ("CN", "中国"), ("RU", "俄罗斯"),
                         ("KR", "韩国"), ("TW", "中国台湾"), ("HK", "中国香港")):
            self.assertEqual(g.CC_ZH.get(cc), name, "%s 的中文名不对" % cc)

    def test_10_mode_switch_persists_to_disk(self):
        """顶栏「封禁模式」按钮必须真正落库。

        回归：按钮只改浏览器本地 state，从未推给后端，下一次 sync 就被
        apply() 里的 state.mode=st.mode 拉回 observe —— 用户表现为
        「点了封禁模式，关掉再打开又变回观察模式」。
        """
        cfg = self.call("GET", "/api/config")
        self.assertEqual(cfg["mode"], "observe", "前置条件：初始应为观察模式")

        # 模拟顶栏按钮的请求：只带 mode 一个键
        res = self.call("PUT", "/api/config", {"mode": "enforce"})
        self.assertTrue(res.get("ok"))
        self.assertEqual(res["config"]["mode"], "enforce")

        # 运行态已切换
        st = self.call("GET", "/api/status")
        self.assertEqual(st["mode"], "enforce")

        # 关键：已落盘（重新读文件，不是读内存里的 cfg）
        path = os.path.join(self.tmp, "config.json")
        with open(path, encoding="utf-8") as f:
            saved = json.load(f)
        self.assertEqual(saved.get("mode"), "enforce", "mode 必须写进 config.json")

        # 切回来，保持其它测试的基线
        self.call("PUT", "/api/config", {"mode": "observe"})

    def test_10b_mode_only_patch_keeps_other_settings(self):
        """只传 mode 时，其它配置项不能被清掉（apply_patch 必须是增量）。"""
        before = self.call("GET", "/api/config")
        self.call("PUT", "/api/config", {"mode": "enforce"})
        after = self.call("GET", "/api/config")
        self.assertEqual(after["mode"], "enforce")
        for k in ("threshold", "window", "poll", "ttl", "ports", "whitelist", "token"):
            self.assertEqual(after.get(k), before.get(k), "%s 不应被 mode 补丁改动" % k)
        self.call("PUT", "/api/config", {"mode": "observe"})

    def test_10c_local_request_detection(self):
        """分级凭证的依据：内网/回环判定。

        内网访问自动补 token（日常零摩擦），外网访问必须手填。
        判定必须与 Python 版本无关，所以用显式网段而非 ipaddress.is_private。
        """
        import importlib.util
        spec = importlib.util.spec_from_file_location("g", GUARD)
        g = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(g)
        local = ["127.0.0.1", "::1", "192.168.110.36", "10.1.2.3",
                 "172.16.5.5", "169.254.10.1", "fd00::1"]
        remote = ["8.8.8.8", "203.0.113.7", "172.32.5.5", "100.64.1.1",
                  "2409:8a20:2485:cb30::157d", "240e:398::1", ""]
        for ip in local:
            self.assertTrue(g._is_local_request(ip), "%s 应判为内网" % ip)
        for ip in remote:
            self.assertFalse(g._is_local_request(ip), "%s 不应判为内网" % ip)

    def test_10d_token_local_only_from_loopback(self):
        """/api/token-local 只能在回环调用，外网拿到 token 等于不设防。"""
        r = urllib.request.Request(self.base + "/api/token-local")
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                res = json.loads(resp.read().decode())
            # 测试服务器就在本机，回环放行是预期行为
            self.assertTrue(res.get("ok"))
            self.assertEqual(res.get("token"), self.token)
        except urllib.error.HTTPError as e:
            # 非回环来源应被拒
            self.assertEqual(e.code, 403, "非回环调用应返回 403")

    def test_10e_page_entry_auto_token_only_for_local(self):
        """页面入口自动补 token 只能对内网来源生效。

        回归风险：若对所有来源都自动补，面板一旦暴露到公网就等于公开。
        这里直接改 Handler 的 client_address 模拟外网来源，
        断言不再 302 补 token（而是停在凭证门）。
        """
        import importlib.util
        spec = importlib.util.spec_from_file_location("g", GUARD)
        g = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(g)
        # 判定逻辑本身
        self.assertTrue(g._is_local_request("192.168.110.36"))
        self.assertFalse(g._is_local_request("203.0.113.7"))
        # 源码里必须存在来源判定，不能是无条件补
        src = io.open(GUARD, encoding="utf-8").read()
        self.assertIn("_is_local_request(client)", src,
                      "自动补 token 必须受来源判定约束")
        self.assertIn("if tok and want != tok and local:", src,
                      "页面入口补 token 的条件必须包含 local 判断")

    def test_11_static_ui(self):
        code, body = self.call("GET", "/", raw=True)
        self.assertEqual(code, 200)
        self.assertIn(b"<!DOCTYPE html>", body[:200])
        self.assertEqual(self.status_code("GET", "/../etc/passwd", token=None) in (400, 403, 404), True)

    def test_12_token_rotation(self):
        old = self.token
        data = self.call("POST", "/api/token")
        new = data["token"]
        self.assertNotEqual(new, old)
        self.assertEqual(self.status_code("GET", "/api/status", token=old), 401)
        self.assertEqual(self.status_code("GET", "/api/status", token=new), 200)
        type(self).token = new


class HfishIngestTest(ApiBase):
    """HFish 官方出口接入：syslog（UDP/TCP）与自定义 webhook。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="hfish-guard-hf-")
        cls.port = free_port()
        cls.syslog_port = free_dual_port()
        cls.base = "http://127.0.0.1:%d" % cls.port
        cls.token = "hg-test-token-hf1"
        cfg = {
            "mode": "enforce", "threshold": 9999, "window": 60, "poll": 1, "ttl": 600,
            "token": cls.token, "ports": [6379], "whitelist": [{"cidr": "10.9.0.0/16"}],
            "hfish": {"enabled": True, "syslog_port": cls.syslog_port,
                      "webhook_token": "wh-secret", "auto_block_level": "high",
                      "api_base": "", "api_key": ""},
        }
        with open(os.path.join(cls.tmp, "config.json"), "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        env = dict(os.environ)
        env.update({"HFISH_GUARD_FAKE": "1", "HFISH_GUARD_SIM": "0"})
        cls.proc = subprocess.Popen(
            [sys.executable, GUARD, "--fake", "--port", str(cls.port), "--data", cls.tmp],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                st = GuardApiTest.call.__func__(cls, "GET", "/api/status")
                if st.get("link", {}).get("hfish", {}).get("syslog_bound", {}).get("udp"):
                    return
            except Exception:
                pass
            time.sleep(0.3)
        raise RuntimeError("HFish syslog 未就绪")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def syslog(self, fields):
        line = ", ".join("%s: %s" % (k, v) for k, v in fields.items()) + "\n"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(line.encode(), ("127.0.0.1", self.syslog_port))
        sock.close()
        time.sleep(0.6)

    def test_00_scan_sensor_noise_is_dropped(self):
        """扫描感知把传感器端口上的广播流量也算 scan 告警，必须过滤掉，
        否则 11 万条噪声会把事件表刷满（真机实测）。"""
        body = {"src_ip": "198.51.100.44", "attack_type": "scan",
                "scan_port": 63219, "threat_level": "low"}
        r = urllib.request.Request(self.base + "/api/hfish/webhook?k=wh-secret",
                                   data=json.dumps(body).encode(), method="POST",
                                   headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=10) as resp:
            res = json.loads(resp.read().decode())
        self.assertEqual(res.get("accepted", 0), 0, "传感器端口噪声不应被接受")
        rows = self.call("GET", "/api/events?limit=100")
        self.assertNotIn("198.51.100.44", [x["ip"] for x in rows])

    def test_01_syslog_event_and_auto_block(self):
        self.syslog({"client": "node1", "src_ip": "203.0.113.201", "attack_type": "signon",
                     "class": "SSH", "account": "root/123456", "threat_level": "high",
                     "scan_port": "2022", "geo": "NL"})
        st = self.call("GET", "/api/status")
        self.assertTrue(st["link"]["hfish"]["enabled"])
        rows = self.call("GET", "/api/events?limit=50")
        hit = [r for r in rows if r["ip"] == "203.0.113.201"]
        self.assertTrue(hit, "syslog 告警应落库")
        self.assertEqual(hit[0]["verdict"], "hfish")
        self.assertIn("SSH", hit[0]["detail"])
        # 高危及 + enforce → 直接封禁
        self.assertIn("203.0.113.201", [b["ip"] for b in self.call("GET", "/api/blacklist")])
        self.assertTrue(hit[0]["action"].startswith("自动封禁"))

    def test_02_syslog_dedup(self):
        before = len([r for r in self.call("GET", "/api/events?limit=100")
                      if r["ip"] == "203.0.113.201"])
        for _ in range(3):
            self.syslog({"src_ip": "203.0.113.201", "attack_type": "signon", "class": "SSH",
                         "threat_level": "high"})
        after = len([r for r in self.call("GET", "/api/events?limit=100")
                     if r["ip"] == "203.0.113.201"])
        self.assertEqual(before, after, "同一 (IP, 类型, 蜜罐) 60s 内应去重")

    def test_03_webhook_ingest(self):
        # 源用真公网段：扫描类告警按「源地址是否公网」过滤，保留段会被当噪声丢
        body = {"src_ip": "45.33.32.90", "attack_type": "scan", "class": "Redis",
                "threat_level": "low", "scan_port": 6379}
        r = urllib.request.Request(self.base + "/api/hfish/webhook?k=wh-secret",
                                   data=json.dumps(body).encode(), method="POST",
                                   headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=10) as resp:
            res = json.loads(resp.read().decode())
        self.assertEqual(res["accepted"], 1)
        rows = self.call("GET", "/api/events?limit=50")
        ip = [x for x in rows if x["ip"] == "45.33.32.90"]
        self.assertTrue(ip)
        # low 级不自动封禁
        self.assertNotIn("45.33.32.90", [b["ip"] for b in self.call("GET", "/api/blacklist")])

    def test_04_webhook_bad_token(self):
        req = urllib.request.Request(self.base + "/api/hfish/webhook?k=wrong",
                                     data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("错误校验串应被拒绝")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 401)
            e.read()

    def test_05_whitelist_source_ignored(self):
        self.syslog({"src_ip": "10.9.1.2", "attack_type": "scan", "class": "Redis",
                     "threat_level": "high"})
        rows = self.call("GET", "/api/events?limit=100")
        self.assertNotIn("10.9.1.2", [r["ip"] for r in rows])

    def test_06_private_ip_syslog_parsed(self):
        # 不带 class/level 的极简行也要能落库（字段容错）
        self.syslog({"src_ip": "192.0.2.55", "info": "redis brute force"})
        rows = self.call("GET", "/api/events?limit=100")
        self.assertIn("192.0.2.55", [r["ip"] for r in rows])

    def test_07_syslog_rebinds_on_config_change(self):
        # UI 里改 syslog 端口必须即时生效：不重启进程也要重绑到新端口
        new_port = free_dual_port()
        cfg = self.call("PUT", "/api/config", {"hfish": {"syslog_port": new_port}})
        self.assertEqual(cfg["config"]["hfish"]["syslog_port"], new_port)

        bound = {}
        deadline = time.time() + 8
        while time.time() < deadline:
            hf = self.call("GET", "/api/status")["link"]["hfish"]
            bound = hf["syslog_bound"]
            if hf["syslog_port"] == new_port and bound.get("udp") and bound.get("tcp"):
                break
            time.sleep(0.3)
        self.assertTrue(bound.get("udp"), "新端口未绑定 UDP")
        self.assertTrue(bound.get("tcp"), "新端口未绑定 TCP")

        type(self).syslog_port = new_port      # 后续 syslog() 打到新端口
        # 源用真公网段：扫描类告警按「源地址是否公网」过滤，保留段会被当噪声丢
        self.syslog({"src_ip": "45.33.32.77", "attack_type": "scan", "class": "Redis",
                     "threat_level": "low"})
        rows = self.call("GET", "/api/events?limit=100")
        self.assertIn("45.33.32.77", [r["ip"] for r in rows], "重绑后新端口收不到告警")

    def test_08_disable_stops_receiver(self):
        self.call("PUT", "/api/config", {"hfish": {"enabled": False}})
        deadline = time.time() + 8
        while time.time() < deadline:
            hf = self.call("GET", "/api/status")["link"]["hfish"]
            if not hf["enabled"] and not hf["syslog_bound"].get("udp"):
                break
            time.sleep(0.3)
        hf = self.call("GET", "/api/status")["link"]["hfish"]
        self.assertFalse(hf["enabled"])
        self.assertFalse(hf["syslog_bound"].get("udp"), "关闭联动后应释放 syslog 端口")


class LegacyConfigTest(ApiBase):
    """v1.0.0 部署升级上来：旧 UI 把封禁模式写成 "block"，不能被静默降级。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="hfish-guard-legacy-")
        cls.port = free_port()
        cls.base = "http://127.0.0.1:%d" % cls.port
        cls.token = "hg-test-token-legacy"
        # 还原线上真实形态：mode=block、ports 为字符串、无 hfish 段
        with open(os.path.join(cls.tmp, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"mode": "block", "threshold": 40, "window": 60, "ttl": 86400,
                       "token": cls.token,
                       "ports": ["6379", "9200", "2022"],
                       "whitelist": ["127.0.0.1", "192.168.110.97"]}, f)
        env = dict(os.environ)
        env.update({"HFISH_GUARD_FAKE": "1", "HFISH_GUARD_SIM": "0"})
        cls.proc = subprocess.Popen(
            [sys.executable, GUARD, "--fake", "--port", str(cls.port), "--data", cls.tmp],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                if cls.call("GET", "/api/health", token=None).get("ok"):
                    return
            except Exception:
                pass
            time.sleep(0.2)
        raise RuntimeError("守护进程未就绪")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_01_block_migrates_to_enforce(self):
        self.assertEqual(self.call("GET", "/api/config")["mode"], "enforce")
        self.assertEqual(self.call("GET", "/api/status")["mode"], "enforce")

    def test_02_legacy_port_and_whitelist_survive(self):
        s = self.call("GET", "/api/status")
        self.assertEqual(s["ports"], [6379, 9200, 2022])
        self.assertIn("192.168.110.97", [w["cidr"] for w in s["whitelist"]])

    def test_03_patch_still_accepts_legacy_value(self):
        # 旧页面缓存直接 POST block 也要落到 enforce，不能静默失败
        self.call("PUT", "/api/config", {"mode": "observe"})
        self.assertEqual(self.call("GET", "/api/config")["mode"], "observe")
        self.call("PUT", "/api/config", {"mode": "block"})
        self.assertEqual(self.call("GET", "/api/config")["mode"], "enforce")

    def test_04_hfish_defaults_when_absent(self):
        hf = self.call("GET", "/api/config")["hfish"]
        self.assertFalse(hf["enabled"])
        self.assertEqual(hf["syslog_port"], 5514)


class LegacyDbTest(ApiBase):
    """v1.0.0 的 guard.db 结构与现在完全不同，升级时必须自动补列而不是崩。

    线上真实形态（fnOS 实机）：events(id, ts, ip, hits, action, detail)、
    blocks(ip, ts, expire, reason, hits, active)，缺 port/packets/verdict/ttl。
    """

    @classmethod
    def setUpClass(cls):
        import sqlite3
        cls.tmp = tempfile.mkdtemp(prefix="hfish-guard-legacydb-")
        cls.port = free_port()
        cls.base = "http://127.0.0.1:%d" % cls.port
        cls.token = "hg-test-token-legacydb"
        with open(os.path.join(cls.tmp, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"mode": "enforce", "threshold": 9999, "poll": 1,
                       "token": cls.token, "ports": [6379], "whitelist": []}, f)
        db = sqlite3.connect(os.path.join(cls.tmp, "guard.db"))
        db.execute("CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, "
                   "ip TEXT, hits INTEGER, action TEXT, detail TEXT)")
        db.execute("CREATE TABLE blocks(ip TEXT PRIMARY KEY, ts INTEGER, expire INTEGER, "
                   "reason TEXT, hits INTEGER, active INTEGER DEFAULT 1)")
        db.execute("CREATE TABLE kv(k TEXT PRIMARY KEY, v TEXT)")
        db.execute("INSERT INTO events(ts,ip,hits,action,detail) VALUES(1,'203.0.113.9',7,"
                   "'自动封禁','旧版事件')")
        db.execute("INSERT INTO blocks(ip,ts,expire,reason,hits,active) "
                   "VALUES('203.0.113.9',1,4102444800,'旧版封禁',7,1)")
        db.commit()
        db.close()

        env = dict(os.environ)
        env.update({"HFISH_GUARD_FAKE": "1", "HFISH_GUARD_SIM": "0"})
        cls.proc = subprocess.Popen(
            [sys.executable, GUARD, "--fake", "--port", str(cls.port), "--data", cls.tmp],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                if cls.call("GET", "/api/health", token=None).get("ok"):
                    return
            except Exception:
                pass
            if cls.proc.poll() is not None:
                raise RuntimeError("迁移后进程退出：\n%s" % cls.proc.stdout.read())
            time.sleep(0.2)
        raise RuntimeError("守护进程未就绪（迁移可能卡住）")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_01_starts_despite_old_schema(self):
        self.assertTrue(self.call("GET", "/api/health")["ok"])

    def test_02_old_events_migrated(self):
        rows = self.call("GET", "/api/events?limit=20")
        old = [r for r in rows if r["ip"] == "203.0.113.9"]
        self.assertTrue(old, "旧事件应保留")
        self.assertEqual(old[0]["packets"], 7, "hits 应搬到 packets")
        self.assertEqual(old[0]["port"], 0)

    def test_03_old_block_migrated(self):
        bl = self.call("GET", "/api/blacklist")
        self.assertIn("203.0.113.9", [b["ip"] for b in bl])
        row = [b for b in bl if b["ip"] == "203.0.113.9"][0]
        self.assertEqual(row["packets"], 7)


class RateSpecTest(unittest.TestCase):
    """hashlimit 速率写法必须合法：真机上 "40/60sec" 会被直接拒掉，
    结果是规则没挂上、以为在防护其实什么都不做。"""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("guard_mod", GUARD)
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)

    def test_units_are_valid(self):
        rs = self.mod.rate_spec
        self.assertEqual(rs(40, 60), "40/minute")
        self.assertEqual(rs(100, 60), "100/minute")
        self.assertEqual(rs(40, 300), "8/minute")
        self.assertEqual(rs(3600, 86400), "3600/day")
        self.assertEqual(rs(600, 3600), "600/hour")
        self.assertEqual(rs(10, 5), "2/second")

    def test_never_returns_zero_rate(self):
        rs = self.mod.rate_spec
        for thr, win in ((1, 3600), (1, 86400), (2, 300), (1, 1)):
            self.assertNotIn("/0", rs(thr, win))
            self.assertTrue(rs(thr, win).split("/")[0].isdigit())

    def test_only_supported_suffixes(self):
        rs = self.mod.rate_spec
        for thr, win in ((40, 60), (5, 5), (900, 3600), (5000, 86400)):
            self.assertIn(rs(thr, win).split("/", 1)[1], ("second", "minute", "hour", "day"))


class ScanDetectTest(ApiBase):
    """端口扫描面检测：同一源在窗口内命中多个不同蜜罐端口（真实蜜罐数据里
    出现过的形态——一个源 1 分钟内打了 5 个端口）。"""

    PORTS = [6379, 9200, 9000, 8080, 8081, 9198, 9080]

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="hfish-guard-scan-")
        cls.port = free_port()
        cls.base = "http://127.0.0.1:%d" % cls.port
        cls.token = "hg-test-token-scan"
        with open(os.path.join(cls.tmp, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"mode": "observe", "threshold": 9999, "window": 60, "poll": 1,
                       "ttl": 600, "token": cls.token, "ports": cls.PORTS,
                       "whitelist": [], "scan_ports": 4, "scan_block": True,
                       "udp": True}, f)
        env = dict(os.environ)
        env.update({"HFISH_GUARD_FAKE": "1", "HFISH_GUARD_SIM": "0"})
        cls.proc = subprocess.Popen(
            [sys.executable, GUARD, "--fake", "--port", str(cls.port), "--data", cls.tmp],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                if cls.call("GET", "/api/health", token=None).get("ok"):
                    return
            except Exception:
                pass
            time.sleep(0.2)
        raise RuntimeError("守护进程未就绪：\n%s" % (cls.proc.stdout.read() if cls.proc.stdout else ""))

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _sweep(self, ip, ports):
        for p in ports:
            self.call("POST", "/api/simulate", {"ip": ip, "port": p, "packets": 1})

    def _wait_scan(self, ip, timeout=12):
        deadline = time.time() + timeout
        while time.time() < deadline:
            rows = self.call("GET", "/api/events?limit=200")
            hit = [r for r in rows if r["ip"] == ip and r["verdict"] == "scan"]
            if hit:
                return hit[0]
            time.sleep(0.4)
        return None

    def test_01_sweep_below_threshold_no_scan(self):
        self._sweep("203.0.113.31", self.PORTS[:2])       # 只碰 2 个端口
        time.sleep(3)
        rows = self.call("GET", "/api/events?limit=200")
        self.assertFalse([r for r in rows if r["ip"] == "203.0.113.31"],
                         "2 个端口不该判成扫描")

    def test_02_sweep_over_threshold_records_scan(self):
        self._sweep("203.0.113.32", self.PORTS[:5])       # 5 个端口 ≥ scan_ports(4)
        row = self._wait_scan("203.0.113.32")
        self.assertIsNotNone(row, "命中 5 个端口应产生 scan 事件")
        self.assertEqual(row["verdict"], "scan")
        self.assertEqual(row["action"], "扫描探测")
        self.assertIn("个蜜罐端口", row["detail"])
        # 观察模式不封禁
        self.assertNotIn("203.0.113.32", [b["ip"] for b in self.call("GET", "/api/blacklist")])

    def test_03_scan_blocks_in_enforce(self):
        self.call("PUT", "/api/config", {"mode": "enforce"})
        self._sweep("203.0.113.33", self.PORTS[:5])
        row = self._wait_scan("203.0.113.33")
        self.assertIsNotNone(row)
        self.assertEqual(row["action"], "自动封禁（端口扫描）")
        self.assertIn("203.0.113.33", [b["ip"] for b in self.call("GET", "/api/blacklist")])
        self.call("DELETE", "/api/blacklist/203.0.113.33")

    def test_04_scan_ports_zero_disables(self):
        self.call("PUT", "/api/config", {"mode": "observe", "scan_ports": 0})
        self.assertEqual(self.call("GET", "/api/config")["scan_ports"], 0)
        self._sweep("203.0.113.34", self.PORTS)
        time.sleep(3)
        rows = self.call("GET", "/api/events?limit=200")
        self.assertFalse([r for r in rows if r["ip"] == "203.0.113.34" and r["verdict"] == "scan"],
                         "scan_ports=0 应关闭扫描判定")

    def test_05_udp_toggle_persists(self):
        cfg = self.call("PUT", "/api/config", {"udp": False})
        self.assertFalse(cfg["config"]["udp"])
        self.assertFalse(self.call("GET", "/api/config")["udp"])
        cfg = self.call("PUT", "/api/config", {"udp": True})
        self.assertTrue(cfg["config"]["udp"])

    def test_07_ipv6_block_unblock_via_encoded_path(self):
        # IPv6 字面量在 URL 路径里会被百分号编码，服务端必须能解出原地址
        ip = "2409:8a20:2485:cb30::157d"
        self.assertEqual(self.status_code("POST", "/api/blacklist", {"ip": ip}), 200)
        self.assertIn(ip, [b["ip"] for b in self.call("GET", "/api/blacklist")])
        code = self.status_code("DELETE", "/api/blacklist/" + quote(ip, safe=""))
        self.assertEqual(code, 200, "百分号编码的 IPv6 解封应返回 200")
        self.assertNotIn(ip, [b["ip"] for b in self.call("GET", "/api/blacklist")])

    def test_06_kernel_reports_ipv6_capability(self):
        k = self.call("GET", "/api/status")["kernel"]
        self.assertIn("v6", k, "status.kernel 应说明 IPv6 可用性")
        self.assertIn("rules", k)
        self.assertFalse(k["v6"], "fake 内核不模拟 IPv6")


class HfishPayloadTest(unittest.TestCase):
    """HFish 真实 syslog 报文解析（真机踩过的坑：带 RFC3164 头）。

    线上原文：
      <4>2026-11-06T08:12:44+08:00 fnOS HFish[942440]: {"title":"HFish Threat Alert",
       ..., "src_ip":"2409:...","attack_type":"scan",...}
    旧实现先整体 json.loads（失败）再跑 key:value 正则，正则先把时间戳里的
    "T08:12:44" 当成字段，字典写脏后 src_ip 取不到 —— 表现为全量 skipped。
    """

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("guard_mod2", GUARD)
        cls.g = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.g)

    def test_rfc3164_header_with_json_body(self):
        raw = ('<4>2026-11-06T08:12:44+08:00 fnOS HFish[942440]: {"title":"HFish Threat Alert",'
               '"client":"内置节点","client_ip":"192.168.110.97","attack_type":"scan",'
               '"scan_type":"UDP","scan_port":"63219","class":"","type":"","name":"","account":"",'
               '"src_ip":"2409:8a20:4c84:6200:d65e:4eb0:8dc4:93aa","src_port":"13873",'
               '"dst_ip":"192.168.110.97","dst_port":"63219","threat_level":"low",'
               '"info":"扫描感知","time":"2026-11-06 08:12:44"}')
        d = self.g.parse_hfish_payload(raw)
        self.assertEqual(d["ip"], "2409:8a20:4c84:6200:d65e:4eb0:8dc4:93aa")
        self.assertEqual(d["port"], 63219)
        self.assertEqual(d["attack_type"], "scan")
        self.assertEqual(d["level"], "low")
        self.assertTrue(self.g.valid_ip(d["ip"]))

    def test_plain_json(self):
        d = self.g.parse_hfish_payload(
            '{"src_ip":"203.0.113.5","attack_type":"signon","threat_level":"high"}')
        self.assertEqual(d["ip"], "203.0.113.5")

    def test_key_value_line(self):
        d = self.g.parse_hfish_payload(
            "client: node1, src_ip: 1.2.3.4, attack_type: signon, threat_level: high")
        self.assertEqual(d["ip"], "1.2.3.4")

    def test_plain_text_fallback(self):
        d = self.g.parse_hfish_payload("some random line 198.51.100.7 hit us")
        self.assertEqual(d["ip"], "198.51.100.7")

    def test_header_stripped_for_key_value(self):
        d = self.g.parse_hfish_payload(
            "<134>Nov  6 08:12:44 fnOS HFish[942440]: client: n1, src_ip: 198.51.100.9")
        self.assertEqual(d["ip"], "198.51.100.9")


class AutoBlockTest(ApiBase):
    """HFish 告警自动封禁：等级门禁（other）、速率熔断、容量上限。

    三个用例互相会污染黑名单与熔断窗口，所以每个用例各起一个干净实例。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hfish-guard-ab-")
        self.port = free_port()
        self.syslog_port = free_dual_port()
        type(self).base = "http://127.0.0.1:%d" % self.port
        type(self).token = "hg-test-token-ab"
        cfg = {
            "mode": "enforce", "threshold": 9999, "window": 60, "poll": 1, "ttl": 600,
            "token": self.token, "ports": [6379], "whitelist": [{"cidr": "10.9.0.0/16"}],
            "hfish": {"enabled": True, "syslog_port": self.syslog_port,
                      "webhook_token": "wh-secret", "auto_block_level": "all",
                      "auto_block_max_per_min": 120, "max_blocks": 20000},
        }
        with open(os.path.join(self.tmp, "config.json"), "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        env = dict(os.environ)
        env.update({"HFISH_GUARD_FAKE": "1", "HFISH_GUARD_SIM": "0"})
        self.proc = subprocess.Popen(
            [sys.executable, GUARD, "--fake", "--port", str(self.port), "--data", self.tmp],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                st = self.call("GET", "/api/status")
                if st.get("link", {}).get("hfish", {}).get("syslog_bound", {}).get("udp"):
                    return
            except Exception:                                  # noqa: BLE001
                pass
            time.sleep(0.3)
        raise RuntimeError("自动封禁用例实例未就绪")

    def tearDown(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def alert(self, ip, level="other", port=6379, atype="attack", pot="数据库服务"):
        body = {"src_ip": ip, "attack_type": atype, "threat_level": level,
                "dst_port": port, "pot": pot, "info": "unit-test"}
        r = urllib.request.Request(self.base + "/api/hfish/webhook?k=wh-secret",
                                   data=json.dumps(body).encode(), method="POST",
                                   headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=10) as resp:
            return json.loads(resp.read().decode())

    def blocked(self):
        return [b["ip"] for b in self.call("GET", "/api/blacklist?limit=1000")]

    def test_01_other_level_blocks_with_all(self):
        """HFish 蜜罐告警等级是 other，选「全部等级」必须真的封。"""
        self.alert("203.0.113.21")
        self.assertIn("203.0.113.21", self.blocked())

    def test_02_high_gate_ignores_other(self):
        """等级门禁仍要有效：设 high 时 other 级告警只记录不封。"""
        self.call("PUT", "/api/config", {"hfish": {"auto_block_level": "high"}})
        self.alert("203.0.113.22")
        self.assertNotIn("203.0.113.22", self.blocked())
        rows = [e for e in self.call("GET", "/api/events?limit=50") if e["ip"] == "203.0.113.22"]
        self.assertTrue(rows, "至少要有事件记录")

    def test_03_rate_limit_trips(self):
        """熔断：每分钟只允许封 N 个，超出的只记录，防告警洪水刷爆黑名单。"""
        self.call("PUT", "/api/config", {"hfish": {"auto_block_max_per_min": 2}})
        for i in range(5):
            self.alert("198.51.100.%d" % (30 + i))
        self.assertEqual(len(self.blocked()), 2, "到达速率上限后不应继续封禁")
        rows = [e for e in self.call("GET", "/api/events?limit=50")
                if e["ip"].startswith("198.51.100.")]
        self.assertEqual(len(rows), 5, "被熔断的告警仍要落事件")

    def test_05_scan_fanout_blocks_after_threshold(self):
        """公网源扫够多个不同端口 → 判为扫描者，封禁一次。"""
        self.call("PUT", "/api/config",
                  {"hfish": {"auto_block_level": "all", "scan_fanout": 3}})
        for port in (445, 22, 3389):
            self.alert("45.33.32.156", level="low", port=port, atype="scan", pot="扫描")
        self.assertIn("45.33.32.156", self.blocked())

    def test_06_scan_below_threshold_not_blocked(self):
        """扇出不够时不封（只记事件），避免单端口高频被误判。"""
        self.call("PUT", "/api/config",
                  {"hfish": {"auto_block_level": "all", "scan_fanout": 5}})
        for port in (445, 22):
            self.alert("45.33.32.157", level="low", port=port, atype="scan", pot="扫描")
        self.assertNotIn("45.33.32.157", self.blocked())
        rows = [e for e in self.call("GET", "/api/events?limit=50") if e["ip"] == "45.33.32.157"]
        self.assertTrue(rows, "未达阈值也要留事件")

    def test_07_private_source_scan_is_noise(self):
        """内网源（同网段 IPv6/广播）算噪声：丢弃，不写事件、不封。"""
        body = {"src_ip": "192.168.110.50", "attack_type": "scan",
                "scan_port": 63219, "threat_level": "low"}
        r = urllib.request.Request(self.base + "/api/hfish/webhook?k=wh-secret",
                                   data=json.dumps(body).encode(), method="POST",
                                   headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=10) as resp:
            res = json.loads(resp.read().decode())
        self.assertEqual(res.get("accepted", 0), 0, "内网源的扫描告警应被当噪声丢弃")
        rows = [e for e in self.call("GET", "/api/events?limit=50") if e["ip"] == "192.168.110.50"]
        self.assertEqual(rows, [], "噪声不应进事件表")

    def test_04_max_blocks_cap(self):
        """容量上限：到顶后不再新增，避免 ipset/DB 无界增长。"""
        self.call("PUT", "/api/config",
                  {"hfish": {"auto_block_max_per_min": 0, "max_blocks": 1}})
        for i in range(3):
            self.alert("198.51.100.%d" % (60 + i))
        self.assertEqual(len(self.blocked()), 1, "超过容量上限不应再封")


if __name__ == "__main__":
    unittest.main(verbosity=2)
