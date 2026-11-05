#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""接口面端到端测试：拉起一个 --fake 守护进程，用真实 HTTP 打全流程。

    python -m unittest discover -s tests -v
    # 或
    python tests/test_api.py

覆盖：鉴权、状态快照、事件流、观察/封禁双模式、白名单豁免、
黑名单解封、配置热加载、凭证轮换、归属地解析、静态页面。
"""
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

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GUARD = os.path.join(ROOT, "fpk", "app", "bin", "guard.py")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


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
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        cls.syslog_port = s.getsockname()[1]
        s.close()
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
        body = {"src_ip": "198.51.100.9", "attack_type": "scan", "class": "Redis",
                "threat_level": "low", "scan_port": 6379}
        r = urllib.request.Request(self.base + "/api/hfish/webhook?k=wh-secret",
                                   data=json.dumps(body).encode(), method="POST",
                                   headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=10) as resp:
            res = json.loads(resp.read().decode())
        self.assertEqual(res["accepted"], 1)
        rows = self.call("GET", "/api/events?limit=50")
        ip = [x for x in rows if x["ip"] == "198.51.100.9"]
        self.assertTrue(ip)
        # low 级不自动封禁
        self.assertNotIn("198.51.100.9", [b["ip"] for b in self.call("GET", "/api/blacklist")])

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
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        new_port = s.getsockname()[1]
        s.close()
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
        self.syslog({"src_ip": "192.0.2.77", "attack_type": "scan", "class": "Redis",
                     "threat_level": "low"})
        rows = self.call("GET", "/api/events?limit=100")
        self.assertIn("192.0.2.77", [r["ip"] for r in rows], "重绑后新端口收不到告警")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
