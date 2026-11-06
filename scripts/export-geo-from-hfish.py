# -*- coding: utf-8 -*-
"""在 ECS 上从 HFish 库导出 ip → 归属地 的 geo.json。

用法（ECS 上执行，HFish 用 SQLite 的那台）：
    python3 export-geo-from-hfish.py > /tmp/geo.json
    scp /tmp/geo.json admin@<NAS>:/vol2/@appdata/hfish-guard/geo.json
    systemctl restart hfish-guard


HFish 自己就把归属地解析好了（scanners/infos 的 source_ip_country 字段，
形如「美国」「中国-江苏-无锡」），别浪费。

守卫的 Geo 读取顺序：geo.json 精确匹配 → mmdb → 内置推算表。
所以这份表当「已知攻击源速查表」用，未命中的 IP 仍会走 mmdb。
"""
import json
import sqlite3
import sys

CC_ZH = {}


def load_cc_zh():
    """从守卫源码里拿 ISO→中文映射，保证两边一致。"""
    for path in ("/vol2/@appcenter/hfish-guard/bin/guard.py",
                 "/vol2/@appdata/hfish-guard/guard.py"):
        try:
            src = open(path, encoding="utf-8").read()
        except OSError:
            continue
        start = src.find("CC_ZH = {")
        if start < 0:
            continue
        end = src.find("}", start)
        body = src[start + len("CC_ZH = {"):end]
        for line in body.splitlines():
            line = line.strip().strip(",").strip('"')
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            CC_ZH[k.strip().strip('"')] = v.strip().strip('"').strip(",")
        break
    if not CC_ZH:                      # 兜底：守卫里读不到就硬编码几组常见的
        CC_ZH.update({"US": "美国", "CN": "中国", "RU": "俄罗斯", "KR": "韩国",
                      "JP": "日本", "TW": "中国台湾", "HK": "中国香港",
                      "SG": "新加坡", "IN": "印度", "BR": "巴西", "FR": "法国",
                      "DE": "德国", "GB": "英国", "NL": "荷兰", "VN": "越南",
                      "TH": "泰国", "ID": "印度尼西亚", "MY": "马来西亚",
                      "PH": "菲律宾", "PK": "巴基斯坦", "TR": "土耳其",
                      "UA": "乌克兰", "IL": "以色列", "AE": "阿联酋",
                      "SA": "沙特阿拉伯", "EG": "埃及", "NG": "尼日利亚",
                      "ZA": "南非", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
                      "MX": "墨西哥", "CA": "加拿大", "AU": "澳大利亚",
                      "IT": "意大利", "ES": "西班牙", "SE": "瑞典", "PL": "波兰",
                      "RO": "罗马尼亚", "CZ": "捷克", "GR": "希腊", "AT": "奥地利",
                      "CH": "瑞士", "BE": "比利时", "IE": "爱尔兰", "FI": "芬兰",
                      "NO": "挪威", "DK": "丹麦", "PT": "葡萄牙", "KZ": "哈萨克斯坦"})


def main():
    load_cc_zh()
    rev = {}
    for iso, name in CC_ZH.items():
        rev.setdefault(name, iso)
    db = "/usr/share/hfish/database/hfish.db"
    conn = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    out = {}
    for table in ("scanners", "infos"):
        try:
            rows = conn.execute(
                "select distinct source_ip, source_ip_country from %s" % table).fetchall()
        except sqlite3.Error as e:
            print("skip %s: %s" % (table, e), file=sys.stderr)
            continue
        for ip, country in rows:
            if not ip or not country:
                continue
            country = str(country).strip()
            if country in ("本机地址", "内网地址", "-", ""):
                continue
            city = "-"
            cn = country
            if "-" in country:
                parts = [p.strip() for p in country.split("-") if p.strip()]
                if len(parts) == 2:
                    cn, city = parts[0], parts[1]
                elif len(parts) > 2:
                    # 「中国-内蒙古-呼和浩特」→ 国=中国，城市=呼和浩特
                    cn, city = parts[0], parts[-1]
            out[ip] = {"cc": rev.get(cn, "--"), "cn": cn, "city": city,
                       "lat": None, "lon": None, "org": "HFish 情报"}
    print(json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
