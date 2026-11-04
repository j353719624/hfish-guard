# hfish-guard · 蜜罐守卫

与 [fnos-hive](https://github.com/j353719624/fnos-hive) 蜜罐联动的 fnOS FPK 应用：**蜜罐端口被触碰即计数，超过阈值自动拉黑攻击来源 IP**。标准 FPK 应用（Python 守护 + 内置 Web 界面），非松散脚本。

## 整体架构

```
数据面（内核 iptables/ipset）
  陷阱规则：目的端口 ∈ 蜜罐端口列表 的包 → 源 IP 记入 ipset hfish_guard_seen
  （hash:ip counters，带 120s 自动超时；白名单 ipset 豁免；零日志洪水）
控制面（guard.py 守护，python3 stdlib，systemd 托管）
  每 10s 轮询 seen 集合 → 包计数增量 → 滑动窗口（默认 60s）汇总
  → 超阈值（默认 40）触发：
      封禁模式：源 IP 进 hfish_guard_black + INPUT DROP（全端口断网）
      观察模式：只记录事件（默认，最安全）
  → 黑名单 TTL 自动过期（默认 24h，可设永久）→ 自动解封
接口面（:9705，token 鉴权）
  REST API + 单页 UI：状态总览 / 攻击事件 / 黑名单管理 / 白名单管理 / 联动配置
存储面（/vol2/@appdata/hfish-guard）
  config.json（配置与 token）+ guard.db（事件流水、黑名单，sqlite）
```

## 与蜜罐的联动方式

- **端口面联动**：守卫监视的端口列表 = 蜜罐服务端口（默认 6379,9200,9000,8080,8081,9198,9080,9092,2022,7878）。蜜罐侧改了服务端口，在守卫 UI 里同步改监视端口即可，即时生效；
- **不耦合 HFish 内部**：不调用 HFish API、不读它的数据库，HFish 升级/重装不受影响；
- **systemd 依赖编排**：`After=hive-honeypot.service`，蜜罐先起、守卫后起。

## 核心功能模块

| 模块 | 说明 |
|---|---|
| 检测器 | iptables 陷阱 + ipset counters，按来源 IP 精确计数 |
| 判定器 | 滑动窗口阈值（可配），白名单豁免，防重放（已封 IP 不重复计数） |
| 执行器 | ipset 黑名单 + iptables DROP；观察/封禁双模式；规则幂等可重装 |
| 过期器 | 黑名单 TTL 自动解封（默认 24h，0=永久） |
| 日志器 | sqlite 事件流水（时间/IP/命中数/动作/详情），UI 展示最近 100 条 |
| 管理器 | Web UI：手动封禁/解封、白名单增删、阈值与模式配置、状态总览 |

## 配置项（UI 内修改，即时生效）

| 配置 | 默认 | 说明 |
|---|---|---|
| mode | observe | observe=只记录；block=自动拉黑 |
| threshold | 40 | 窗口期内命中包数阈值 |
| window | 60 | 滑动窗口秒数 |
| ttl | 86400 | 黑名单过期秒数，0=永久 |
| ports | 蜜罐端口列表 | 监视的蜜罐端口（与 hive 服务保持一致） |
| whitelist | 本机/网关/用户 PC | 永不触发与封禁的 IP |

UI 访问带随机 token（安装时自动生成并注入飞牛桌面入口），API 全部鉴权。

## 安装

```bash
fnos-cli app install-fpk hfish-guard.fpk --yes
```

装完即启动、开机自启、崩溃自愈（systemd Restart=always）。桌面出现「蜜罐守卫」图标，点开即管理界面。

## 卸载

应用中心卸载会：停守护 → 清理本应用的 iptables 规则与 ipset → 删除单元。蜜罐本体（hive）与守卫数据（`/vol2/@appdata/hfish-guard`）保留。

## 注意

- 默认**观察模式**：先跑几天看事件表，确认阈值不会误伤自家设备，再切「封禁模式」；
- 白名单务必包含你常用的管理设备（默认已含 192.168.110.36/97、网关）；
- 失陷蜜饵回调端口 7878 也在监视列表——家内设备打开蜜饵被记录正是该功能的用途。

## License

MIT
