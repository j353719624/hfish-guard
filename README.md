# hfish-guard · 蜜罐守卫

与 [fnos-hive](https://github.com/j353719624/fnos-hive) 蜜罐联动的 fnOS FPK 应用：**蜜罐端口被触碰即计数，超过阈值自动拉黑攻击来源 IP**。标准 FPK 应用（Python 标准库守护进程 + 内置单页值守台），不是松散脚本。

> hive 负责「诱捕」，guard 负责「处置」。两者的职责边界、耦合点和数据流见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 整体架构

```
数据面（内核 netfilter，双栈 IPv4 + IPv6，TCP + UDP，每端口 10 条规则 + 2 条全局 DROP）
  记名：目的端口 ∈ 蜜罐端口的包 → 源 IP 进 ipset hfish_guard_seen_<端口>（IPv6 走 seen_6_<端口>）
        （白名单在内核侧 ! --match-set 豁免，不计包、不产生事件）
  判定：-m hashlimit 按源 IP 计速率，超过「阈值 / 窗口」即写命中池
        封禁模式 enforce → hfish_guard_black / black6（顶部 DROP 规则全端口断网）
        观察模式 observe → hfish_guard_alert / alert6（只记名，用户态取走后清空）
  扫描面：用户态每轮读 seen 集合，同一源命中 ≥ scan_ports 个不同蜜罐端口即判端口扫描
控制面（guard.py 守护，python3 标准库，systemd 托管）
  每 poll 秒：读各端口规则的包计数器（iptables -vnxL，精确值）→ 流量曲线与端口热度
             读命中池：black 新增成员 → 落库 + 记「自动封禁」事件 + 管 TTL
                       alert 成员   → 记「观察记录」事件后清空（允许再次触发）
接口面（:9705，token 鉴权）
  REST API + 单页 UI：全球态势 / 状态总览 / 事件流水 / 黑名单 / 白名单 / 联动配置
联动面（可选，消费 HFish 官方出口；不开启则退化为纯内核计数）
  syslog :5514（UDP+TCP）· webhook /api/hfish/webhook · 开放 API 只读情报
存储面（/vol2/@appdata/hfish-guard）
  config.json（配置与凭证）+ guard.db（事件流水、黑名单，sqlite3）
```

### 为什么判定放在内核（一个真机踩出来的坑）

最初版本靠轮询 ipset 每个成员的 `packets` 计数器做增量，再在用户态累计窗口——真机实测这个方案**根本不会触发**：ipset 的 `packets` 只在条目被创建时记 1，后续同源包不累加，连 `ipset add -exist` 都保持 0。也就是说计数器永远停在 1，阈值永远够不到。

现在改成：内核用 `hashlimit` 直接判定（`--hashlimit-above 阈值/窗口 --hashlimit-burst 阈值`，`--hashlimit-mode srcip`），用户态只负责「取走命中 → 落库 → 管 TTL」。流量曲线仍读每条端口规则自己的包计数器（`iptables -vnxL` 的精确值），所以态势图上的数值是真的。

## 与蜜罐（fnos-hive）的联动方式

- **端口面联动**：守卫监视的端口列表 = 蜜罐服务端口（默认 6379,9200,9000,8080,8081,9198,9080,9092,2022,7878）。hive 侧改了服务端口，在守卫 UI 里同步改监视端口即可，**即时生效、无需重启**；
- **不耦合 HFish 内部**：不读 HFish 数据库、不改它的规则、不依赖它的进程；HFish 的 syslog/webhook/OpenAPI 是**可选**的富化输入（见下节），不配也完整可用，HFish 升级 / 重装 / 换面板端口都不受影响；
- **systemd 依赖编排**：`After=hive-honeypot.service`、`Wants=` 软依赖 —— 蜜罐先起、守卫后起；hive 没装也能单独跑；
- **封禁效果共享**：DROP 规则在 `INPUT` 链上，对蜜罐与 NAS 上的所有服务同时生效——这正是「处置面」的意义。

## 接入 HFish 官方告警（可选，推荐）

官方文档已经确认：HFish 对外只有**读**和**推**三种出口，**没有封禁/黑名单写接口**。所以守卫的检测永远走内核 ipset 计数（覆盖全部被监视端口），HFish 的出口只用来做**事件富化**和**可选的按等级封禁**。三条通路都可以不配，不配就是纯内核计数模式。

| 通路 | 方向 | 在 HFish 里怎么配 | 在守卫里怎么配 |
|---|---|---|---|
| **syslog**（推荐） | HFish 推 | 告警配置 → 通知配置 → syslog：填 `<NAS_IP>` + 端口 `5514`，协议 UDP 或 TCP（守卫同时监听两者）→ 告警策略 → 新增 → 类型「威胁告警」→ 勾这条 syslog | 配置页勾「接入 HFish 告警」，syslog 端口填 `5514` |
| **webhook** | HFish 推 | 告警配置 → 通知配置 → webhook → **自定义**，URL 填 `http://<NAS_IP>:9705/api/hfish/webhook?k=<webhook_token>` | 配置页填 `webhook_token`（留空则退化为主 token 校验） |
| **开放 API** | 守卫拉（只读） | 系统设置 → API 配置 → 开启、生成 `api_key`、允许 `127.0.0.1` | 填 `api_base=https://127.0.0.1:4433`、`api_key`、`verify_tls=false` |

syslog 官方字段全部解析（`src_ip` / `scan_port` / `attack_type` / `type` / `class` / `account` / `threat_level` / `threat_name` / `labels` / `geo` / `client` / `time` / `info`），且**容错**：JSON、`key: value`、`key=value`、只有一行带 IP 的纯文本都能吃；节点离线这类系统告警没有 `src_ip`，只计入 `skipped`，不会当成攻击。

配了 `auto_block_level` 后，等级达到且模式为 `enforce` 时**直接封禁**并记 `verdict=hfish` 事件；否则只记录。闸门：必须 enforce、必须达等级、同 `(IP, 攻击类型, 蜜罐)` 60 秒内只处理一次（挡告警洪水）、每分钟封禁数不超 `auto_block_max_per_min`、黑名单不超 `max_blocks`。白名单 IP 在入口即丢弃。

**要“收到就封”必须选 `all`**：HFish 对蜜罐命中给的等级是 `other`，不是 `high`/`mid`。只配 `high` 的话，真机上一条都不会封（实测 14 条蜜罐告警全是 `other`）。`all` 表示不挑等级（含未标等级），配合熔断与容量上限使用。

联通状态在 `/api/status` 的 `link.hfish` 字段：`syslog_bound`（`{"udp":true,"tcp":true}`）、`received`（`{"syslog":N,"webhook":N,"skipped":N}`）、`api_ok` / `api_error` / `intel_count`。**改 syslog 端口或开关联动都即时生效**（接收器按配置重绑，不用重启进程）。

> 安全：**4433 绝不要映射到公网**（官方安全声明原话），守卫拉 API 走 `127.0.0.1`；9705 只对 LAN 开放；syslog 端口若被 `rsyslog` 占用（`netstat -lnup | grep 5514`）就换一个，HFish 通知配置里同步改。

细节（字段表、请求体形态、去重键、为什么不拿 HFish 当检测源）见 [docs/ARCHITECTURE.md §7](docs/ARCHITECTURE.md)。

## 核心功能模块

| 模块 | 说明 |
|---|---|
| 检测器 | 每端口一条 iptables 陷阱（记名 + 规则级包计数）+ 一条 `hashlimit` 判定规则 |
| 判定器 | 内核 `hashlimit` 按源 IP 计速率（TCP/UDP × IPv4/IPv6 四套），超过「阈值 / 窗口」即命中；白名单内核侧豁免 |
| 扫描器 | 同一源在窗口内命中 ≥ `scan_ports` 个不同蜜罐端口 → 判端口扫描（可配是否直接封禁） |
| 执行器 | ipset 黑名单 + iptables DROP；观察/封禁双模式；规则幂等可重装；重启后自动回填生效封禁 |
| 过期器 | 黑名单 TTL 自动解封（默认 3600s，0 = 永久） |
| 日志器 | sqlite 事件流水（时间/IP/端口/包数/判定/动作/详情），自动裁剪至最近 2 万条 |
| 值守台 | 单文件 UI：地球仪攻击态势、事件下钻、手动封禁/解封、白名单增删、阈值与模式热加载、凭证轮换 |

## 值守台（UI）说明

`fpk/app/ui/index.html` 是**单文件、零外部依赖**的页面（无 CDN、无构建、无图片请求），由 `guard.py` 在 `:9705` 同源托管，飞牛桌面通过 `ui/config` 的 iframe 入口打开 `/web/?token=<安装时生成>`。

- **LIVE 模式**：token 校验通过后每 `poll` 秒拉 `/api/status|events|blacklist|whitelist`，所有操作直接落到后端；顶栏右上角显示 `LIVE :9705`，点击即断开；
- **DEMO 模式**：直接双击 HTML，或点登录页「以演示数据预览」，用内置离线数据展示（设计评审用），顶栏显示 `DEMO`；
- 页面自带自检：`index.html?selftest=1` 跑 54 项断言（布局、联动、鉴权、图表、响应式），结果写入 `document.title`。

## 配置项（UI 内修改，即时生效）

| 配置 | 默认 | 说明 |
|---|---|---|
| mode | observe | observe=只记录；enforce=自动拉黑 |
| threshold | 40 | 窗口期内命中包数阈值 |
| window | 60 | 滑动窗口秒数 |
| poll | 10 | 轮询间隔秒数 |
| ttl | 3600 | 黑名单过期秒数，0=永久 |
| ports | 蜜罐端口列表 | 监视的蜜罐端口（与 hive 服务保持一致） |
| udp | true | 是否同时 trap UDP（蜜罐端口上的 UDP 探测） |
| scan_ports | 6 | 同源命中多少个不同蜜罐端口算扫描，0=关闭 |
| scan_block | true | 判定为扫描时是否直接封禁（仅 enforce 生效） |
| whitelist | 空 | 永不计数、永不封禁的 IP / CIDR（内核侧豁免） |
| hfish.enabled | false | 是否接收 HFish 告警（syslog / webhook） |
| hfish.syslog_port | 5514 | syslog 监听端口，UDP + TCP 同时绑定 |
| hfish.auto_block_level | 空 | 达此等级自动封禁：`all`（收到就封）/`low`/`mid`/`high`/`critical`，空=不自动封 |
| hfish.auto_block_max_per_min | 120 | 自动封禁熔断：每分钟最多封多少个，超出只记事件；0=不限 |
| hfish.max_blocks | 20000 | 黑名单容量上限，到顶不再新增；0=不限 |
| hfish.api_base / api_key / verify_tls | 空 / 空 / false | HFish 开放 API（只读情报），默认自签证书 |
| hfish.webhook_token | 空 | `/api/hfish/webhook` 的校验串，空则用主 token |

API 全部鉴权：`Authorization: Bearer <token>`，或 GET 用 `?token=`（供 iframe 入口）。凭证在安装时随机生成，写入 `config.json`（0600）并注入桌面入口；UI 配置页可一键轮换。

### REST 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 免鉴权探活（版本、内核层状态） |
| GET | `/api/status` | 模式/阈值/端口/窗口序列/端口监听状态/联动信息/最近事件 |
| GET | `/api/events?limit=&filter=&q=` | 事件流水（`filter=over` 只取超阈值） |
| GET/POST/DELETE | `/api/blacklist` · `/api/blacklist/{ip}` | 黑名单查询 / 手动封禁 / 解封 |
| GET/POST/DELETE | `/api/whitelist` · `/api/whitelist/{cidr}` | 白名单查询 / 新增 / 移除 |
| GET/PUT | `/api/config` | 读取 / 热加载配置 |
| POST | `/api/token` | 重新生成凭证 |
| GET | `/api/geo?ip=` 或 `?ips=a,b,c` | 归属地（mmdb > geo.json > 内置粗表） |
| GET | `/api/ports` | 每端口监听/计数/陷阱状态 |
| GET | `/api/hfish/intel` | HFish 开放 API 拉到的情报（只读） |
| POST | `/api/hfish/webhook?k=` | 接收 HFish 自定义 webhook（独立校验串） |
| POST | `/api/simulate` | 仅 `--fake` 模式：注入流量，供自测 |

## 安装

```bash
fnos-cli app install-fpk hfish-guard.fpk --yes
```

装完即启动、开机自启、崩溃自愈（systemd `Restart=always`）。桌面出现「蜜罐守卫」图标，点开即管理界面。

> 应用中心的「停止」按钮会先 `systemctl stop` 再兜底 `pkill`，不会被 `Restart=always` 打回原形（`fpk/cmd/main`）。

## 卸载

应用中心卸载会：停守护 → 删除本应用的 iptables 规则与全部 `hfish_guard_*` ipset（含每端口的 `seen_<port>`）→ 删除 systemd 单元。蜜罐本体（hive）与守卫数据（`/vol2/@appdata/hfish-guard`）保留。

## 开发与联调

```bash
# 无 root / Windows：内存态内核 + 攻击模拟器，判定链路与线上一致
python fpk/app/bin/guard.py --fake --port 9706 --data ./tmp
# 打开 http://127.0.0.1:9706/web/?token=<./tmp/config.json 里的 token>

python tests/test_api.py     # 18 个端到端用例（鉴权/事件/封禁/白名单/配置/凭证/HFish 接入）
bash scripts/build-fpk.sh    # 产出 dist/hfish-guard.fpk
```

依赖：Python 3.6+ 标准库。可选：`geoip2` + `GeoLite2-City.mmdb`（放在数据目录即可自动启用精确归属地）。

## 故障排查

| 现象 | 排查 |
|---|---|
| 页面能开但全是 0 | `HFISH_GUARD_VERBOSE=1` 看日志；确认 `config.ports` 与蜜罐实际端口一致 |
| `trap=false` | 非 root 或 ipset 未安装；`ipset list -n | grep hfish_guard` 看集合是否建出来 |
| 规则不生效 | 检查是否有其他防火墙（docker/ufw）在前面 DROP；`iptables -L INPUT -n --line-numbers` 看规则序号 |
| 封禁没解除 | `ttl=0` 是永久封禁；TTL 到期检查每 15 秒一次 |
| iframe 白屏 | 确认入口是 `http://<NAS>:9705/web/?token=...`；页面不带 `X-Frame-Options`，可内嵌 |
| syslog 收不到 | `netstat -lnup \| grep 5514` 看端口是否被 rsyslog 占用；HFish「告警策略」是否勾了这条 syslog、类型选了「威胁告警」；`/api/status` 的 `hfish.received.skipped` 在涨说明收到了但被判无效（多为系统告警无 `src_ip` 或撞了 60s 去重） |
| webhook 返回 401/403 | 403 = `hfish.enabled` 没开；401 = URL 里的 `k=` 与 `hfish.webhook_token` 不一致 |
| `api_ok=false` | `api_error` 里通常是证书（保持 `verify_tls=false`）或 key 未加入白名单；同机填 `127.0.0.1` |
| 凭证丢失 | `cat /vol2/@appdata/hfish-guard/config.json`，或删掉 token 字段后重启自动重建 |

## 注意

- 默认**观察模式**：先跑几天看事件表，确认阈值不会误伤自家设备，再切「封禁模式」；
- 白名单默认为空，**务必先加**管理设备、网关、监控探针（内核侧豁免，不产生计数）；
- 失陷蜜饵回调端口 7878 也在监视列表——家内设备打开蜜饵被记录正是该功能的用途；
- 封禁是**全端口 DROP**，包含 SSH/Web/文件共享，误封只能从其他机器或控制台解封。

## License

MIT
