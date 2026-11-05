# 架构说明：hfish-guard 与 fnos-hive 的关系

本文回答四个问题：两个项目各自负责什么、它们之间怎么协同、本仓库的 Web UI 在整个系统里处于什么位置、以及**按官方文档 HFish 的三条出口具体怎么接进守卫**（第 7 节）。

---

## 1. 一句话定位

| 项目 | 定位 | 关键词 |
|---|---|---|
| **fnos-hive**（蜜罐蜂巢） | 诱捕面：把攻击**骗进来、录下来** | HFish 3.3.7 + Cowrie 3.1.5 + 反向代理，FPK 自包含 |
| **hfish-guard**（蜜罐守卫） | 处置面：把攻击者**认出来、挡回去** | iptables/ipset 计数 + 滑动窗口判定 + 自动封禁 + 值守台 |

两者是**同一台 NAS 上的上下游关系**，不是一个项目的两个模块：hive 可以单独用（只诱捕不封禁），guard 也可以单独用（监视任意 TCP 端口），装在一起才形成「诱捕 → 识别 → 封禁」的闭环。

```
                       ┌──────────────────────────────┐
   攻击者 ── 扫描/爆破 ─▶│  fnos-hive（诱捕面）          │
                       │  HFish :4433/:4434            │
                       │  Cowrie :2022（22 端口转发）   │
                       │  proxy.py :9704（iframe 入口） │
                       └──────────────┬───────────────┘
                                      │ 蜜罐服务端口（6379/9200/9000/2022/7878…）
                                      │ 内核收包
                       ┌──────────────▼───────────────┐
                       │  netfilter（数据面）          │
                       │  INPUT 陷阱规则 → ipset 计数  │
                       │  hfish_guard_seen_<port>      │
                       │  hfish_guard_black → DROP     │
                       └──────────────┬───────────────┘
                                      │ 每 poll 秒读 counters
                       ┌──────────────▼───────────────┐
                       │  hfish-guard（处置面）        │
                       │  guard.py 滑动窗口判定        │
                       │  sqlite 事件/黑名单           │
                       │  REST + UI :9705              │
                       └──────────────────────────────┘
```

---

## 2. 职责分工

### fnos-hive 负责

- 提供**真实可交互的蜜罐服务**（Redis / Elasticsearch / SSH / HTTP 等伪装端口）；
- 记录攻击者的**会话内容**（Cowrie 能录到登录后敲的每条命令、落盘样本）；
- 提供 HFish 自带的攻击态势面板（:4433，经 :9704 反代给飞牛 iframe）；
- **不负责封禁**：HFish 的封禁是针对它自己节点的，不会保护 NAS 上的其他服务。

### hfish-guard 负责

- **计数**：在每个蜜罐端口上挂一条 iptables 陷阱规则，命中的源 IP 进独立 ipset（`hash:ip counters`），零日志洪水；
- **判定**：按 `(源 IP, 端口)` 取包计数增量，滑动窗口汇总，超阈值判定为攻击；
- **处置**：`enforce` 模式把源 IP 写入 `hfish_guard_black` + INPUT DROP（**全端口断网**，含 SSH/Web/文件共享）；`observe` 模式只记录；
- **生命周期**：黑名单 TTL 到期自动解封、白名单内核侧豁免、配置热加载、事件流水留存；
- **可观测**：`:9705` 的 REST 接口与单页值守台。

### 边界（重要）

- guard **不读 HFish/Cowrie 的数据库、不改它们的规则、不依赖它们的进程**。检测与封禁 100% 由 guard 自己的 netfilter 计数完成（原因见 [§7.1](#71-先看清边界hfish-只有读和推没有封)）。
- guard 只在**可选开启**时读 HFish 的官方出口：syslog / webhook（事件富化 + 可选二级封禁）、开放 API（只读情报）。三者都可以不配，不配就等于「纯内核计数」模式，功能完整。
- HFish 升级、重装、换面板端口都不影响守卫；反之卸载 guard 也只清 `hfish_guard_*` 自己的 ipset 与 INPUT 规则（见 `fpk/cmd/uninstall_callback`）。
- 唯一的「强」耦合是**端口清单**：`config.ports` 要覆盖 hive 实际监听的蜜罐端口。这是一份配置，不是代码依赖，改完 UI 里即时热加载。

---

## 3. 三个耦合点（都很轻）

| 耦合 | 实现方式 | 失效后果 |
|---|---|---|
| 端口清单 | `config.json` 的 `ports`，UI「配置」页可改 | 端口没覆盖 → 该服务被攻击时不计数（不误伤） |
| 启动顺序 | systemd `After=hive-honeypot.service`（软依赖 `Wants=`） | hive 后启动也没关系，陷阱规则按端口挂，不依赖进程 |
| 处置效果 | 同一条 `INPUT` 链，DROP 对 hive 的服务同样生效 | 封禁期间蜜罐也收不到该 IP 的包（符合预期） |

端口占用对照：

| 端口 | 归属 | 说明 |
|---|---|---|
| 4433 / 4434 | hive | HFish 面板 / API（仅本机与 LAN 使用） |
| 9704 | hive | proxy.py，飞牛 iframe 入口（剥 `Secure` cookie、`X-Frame-Options`） |
| 2022 / 22 | hive | Cowrie；22 由 iptables REDIRECT 过来 |
| 9210–9226、6379、9200… | hive | HFish 节点蜜罐，面板里勾选后监听 |
| **9705** | **guard** | REST + UI，token 鉴权，仅 LAN |
| — | guard | 不监听任何额外端口，只在内核里挂规则 |

---

## 4. UI 在整个架构中的位置

**UI 是 guard 接口面的一部分，不是独立前端工程**：`guard.py` 用标准库 `http.server` 直接把 `ui/index.html` 吐出来，页面与 API **同源同端口**（`:9705`），因此：

- 没有构建步骤、没有 Node 依赖、没有 CDN——NAS 常年无外网，页面必须离线可用；
- 没有跨域问题，也不需要给 9705 配 Nginx；
- 飞牛桌面用 `ui/config` 里的 `type=iframe` 内嵌 `/web/?token=<安装时生成>`，token 从 URL 进来后写入 `sessionStorage` 并从地址栏抹掉（`history.replaceState`），避免出现在 Referer 里。

数据来源有**双模**，同一个 HTML 文件两种活法：

| 模式 | 触发条件 | 数据来源 | 写操作 |
|---|---|---|---|
| **LIVE** | 页面由 `guard.py` 托管且 token 校验通过（URL `?token=` 或手输） | 每 `poll` 秒拉 `/api/status`、`/api/events`、`/api/blacklist`、`/api/whitelist` | 真调接口：封禁/解封、白名单增删、配置热加载、凭证轮换 |
| **DEMO** | 直接双击打开 HTML、或点登录页「以演示数据预览」 | 内置离线数据集（含 GEO 字典、攻击流、60 点脉冲序列） | 只改内存，用于设计评审 |

顶栏右上角的 `LIVE :9705` / `DEMO` 徽标就是这个状态的显式指示（点击 `LIVE` 徽标 = 断开连接）。

UI 里的地球仪落点、攻击弧线、TOP ORIGINS 全部由 `state.events` 派生；事件归属地优先用后端 `/api/geo`（可接 MaxMind mmdb），后端没有库时回落到内置粗粒度表并标注「网段推算」。

---

## 5. 数据流与判定细节

1. 内核：`iptables -I INPUT -p tcp --dport <port> -m set ! --match-set hfish_guard_white src -j SET --add-set hfish_guard_seen_<port> src`
   → 白名单在**内核侧**就被排除，自家扫描不会进计数，也不会产生日志洪水。
2. `guard.py` 每 `poll` 秒 `ipset list` 读 `packets` 计数，取增量（同 IP 同端口）。
3. 增量累加到 `(ip, port, slot)` 分桶，`slot = now // window`，只保留最近两个窗口。
4. 每个槽内按 IP 汇总；`>= threshold` 且该槽未告警过 → 判定一次（防重复刷屏）。
5. `enforce`：写 `hfish_guard_black` + `blocks` 表（含 `expire`），并清掉该 IP 的 seen 成员与分桶；`observe`：只写 `events`。
6. 每 15 秒检查一次 TTL，到期 `ipset del` + `active=0` + 记 `expired` 事件。
7. 配置 PUT 后立即重挂规则、重刷白名单，不重启进程。

事件表只保留最近 20000 行（后台线程每 10 分钟裁一次）。`verdict` 取值：`over`（超阈值）/ `manual`（手动处置）/ `expired`（TTL 到期）/ 以及不入列表的 `config`/`token`/`system`/`error`。

---

## 6. 安全模型

- **网络边界**：`:9705` 只应对 LAN 开放，不要做端口映射到公网。REST 与页面都靠 token 保护。
- **凭证**：安装时由 `install_callback` 生成随机 token，同时写进 `config.json`（`chmod 600`）与 `ui/config` 的桌面入口；UI 里可一键轮换，轮换后其他会话需重新登录。
- **最小权限**：进程以 root 运行（需要 netfilter），但只执行固定的 ipset/iptables 命令，不接受任何来自 HTTP 的 shell 拼接（IP/CIDR 全部正则校验后再用）。
- **新增入站面要收口**：syslog 端口与 `/api/hfish/webhook` 是外部可写入口。syslog 只依赖「仅 LAN 可达」这条边界（同机部署即只监听本机网段），webhook 必须带 `k=` 校验串、且 `hfish.enabled=false` 时返回 403；两者进来的一切内容都只当**事件数据**，绝不当命令。
- **误封风险**：默认 `observe` 模式，先跑几天看事件表，确认阈值不误伤自家设备后再切 `enforce`；白名单务必先加上管理设备与网关。按等级自动封禁同理——先不配 `auto_block_level`，看清 HFish 的等级分布再配。

---

## 7. HFish 官方联动：三条通路怎么接

> 依据官方文档：[API 配置](https://hfish.net/#/api-config)、[syslog 字段](https://hfish.net/#/syslog)、[告警配置](https://hfish.net/#/detail-alarm)、[安全声明](https://hfish.net/#/security)

### 7.1 先看清边界：HFish 只有「读」和「推」，没有「封」

| 通路 | 方向 | 官方能力 | guard 怎么用 |
|---|---|---|---|
| 开放 API | 拉（guard 主动） | `POST /api/v1/attack/ip?api_key=` 取攻击来源；另有攻击详情、爆破账号两类 | 情报补充：给 IP 打威胁标签 / 累计次数，每 60s 拉一次 |
| syslog | 推（HFish 主动） | TCP 或 UDP，**最多 5 路**，字段固定（见下表） | **主力通路**：事件富化 + 可选按等级封禁 |
| webhook | 推（HFish 主动） | 钉钉 / 飞书 / 企微 / 自定义 | 「自定义」方式直接指向 guard，备用通路 |
| ~~封禁/黑名单写接口~~ | — | **不存在** | 所以封禁只能由 guard 自己在 netfilter 上做 |

这就是「检测不以 HFish 为源」的根因：HFish 只知道自己蜜罐端口上发生的事，且要等它判定、聚合、外发；而 guard 的 ipset 计数覆盖**全部被监视端口**（含蜜罐还没接管的端口、含 HFish 认为不值得告警的低频探测）。两者是**互补**，不是替代：

```
内核 ipset 计数 ──► 阈值判定 ──┬──► 封禁（唯一处置入口）
                              │
HFish syslog/webhook ──► 事件富化 ──┘ 按等级二次判定（可选）
HFish 开放 API ──────► 威胁标签（只读，不参与封禁决策）
```

**HFish 停机、升级、换面板端口，guard 照常工作**；只是事件表里少掉「类型/蜜罐/账号/等级」这些富化字段。

### 7.2 通路 A：syslog（推荐，默认开启）

HFish 面板操作：

1. **告警配置 → 通知配置 → syslog**：填 guard 所在机器 IP + 端口（默认 `5514`），协议选 **UDP 或 TCP**（guard 同时监听两者，选哪个都行）；
2. **告警配置 → 告警策略 → 新增**：类型选「威胁告警」，通知方式勾上刚才那条 syslog；
3. 攻击发生即外发，最长 1 分钟内到达。

guard 侧：UI「配置 → HFish 联动」里勾「接入 HFish 告警」，syslog 端口填 `5514`。端口绑定状态在 `/api/status` 的 `link.hfish.syslog_bound` 里可见（`{"udp":true,"tcp":true}`）。**改端口或开关联动即时生效**：`hfish_reload()` 会停掉旧接收器、按新端口重绑，不需要重启进程（`test_07/08` 覆盖）。

官方 syslog 威胁告警字段（guard 全部解析，缺字段不影响）：

| 字段 | 含义 | guard 用途 |
|---|---|---|
| `src_ip` | 攻击来源 IP | 事件主体；可选按等级封禁 |
| `scan_port` | 被扫端口（可能为 `N/A`） | 事件端口 |
| `attack_type` | `scan`/`attack`/`signon`/`hr_signon`/`compromise` | 写入详情；参与去重键 |
| `type` / `class` | 蜜罐实例 / 蜜罐类型 | 写入详情；参与去重键 |
| `account` | 爆破用的账号 | 写入详情 |
| `threat_level` | `low`/`mid`/`high`/`critical` | **自动封禁的判定依据** |
| `threat_name` / `labels` | 威胁行为名 / 情报标签 | 写入详情 |
| `geo` | 官方地理位置 | 写入详情（不用它覆盖本地归属地） |
| `client` / `client_ip` | 节点名 / 节点 IP | 写入详情 |
| `time` / `info` | 时间 / 攻击详情 | 详情 |

解析是**容错的**：JSON、`key: value`、`key=value`、甚至只有一行带 IP 的纯文本都能吃；系统告警（节点离线、蜜罐离线）没有 `src_ip`，会被计入 `received.skipped` 而不是当成攻击。

### 7.3 通路 B：webhook（自定义）

HFish：**通知配置 → webhook → 自定义**，URL 填

```
http://<NAS_IP>:9705/api/hfish/webhook?k=<webhook_token>
```

`webhook_token` 在 guard 配置里设（`hfish.webhook_token`）；留空则退化为校验主 token（`?token=` 或 `X-Guard-Token` 头）。这个接口**只接受 POST**，且 `hfish.enabled=false` 时直接 403，避免变成公开的事件注入口。

请求体三种形态都认：单条事件对象、`{"events":[...]}`、以及把事件包在 `data`/`content`/`event` 里。返回 `{"ok":true,"accepted":N,"received":M}`。

> 钉钉/飞书/企微的 webhook 是「发给机器人」，guard 不做机器人，所以要用「自定义」这一种。

### 7.4 通路 C：开放 API（可选，只读情报）

HFish：**系统设置 → API 配置 → 开启**，生成 `api_key`，把 guard 所在 IP 加进白名单（同机就填 `127.0.0.1`）。

guard 配置：

| 项 | 示例 | 说明 |
|---|---|---|
| `api_base` | `https://127.0.0.1:4433` | 面板地址，不含 `/api` |
| `api_key` | 面板生成的那串 | 拼成 `?api_key=` |
| `verify_tls` | `false` | HFish 默认自签证书，内网保持 false |

拉到的数据只进 `/api/hfish/intel`（威胁标签、累计攻击次数），**不参与封禁决策**——官方这个接口是聚合视图，有分钟级延迟，用它封禁会误伤。拉取失败不影响任何其他功能，状态在 `hfish.api_error` 里。

### 7.5 按等级自动封禁

配了 `auto_block_level`（`low`/`mid`/`high`/`critical`）后，HFish 推来的告警只要**等级 ≥ 阈值**且 `mode=enforce`，就直接封禁并记 `verdict=hfish` 的事件；否则只记录。

```
LEVEL_RANK = {"":0, low:1, mid/medium:2, high:3, critical:4, 低:1, 中:2, 高:3, 严重:4}
```

设计上刻意加了三个闸门：**必须是 enforce 模式**、**必须等级达到**、**同一 `(IP, 攻击类型, 蜜罐)` 60 秒内只处理一次**（挡告警洪水）。白名单里的 IP 在入口就被丢掉。

### 7.6 部署与防火墙

| 项 | 要求 |
|---|---|
| HFish 面板 4433 | **绝不要**映射到公网（官方安全声明原话）；guard 拉 API 走 `127.0.0.1` 即可 |
| guard 9705 | 仅 LAN；REST 与页面都靠 token |
| guard syslog 端口 | 对 HFish 管理端开放（同机即 `127.0.0.1`/`0.0.0.0:5514`，guard 不做来源 IP 限制，靠「只有 LAN 能到」这条边界） |
| webhook | 必须带 `k=`，否则等于把事件注入口暴露给 LAN 内任意进程 |

一个常见坑：syslog 端口被系统 `rsyslog` 占了。`netstat -lnup | grep 5514` 确认没被监听；被占就换个端口（HFish 通知配置里同步改）。

---

## 8. 开发与联调

Windows / 无 root 的开发机上没有 ipset，用 `--fake` 跑内存态内核 + 攻击模拟器，整条判定链路与线上一致：

```bash
python fpk/app/bin/guard.py --fake --port 9706 --data ./tmp
# 浏览器打开 http://127.0.0.1:9706/web/?token=<tmp/config.json 里的 token>
```

```bash
python tests/test_api.py        # 12 个接口端到端用例（鉴权/事件/封禁/白名单/配置/凭证）
bash scripts/build-fpk.sh       # 产出 dist/hfish-guard.fpk
```

UI 自带无头自检：`index.html?selftest=1` 会跑 54 项断言并把结果写进 `document.title`，适合 CI 里 `--dump-dom` 抓取。
