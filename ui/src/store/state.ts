// ============================================================
// 全局状态：一个 reactive 对象 + 轮询调度
// 不引 Pinia —— 这个应用状态简单，少一个依赖少一份负担
// ============================================================
import { reactive, computed } from 'vue'
import { api, ApiError, getToken, setToken, clearToken, type Status, type EventItem, type BlacklistItem, type WhitelistItem, type GuardConfig, type Geo } from '@/api/guard'

export type ViewName = 'status' | 'events' | 'blacklist' | 'whitelist' | 'config'

export const state = reactive({
  authed: false,
  view: 'status' as ViewName,
  demo: false,

  // 数据
  status: null as Status | null,
  events: [] as EventItem[],
  blacklist: [] as BlacklistItem[],
  whitelist: [] as WhitelistItem[],
  config: null as GuardConfig | null,

  // 运行态
  loading: false,
  error: '',
  lastSync: 0,
  connected: false,
  fails: 0,

  // 视图内状态
  eventFilter: 'all' as 'all' | 'over' | 'banned' | 'exempt',
  eventQuery: '',
  eventPage: 1,
  pageSize: 20,
  geoCache: {} as Record<string, Geo>,
  toast: null as null | { text: string; kind: 'ok' | 'warn' | 'err' },
  toastTimer: 0
})

export const isEnforce = computed(() => state.status?.mode === 'enforce')
export const geoOf = (ip: string): Geo | null => state.geoCache[ip] || null

export function notify(text: string, kind: 'ok' | 'warn' | 'err' = 'ok'): void {
  state.toast = { text, kind }
  clearTimeout(state.toastTimer)
  state.toastTimer = window.setTimeout(() => { state.toast = null }, 3600)
}

export function fmtTime(ts: number): string {
  const d = new Date(ts > 1e11 ? ts / 1000 : ts * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

export function fmtDuration(sec: number): string {
  if (sec <= 0) return '已过期'
  if (sec < 60) return `${sec} 秒`
  if (sec < 3600) return `${Math.floor(sec / 60)} 分 ${sec % 60} 秒`
  if (sec < 86400) return `${Math.floor(sec / 3600)} 小时 ${Math.floor((sec % 3600) / 60)} 分`
  return `${Math.floor(sec / 86400)} 天 ${Math.floor((sec % 86400) / 3600)} 小时`
}

// ---------------------------------------------------------------- 同步

let syncing = false

export async function sync(force = false): Promise<void> {
  if (!state.authed) return
  if (state.demo) {
    // 演示态：本地样例已就绪，不去打扰后端
    return
  }
  if (syncing) return
  const poll = state.status?.poll || 10
  if (!force && Date.now() - state.lastSync < Math.max(2, poll) * 1000) return
  syncing = true
  try {
    const [st, evs, bl, wl, cfg] = await Promise.all([
      api.status(),
      api.events(200),
      api.blacklist(500),
      api.whitelist(),
      api.config()
    ])
    state.status = st
    state.events = evs
    state.blacklist = bl
    state.whitelist = wl
    state.config = cfg
    state.lastSync = Date.now()
    state.connected = true
    state.fails = 0
    state.error = ''
    warmGeo()
  } catch (e) {
    state.fails++
    if (e instanceof ApiError && e.status === 401) {
      clearToken()
      state.authed = false
      state.connected = false
      notify('凭证已失效，请重新输入', 'err')
    } else if (state.fails >= 3) {
      state.connected = false
      state.error = (e as Error).message || '与守护进程的连接中断'
    }
  } finally {
    syncing = false
  }
}

// 归属地批量补查：事件与黑名单里的 IP 都补上
let geoAsked: Record<string, boolean> = {}
const PRIVATE_RE = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fc|fd|fe80)/i

export function warmGeo(): void {
  const list: string[] = []
  const seen: Record<string, boolean> = {}
  const pick = (ip: string) => {
    if (!ip || state.geoCache[ip] || PRIVATE_RE.test(ip) || seen[ip] || geoAsked[ip]) return
    seen[ip] = true
    list.push(ip)
  }
  state.events.forEach(e => pick(e.ip))
  state.blacklist.forEach(b => pick(b.ip))
  if (!list.length) return
  const batch = list.slice(0, 60)
  batch.forEach(ip => { geoAsked[ip] = true })
  api.geo(batch).then(res => {
    ;(res.items || []).forEach(g => {
      if (g && g.ip) state.geoCache[g.ip] = g
    })
  }).catch(() => { /* 归属地查不到不影响主流程 */ })
}

// ---------------------------------------------------------------- 登录

export async function login(token: string): Promise<boolean> {
  setToken(token)
  try {
    const h = await api.health()
    if (!h.auth) {
      // health 不校验 token，用 status 试一次
      await api.status()
    }
    state.authed = true
    state.demo = false
    await sync(true)
    return true
  } catch (e) {
    clearToken()
    state.authed = false
    throw e
  }
}

export function enterDemo(): void {
  state.authed = true
  state.demo = true
  state.connected = false
  loadDemoData()
}

/**
 * 演示数据 —— 门上的「预览界面」按钮必须真的给出内容，
 * 否则点进去是一张空面板（这正是 v1.6 那版「大片空白」的由来）。
 * 数据全部用 RFC 5737 文档保留网段，不会被误当成真实攻击源。
 */
export function loadDemoData(): void {
  const now = Math.floor(Date.now() / 1000)
  const demoPorts = [22, 23, 3306, 6379, 9200]

  state.status = {
    app: 'hfish-guard', version: 'demo', mode: 'observe',
    threshold: 40, window: 60, poll: 10, ttl: 3600,
    udp: true, scan_ports: 6, scan_block: true,
    ports: demoPorts, whitelist: [], blacklist_count: 3, events_count: 6,
    trap: true,
    geo: { source: 'demo', mmdb: '', custom: 0, ready: true },
    kernel: { kind: 'demo', available: true, reason: '', v6: true, v6_reason: '', rules: { v4: 3, v6: 3 } },
    degraded: false, fake: true,
    last_poll: now, uptime: 3600,
    total_packets: 12048, window_sum: 37, top_src: 4,
    window_series: Array.from({ length: 60 }, (_, i) => [
      now - (59 - i) * 10,
      Math.round(18 + 14 * Math.sin(i / 4.5) + (i % 9) * 1.7)
    ] as [number, number]),
    per_port: { '22': 128, '23': 64, '3306': 41, '6379': 27, '9200': 12 },
    port_last: Object.fromEntries(demoPorts.map(p => [String(p), now - p])),
    port_state: demoPorts.map((p, i) => ({
      port: p, listening: true, hits: 128 - i * 23, live_hits: 4 - i % 3, last: now - p, trapped: true
    })),
    link: {
      hive: { installed: true, dirs: ['/vol1/@appdata/hfish'] },
      hfish: {
        enabled: true, syslog_port: 1514,
        syslog_bound: { udp: true, tcp: true },
        api_configured: false, api_ok: false, api_error: '',
        last_pull: now - 300, intel_count: 0,
        auto_block_level: 'all', auto_block_max_per_min: 20,
        max_blocks: 2000, scan_fanout: 8,
        received: { syslog: 137, webhook: 0, skipped: 4, last: now - 12 }
      },
      ports_watched: demoPorts.length, ports_listening: demoPorts.length
    },
    geo_source: 'demo',
    recent: []
  }

  state.events = [
    { id: 'EV-D1', ts: (now - 12) * 1000, ip: '203.0.113.10', port: 22, packets: 412, verdict: 'over', action: '已封禁', detail: '窗口内 412 包，超阈值 40/60s' },
    { id: 'EV-D2', ts: (now - 46) * 1000, ip: '198.51.100.23', port: 3306, packets: 128, verdict: 'scan', action: '端口扫描', detail: '同源命中 6 个端口' },
    { id: 'EV-D3', ts: (now - 88) * 1000, ip: '45.148.10.77', port: 6379, packets: 96, verdict: 'hfish', action: '蜜罐告警', detail: 'HFish 捕获 redis 未授权访问尝试' },
    { id: 'EV-D4', ts: (now - 134) * 1000, ip: '203.0.113.10', port: 23, packets: 61, verdict: 'over', action: '已封禁', detail: '同一来源的重复试探' },
    { id: 'EV-D5', ts: (now - 210) * 1000, ip: '192.0.2.44', port: 9200, packets: 12, verdict: 'normal', action: '仅计包', detail: '低于阈值，未处置' },
    { id: 'EV-D6', ts: (now - 320) * 1000, ip: '198.51.100.23', port: 9200, packets: 7, verdict: 'expired', action: '已解封', detail: 'TTL 到期自动放行' }
  ]

  state.blacklist = [
    { ip: '203.0.113.10', at: (now - 12) * 1000, expire: now + 3600, port: 22, packets: 412, ttl: 3600, permanent: false, left: 3488, reason: '窗口内包数超阈值' },
    { ip: '198.51.100.23', at: (now - 46) * 1000, expire: now + 3600, port: 3306, packets: 128, ttl: 3600, permanent: false, left: 3514, reason: '端口扫描扇出超限' },
    { ip: '45.148.10.77', at: (now - 88) * 1000, expire: now + 3600, port: 6379, packets: 96, ttl: 3600, permanent: false, left: 3472, reason: 'HFish 蜜罐告警' }
  ]

  state.whitelist = [
    { cidr: '127.0.0.1', note: '本机回环', at: (now - 3600) * 1000 },
    { cidr: '192.168.0.0/16', note: '内网网段', at: (now - 7200) * 1000 }
  ]

  // 配置必须是完整结构 —— 配置页直接读 cfg.hfish.enabled，
  // 缺字段会直接把模板渲染炸掉（页面一片空白）。
  state.config = {
    mode: 'observe', threshold: 40, window: 60, poll: 10, ttl: 3600,
    udp: true, scan_ports: 6, scan_block: true,
    ports: demoPorts.slice(),
    whitelist: state.whitelist.slice(),
    token: 'demo-token',
    hfish: {
      enabled: true, syslog_port: 1514,
      auto_block_level: 'all', auto_block_max_per_min: 20,
      scan_fanout: 8, max_blocks: 2000,
      api_base: '', api_key: '', webhook_token: ''
    },
    token_set: true
  }

  // 归属地缓存：演示态没有后端可查，地球仪与地域列需要它才有落点
  state.geoCache = {
    '203.0.113.10': { ip: '203.0.113.10', cc: 'US', cn: '美国', city: '旧金山', lat: 37.7749, lon: -122.4194, org: 'demo', source: 'demo' },
    '198.51.100.23': { ip: '198.51.100.23', cc: 'DE', cn: '德国', city: '法兰克福', lat: 50.1109, lon: 8.6821, org: 'demo', source: 'demo' },
    '45.148.10.77': { ip: '45.148.10.77', cc: 'CN', cn: '中国', city: '香港', lat: 22.3193, lon: 114.1694, org: 'demo', source: 'demo' },
    '192.0.2.44': { ip: '192.0.2.44', cc: 'JP', cn: '日本', city: '东京', lat: 35.6762, lon: 139.6503, org: 'demo', source: 'demo' }
  }
}

export function logout(): void {
  clearToken()
  state.authed = false
  state.demo = false
  state.connected = false
  state.status = null
}

// ---------------------------------------------------------------- 写操作

export async function setMode(mode: 'observe' | 'enforce'): Promise<void> {
  await api.putConfig({ mode })
  await sync(true)
  notify(mode === 'enforce' ? '已切换为封禁模式 · 内核规则已同步生效' : '已切换为观察模式（安全默认）',
    mode === 'enforce' ? 'warn' : 'ok')
}

export async function saveConfig(patch: Partial<GuardConfig> & { hfish?: Partial<GuardConfig['hfish']> }): Promise<void> {
  await api.putConfig(patch)
  await sync(true)
  notify('配置已热加载 · 无需重启 guard.service')
}

// ---------------------------------------------------------------- 轮询

let timer = 0

export function startPolling(): void {
  stopPolling()
  timer = window.setInterval(() => {
    if (!state.authed) return
    sync(false)
  }, 3000)
}

export function stopPolling(): void {
  if (timer) { clearInterval(timer); timer = 0 }
}

export function initAuth(): void {
  const t = getToken()
  if (t) {
    login(t).catch(() => { /* 门会显示出来 */ })
    return
  }
  // 自检模式没有 token：直接进演示态，让自检能跑结构断言
  if (/[?&]selftest(=|&|$)/.test(location.search)) {
    enterDemo()
  }
}