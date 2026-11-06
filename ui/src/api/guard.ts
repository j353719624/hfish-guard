// ============================================================
// 与守卫后端（guard.py）交互的 API 层
// 后端是纯 Python 标准库 HTTP 服务，接口形状见 docs/ARCHITECTURE.md
// ============================================================

export interface Geo {
  ip: string
  cc: string
  cn: string
  city: string
  lat: number | null
  lon: number | null
  org: string
  source: string
}

export interface WhitelistItem {
  cidr: string
  note: string
  at: number
}

export interface BlacklistItem {
  ip: string
  at: number
  expire: number
  port: number
  packets: number
  ttl: number
  permanent: boolean
  left: number
  reason: string
  geo?: Geo
}

export type Verdict = 'over' | 'hfish' | 'manual' | 'expired' | 'scan' | 'normal'

export interface EventItem {
  id: string
  ts: number
  ip: string
  port: number
  packets: number
  verdict: Verdict
  action: string
  detail: string
  geo?: Geo
}

export interface PortState {
  port: number
  listening: boolean
  hits: number
  live_hits: number
  last: number
  trapped: boolean
}

export interface HfishLink {
  enabled: boolean
  syslog_port: number
  syslog_bound: { udp: boolean; tcp: boolean }
  api_configured: boolean
  api_ok: boolean
  api_error: string
  last_pull: number
  intel_count: number
  auto_block_level: string
  auto_block_max_per_min: number
  max_blocks: number
  scan_fanout: number
  received: { syslog: number; webhook: number; skipped: number; last: number }
}

export interface Status {
  app: string
  version: string
  mode: 'observe' | 'enforce'
  threshold: number
  window: number
  poll: number
  ttl: number
  udp: boolean
  scan_ports: number
  scan_block: boolean
  ports: number[]
  whitelist: WhitelistItem[]
  blacklist_count: number
  events_count: number
  trap: boolean
  geo: { source: string; mmdb: string; custom: number; ready: boolean }
  kernel: {
    kind: string
    available: boolean
    reason: string
    v6: boolean
    v6_reason: string
    rules: Record<string, number>
  }
  degraded: boolean
  fake: boolean
  last_poll: number
  uptime: number
  total_packets: number
  window_sum: number
  top_src: number
  window_series: [number, number][]
  per_port: Record<string, number>
  port_last: Record<string, number>
  port_state: PortState[]
  link: {
    hive?: { installed: boolean; dirs?: string[] }
    hfish?: HfishLink
    ports_watched?: number
    ports_listening?: number
  }
  geo_source: string
  recent: EventItem[]
}

export interface GuardConfig {
  mode: 'observe' | 'enforce'
  threshold: number
  window: number
  poll: number
  ttl: number
  udp: boolean
  scan_ports: number
  scan_block: boolean
  ports: number[]
  whitelist: WhitelistItem[]
  token: string
  hfish: {
    enabled: boolean
    syslog_port: number
    auto_block_level: string
    auto_block_max_per_min: number
    scan_fanout: number
    max_blocks: number
    api_base: string
    api_key: string
    webhook_token: string
  }
  token_set?: boolean
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

// ---------------------------------------------------------------- token

const TOKEN_KEY = 'hfish-guard-token'

export function getToken(): string {
  try {
    const u = new URL(window.location.href)
    const q = u.searchParams.get('token')
    if (q) {
      try { sessionStorage.setItem(TOKEN_KEY, q) } catch { /* 隐私模式 */ }
      // 只从地址栏移除 token —— 其它参数（?selftest=1 / ?demo=1）必须保留，
      // 否则「访问后清 token」会把自检/演示标记一起吃掉，页面就失去了这些模式。
      u.searchParams.delete('token')
      const rest = u.searchParams.toString()
      window.history.replaceState(null, '', u.pathname + (rest ? '?' + rest : '') + u.hash)
      return q
    }
    return sessionStorage.getItem(TOKEN_KEY) || ''
  } catch {
    return ''
  }
}

export function setToken(t: string): void {
  try { sessionStorage.setItem(TOKEN_KEY, t) } catch { /* ignore */ }
}

export function clearToken(): void {
  try { sessionStorage.removeItem(TOKEN_KEY) } catch { /* ignore */ }
}

// ---------------------------------------------------------------- 请求

async function req<T>(path: string, opts: { method?: string; body?: unknown; auth?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  const token = getToken()
  if (opts.auth !== false && token) headers['Authorization'] = 'Bearer ' + token
  const init: RequestInit = {
    method: opts.method || 'GET',
    headers,
    cache: 'no-store'
  }
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(opts.body)
  }
  const res = await fetch(path, init)
  if (res.status === 401) throw new ApiError(401, '凭证无效或已失效')
  if (!res.ok) {
    let msg = 'HTTP ' + res.status
    try {
      const j = await res.json()
      msg = j.error || j.message || msg
    } catch { /* 非 JSON 响应 */ }
    throw new ApiError(res.status, msg)
  }
  return (await res.json()) as T
}

// ---------------------------------------------------------------- 接口

export const api = {
  health: () => req<{ ok: boolean; version: string; auth: boolean; fake?: boolean }>('/api/health', { auth: false }),
  status: () => req<Status>('/api/status'),
  events: (limit = 200) => req<EventItem[]>('/api/events?limit=' + limit),
  blacklist: (limit = 500) => req<BlacklistItem[]>('/api/blacklist?limit=' + limit),
  whitelist: () => req<WhitelistItem[]>('/api/whitelist'),
  config: () => req<GuardConfig>('/api/config'),
  geo: (ips: string[]) => req<{ items: Geo[] }>('/api/geo?ips=' + encodeURIComponent(ips.join(','))),

  putConfig: (patch: Partial<GuardConfig> & { hfish?: Partial<GuardConfig['hfish']> }) =>
    req<{ ok: boolean; config: GuardConfig }>('/api/config', { method: 'PUT', body: patch }),

  addBlack: (ip: string, ttl?: number, reason?: string) =>
    req<{ ok: boolean }>('/api/blacklist', { method: 'POST', body: { ip, ttl, reason } }),
  delBlack: (ip: string) =>
    req<{ ok: boolean }>('/api/blacklist/' + encodeURIComponent(ip), { method: 'DELETE' }),

  addWhite: (cidr: string, note?: string) =>
    req<{ ok: boolean }>('/api/whitelist', { method: 'POST', body: { cidr, note } }),
  delWhite: (cidr: string) =>
    req<{ ok: boolean }>('/api/whitelist/delete', { method: 'POST', body: { cidr } }),

  regenToken: () => req<{ ok: boolean; token: string }>('/api/token', { method: 'POST' })
}
