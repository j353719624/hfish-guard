<script setup lang="ts">
/**
 * 状态总览 —— 由原「全球态势」与「状态总览」合并而来。
 *
 * 合并后的信息层级（自上而下按「运维决策的阅读顺序」排列）：
 *   ① KPI 四联      —— 一眼看到关键数字（包数 / 封禁 / 端口 / 事件）
 *   ② 运行状态      —— 守护进程的核心参数
 *   ③ 流量趋势 + 判定分布 —— 有什么流量、怎么判定的
 *   ④ 内核 / 联动 / 来源地域 —— 内核能不能干、上游通没通、攻击来自哪
 *   ⑤ 端口面命中 + 端口清单 —— 哪个端口在被摸、状态是否正常
 *
 * 原「全球攻击来源」地球仪已按需求移除 —— 占地方且信息密度低，
 * 攻击来源改用下面的「来源地域 TOP」列表呈现。
 */
import { computed } from 'vue'
import { state, geoOf, fmtTime, fmtDuration } from '@/store/state'
import FlowWave from '@/components/FlowWave.vue'
import PortBars from '@/components/PortBars.vue'

const st = computed(() => state.status)

// ---------------------------------------------------------------- 运行状态

const statusRows = computed(() => {
  const s = st.value
  if (!s) return []
  return [
    { key: '版本', value: s.version || '—' },
    { key: '处置模式', value: s.mode === 'enforce' ? '封禁模式' : '观察模式', danger: s.mode === 'enforce' },
    { key: '判定阈值', value: `${s.threshold} 包 / ${s.window}s` },
    { key: '轮询间隔', value: `${s.poll}s` },
    { key: '黑名单 TTL', value: `${s.ttl}s` },
    { key: 'UDP 探测', value: s.udp ? '一并拦截' : '只处理 TCP' },
    { key: '扫描判定', value: `${s.scan_ports} 个端口` },
    { key: '最后轮询', value: s.last_poll ? fmtTime(s.last_poll) : '—' }
  ]
})

const kernelRows = computed(() => {
  const k = st.value?.kernel
  if (!k) return []
  return [
    { key: '内核实现', value: k.kind, ok: k.available },
    { key: 'IPv6 双栈', value: k.v6 ? '已启用' : '未启用', ok: k.v6 },
    { key: '规则条数', value: Object.entries(k.rules || {}).map(([a, b]) => `${a.toUpperCase()} ${b}`).join(' / ') || '—', ok: true },
    { key: '降级模式', value: st.value?.degraded ? '是（只读）' : '否', ok: !st.value?.degraded },
    { key: '归属地库', value: st.value?.geo?.source || '未启用', ok: !!st.value?.geo?.ready }
  ]
})

const linkRows = computed(() => {
  const h = st.value?.link?.hfish
  const hive = st.value?.link?.hive
  if (!h) return []
  return [
    { key: 'HFish 告警接收', value: h.enabled ? `已开启 :${h.syslog_port}（UDP${h.syslog_bound.udp ? '✓' : '✗'} / TCP${h.syslog_bound.tcp ? '✓' : '✗'}）` : '未开启', ok: h.enabled },
    { key: '自动封禁门禁', value: h.auto_block_level || '未设置', ok: !!h.auto_block_level },
    { key: '封禁速率熔断', value: `${h.auto_block_max_per_min} 个/分钟`, ok: true },
    { key: '黑名单容量上限', value: `${h.max_blocks} 条`, ok: true },
    { key: '扫描扇出阈值', value: `${h.scan_fanout} 个端口`, ok: true },
    { key: '累计收到告警', value: `${h.received.syslog} 条（跳过 ${h.received.skipped}）`, ok: true },
    { key: '蜜罐蜂巢', value: hive?.installed ? '已安装' : '未安装', ok: !!hive?.installed }
  ]
})

// ---------------------------------------------------------------- 判定分布

const VERDICT_MAP: Record<string, { label: string; cls: string }> = {
  over: { label: '已封禁', cls: 'tag--red' },
  hfish: { label: '蜜罐告警', cls: 'tag--orange' },
  scan: { label: '端口扫描', cls: 'tag--blue' },
  manual: { label: '手动封禁', cls: 'tag--grey' },
  expired: { label: '已解封', cls: 'tag--green' },
  normal: { label: '仅计包', cls: 'tag--grey' }
}

const verdictDist = computed(() => {
  const acc: Record<string, number> = {}
  state.events.forEach(e => { acc[e.verdict] = (acc[e.verdict] || 0) + 1 })
  return Object.entries(acc)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ key: k, count: v, ...(VERDICT_MAP[k] || { label: k, cls: 'tag--grey' }) }))
})

// ---------------------------------------------------------------- 来源地域

/** 来源地域 TOP：按国家的攻击次数聚合 */
const origins = computed(() => {
  const acc = new Map<string, { cc: string; cn: string; count: number }>()
  const bump = (ip: string) => {
    const g = geoOf(ip)
    if (!g || !g.cc) return
    const cur = acc.get(g.cc)
    if (cur) cur.count++
    else acc.set(g.cc, { cc: g.cc, cn: g.cn, count: 1 })
  }
  state.events.forEach(e => bump(e.ip))
  state.blacklist.forEach(b => bump(b.ip))
  return [...acc.values()].sort((a, b) => b.count - a.count).slice(0, 8)
})

// ---------------------------------------------------------------- 端口面

/** 端口命中柱图 */
const ports = computed(() =>
  Object.entries(st.value?.per_port || {})
    .map(([port, value]) => ({ label: port, value: Number(value) || 0 }))
    .sort((a, b) => b.value - a.value)
)

/** 端口清单 */
const portRows = computed(() =>
  (st.value?.port_state || []).map(p => ({
    port: p.port,
    listening: p.listening,
    hits: p.hits,
    live: p.live_hits,
    trapped: p.trapped,
    last: p.last
  }))
)
</script>

<template>
  <div class="status-view">
    <!-- ① KPI 四联 -->
    <div class="kpi-row">
      <div class="card kpi">
        <div class="kpi-label">窗口内包数</div>
        <div class="kpi-value mono">{{ st?.window_sum ?? 0 }}</div>
        <div class="kpi-hint">
          <template v-if="(st?.window_sum ?? 0) === 0">
            本端口面当前无流量 · 累计 {{ st?.total_packets ?? 0 }} 包
          </template>
          <template v-else>真实流量 · 每 {{ st?.poll ?? 10 }}s 采样</template>
        </div>
      </div>
      <div class="card kpi">
        <div class="kpi-label">生效封禁</div>
        <div class="kpi-value mono is-danger">{{ st?.blacklist_count ?? 0 }}</div>
        <div class="kpi-hint">TTL {{ st?.ttl ?? 0 }}s 自动解封</div>
      </div>
      <div class="card kpi">
        <div class="kpi-label">监视端口</div>
        <div class="kpi-value mono">{{ st?.ports.length ?? 0 }}</div>
        <div class="kpi-hint">
          TCP+UDP · IPv4+IPv6
          <span class="tag tag--green" style="margin-left: 4px">{{ st?.trap ? '已挂陷阱' : '未挂载' }}</span>
        </div>
      </div>
      <div class="card kpi">
        <div class="kpi-label">事件总数</div>
        <div class="kpi-value mono">{{ state.events.length }}</div>
        <div class="kpi-hint">
          <span class="tag" :class="st?.mode === 'enforce' ? 'tag--red' : 'tag--blue'">
            {{ st?.mode === 'enforce' ? '封禁模式' : '观察模式' }}
          </span>
        </div>
      </div>
    </div>

    <!-- ② 运行状态 -->
    <div class="card">
      <div class="card__head">
        <span class="card__title">运行状态</span>
        <span class="card__sub">运行 {{ st ? fmtDuration(st.uptime) : '—' }}</span>
      </div>
      <div class="card__body">
        <div class="kv-grid">
          <div v-for="r in statusRows" :key="r.key" class="kv">
            <span class="kv-k">{{ r.key }}</span>
            <span class="kv-v mono">{{ r.value }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- ③ 起：两列主布局
         左列（宽）：流量趋势 → 内核与能力 → 端口面命中
         右列（窄）：判定分布 → 来源地域 → 联动状态
         两列各自纵向填满，避免「一列很高、另一列留白」。 -->
    <div class="cols">
      <!-- 左列 -->
      <div class="col-main">
        <div class="card">
          <div class="card__head">
            <span class="card__title">流量趋势</span>
            <span class="card__sub mono">阈值 {{ st?.threshold }}/{{ st?.window }}s</span>
          </div>
          <div class="card__body"><FlowWave /></div>
        </div>

        <div class="card">
          <div class="card__head">
            <span class="card__title">内核与能力</span>
          </div>
          <div class="card__body">
            <div class="kv-list">
              <div v-for="r in kernelRows" :key="r.key" class="kv">
                <span class="kv-k">{{ r.key }}</span>
                <span class="kv-v" :class="r.ok ? '' : 'is-warn'">{{ r.value }}</span>
              </div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card__head">
            <span class="card__title">端口面命中</span>
            <span class="card__sub">累计</span>
          </div>
          <div class="card__body"><PortBars :items="ports" /></div>
        </div>
      </div>

      <!-- 右列 -->
      <div class="col-side">
        <div class="card">
          <div class="card__head">
            <span class="card__title">判定分布</span>
            <span class="card__sub">蜜罐 / 计数 / 扫描</span>
          </div>
          <div class="card__body">
            <div v-if="verdictDist.length" class="verdict-list">
              <div v-for="v in verdictDist" :key="v.key" class="verdict-row">
                <span class="tag" :class="v.cls">{{ v.label }}</span>
                <span class="grow"></span>
                <span class="mono">{{ v.count }}</span>
              </div>
            </div>
            <p v-else class="dim">暂无事件</p>
          </div>
        </div>

        <div class="card">
          <div class="card__head">
            <span class="card__title">来源地域 TOP</span>
            <span class="card__sub">{{ origins.length }} 个国家/地区</span>
          </div>
          <div class="card__body">
            <div v-if="origins.length" class="origin-list">
              <div v-for="o in origins" :key="o.cc" class="origin-row">
                <span class="origin-cc mono">{{ o.cc }}</span>
                <span class="origin-cn">{{ o.cn || '--' }}</span>
                <span class="grow"></span>
                <span class="origin-n mono">{{ o.count }}</span>
              </div>
            </div>
            <p v-else class="dim">暂无归属地数据（需要 GeoIP 库，或事件里有公网来源）</p>
          </div>
        </div>

        <div class="card">
          <div class="card__head">
            <span class="card__title">联动状态</span>
            <span class="card__sub">上游蜜罐</span>
          </div>
          <div class="card__body">
            <div class="kv-list">
              <div v-for="r in linkRows" :key="r.key" class="kv">
                <span class="kv-k">{{ r.key }}</span>
                <span class="kv-v" :class="r.ok ? '' : 'is-warn'">{{ r.value }}</span>
              </div>
              <div v-if="!linkRows.length" class="dim">暂无联动信息</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 端口清单（整宽表格） -->
    <div class="card">
      <div class="card__head">
        <span class="card__title">端口清单</span>
        <span class="card__sub">{{ portRows.length }} 个蜜罐端口</span>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>端口</th>
              <th>服务监听</th>
              <th>陷阱已挂</th>
              <th>累计命中</th>
              <th>本轮命中</th>
              <th>最近活动</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in portRows" :key="p.port">
              <td class="num">{{ p.port }}</td>
              <td><span class="tag" :class="p.listening ? 'tag--green' : 'tag--grey'">{{ p.listening ? '在线' : '未监听' }}</span></td>
              <td><span class="tag" :class="p.trapped ? 'tag--green' : 'tag--red'">{{ p.trapped ? '已挂载' : '未挂载' }}</span></td>
              <td class="num">{{ p.hits }}</td>
              <td class="num" :class="p.live ? 'is-hot' : ''">{{ p.live }}</td>
              <td class="num dim">{{ p.last ? fmtTime(p.last) : '—' }}</td>
            </tr>
            <tr v-if="!portRows.length">
              <td colspan="6" class="empty">暂无端口数据</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.status-view { display: flex; flex-direction: column; gap: var(--sp-4); }

/* ---- KPI ---- */
.kpi-row { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: var(--sp-4); }
@media (max-width: 1100px) { .kpi-row { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.kpi { padding: var(--sp-4) var(--sp-5); }
.kpi-label { font-size: var(--fs-sm); color: var(--text-3); }
.kpi-value { font-size: var(--fs-3xl); font-weight: 600; line-height: 1.2; margin: 4px 0 2px; }
.kpi-value.is-danger { color: var(--color-danger); }
.kpi-hint { font-size: var(--fs-xs); color: var(--text-3); }

/* ---- 两列主布局 ----
   媒体查询按视口宽度算，而左侧导航占 200px、内容区还有内边距，
   所以断点要比「内容区想要的最小宽度」再放宽一些，
   否则 1139px 的视口会被误判成窄屏、把多列压成一列。 */
.cols { display: grid; grid-template-columns: minmax(0, 1.75fr) minmax(300px, 1fr); gap: var(--sp-4); align-items: start; }
/* 列内是 flex column —— 不给子卡片 width:100% 的话，
   它们会按内容宽度收缩（内核与能力被压成 121px 宽），必须显式撑满。 */
.col-main, .col-side { display: flex; flex-direction: column; gap: var(--sp-4); min-width: 0; }
.col-main > .card, .col-side > .card { width: 100%; }
@media (max-width: 1080px) {
  .cols { grid-template-columns: minmax(0, 1fr); }
}

/* 每一张卡都按自己的内容高度收缩，不要被同排的邻居撑高 ——
   grid 默认 stretch 会把矮卡拉到和最高的那张一样高，底下全是空白。 */
.status-view .card { align-self: start; }
/* .status-view 是 flex column —— 直接子卡片不撑满的话会按内容宽度收缩
   （「运行状态」只占半行、「端口清单」也只占一半）。 */
.status-view > .card,
.status-view > .kpi-row { width: 100%; }

/* ---- KV ---- */
.kv-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: var(--sp-4); }
.kv-list { display: flex; flex-direction: column; gap: var(--sp-3); }
.kv { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.kv-k { font-size: var(--fs-xs); color: var(--text-3); }
.kv-v { font-size: var(--fs-base); color: var(--text-1); }
.kv-v.is-warn { color: var(--color-warning); }
.is-hot { color: var(--color-danger); font-weight: 600; }

/* ---- 列表 ---- */
.verdict-list, .origin-list { display: flex; flex-direction: column; gap: 9px; }
.verdict-row, .origin-row { display: flex; align-items: center; gap: var(--sp-2); font-size: var(--fs-sm); }
.origin-cc {
  width: 30px; flex: 0 0 30px; text-align: center;
  padding: 1px 0; border-radius: var(--radius-xs);
  background: var(--bg-hover); color: var(--text-2); font-size: var(--fs-xs);
}
.origin-cn { color: var(--text-1); }
.origin-n { color: var(--text-2); }
</style>
