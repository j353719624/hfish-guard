<script setup lang="ts">
import { computed } from 'vue'
import { state, geoOf } from '@/store/state'
import GlobeMap from '@/components/GlobeMap.vue'
import FlowWave from '@/components/FlowWave.vue'
import PortBars from '@/components/PortBars.vue'

const st = computed(() => state.status)

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

/** 端口命中 */
const ports = computed(() =>
  Object.entries(st.value?.per_port || {})
    .map(([port, value]) => ({ label: port, value: Number(value) || 0 }))
    .sort((a, b) => b.value - a.value)
)

/** 判定分布 */
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

/** 归属地数据源说明 */
const geoSourceText = computed(() => {
  const g = st.value?.geo
  if (!g) return ''
  if (g.source === 'mmdb') return 'GeoIP 城市库'
  if (g.source === 'custom') return '自定义情报表'
  if (g.source === 'approx') return '网段推算'
  return '未启用'
})
</script>

<template>
  <div class="map-view">
    <!-- KPI 行 -->
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

    <div class="map-grid">
      <div class="card">
        <div class="card__head">
          <span class="card__title">全球攻击来源</span>
          <span class="card__sub">{{ geoSourceText }}</span>
        </div>
        <div class="card__body map-body">
          <GlobeMap />
        </div>
      </div>

      <div class="map-side">
        <div class="card">
          <div class="card__head">
            <span class="card__title">流量趋势</span>
            <span class="card__sub mono">阈值 {{ st?.threshold }}/{{ st?.window }}s</span>
          </div>
          <div class="card__body"><FlowWave /></div>
        </div>

        <div class="card">
          <div class="card__head"><span class="card__title">来源地域 TOP</span></div>
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
          <div class="card__head"><span class="card__title">端口面命中</span></div>
          <div class="card__body"><PortBars :items="ports" /></div>
        </div>

        <div class="card">
          <div class="card__head">
            <span class="card__title">判定分布</span>
            <span class="card__sub">蜜罐告警 / 端口计数 / 扫描</span>
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
      </div>
    </div>
  </div>
</template>

<style scoped>
.map-view { display: flex; flex-direction: column; gap: var(--sp-4); }

.kpi-row { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: var(--sp-4); }
@media (max-width: 1100px) { .kpi-row { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.kpi { padding: var(--sp-4) var(--sp-5); }
.kpi-label { font-size: var(--fs-sm); color: var(--text-3); }
.kpi-value { font-size: var(--fs-3xl); font-weight: 600; line-height: 1.2; margin: 4px 0 2px; }
.kpi-value.is-danger { color: var(--color-danger); }
.kpi-hint { font-size: var(--fs-xs); color: var(--text-3); }

.map-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(280px, 360px); gap: var(--sp-4); align-items: start; }
@media (max-width: 1100px) { .map-grid { grid-template-columns: 1fr; } }
.map-body { display: flex; justify-content: center; }
.map-side { display: flex; flex-direction: column; gap: var(--sp-4); }

.origin-list, .verdict-list { display: flex; flex-direction: column; gap: 9px; }
.origin-row, .verdict-row { display: flex; align-items: center; gap: var(--sp-2); font-size: var(--fs-sm); }
.origin-cc {
  width: 30px; flex: 0 0 30px; text-align: center;
  padding: 1px 0; border-radius: var(--radius-xs);
  background: var(--bg-hover); color: var(--text-2); font-size: var(--fs-xs);
}
.origin-cn { color: var(--text-1); }
.origin-n { color: var(--text-2); }
</style>
