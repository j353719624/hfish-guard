<script setup lang="ts">
import { computed } from 'vue'
import { state, fmtTime, fmtDuration } from '@/store/state'

const st = computed(() => state.status)

const rows = computed(() =>
  (st.value?.port_state || []).map(p => ({
    port: p.port,
    listening: p.listening,
    hits: p.hits,
    live: p.live_hits,
    trapped: p.trapped,
    last: p.last
  }))
)

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
</script>

<template>
  <div class="status-view">
    <div class="card">
      <div class="card__head">
        <span class="card__title">运行状态</span>
        <span class="card__sub">运行 {{ st ? fmtDuration(st.uptime) : '—' }}</span>
      </div>
      <div class="card__body">
        <div class="kv-grid">
          <div class="kv"><span class="kv-k">版本</span><span class="kv-v mono">{{ st?.version || '—' }}</span></div>
          <div class="kv"><span class="kv-k">处置模式</span><span class="kv-v">
            <span class="tag" :class="st?.mode === 'enforce' ? 'tag--red' : 'tag--blue'">
              {{ st?.mode === 'enforce' ? '封禁模式' : '观察模式' }}
            </span>
          </span></div>
          <div class="kv"><span class="kv-k">判定阈值</span><span class="kv-v mono">{{ st?.threshold }} 包 / {{ st?.window }}s</span></div>
          <div class="kv"><span class="kv-k">轮询间隔</span><span class="kv-v mono">{{ st?.poll }}s</span></div>
          <div class="kv"><span class="kv-k">黑名单 TTL</span><span class="kv-v mono">{{ st?.ttl }}s</span></div>
          <div class="kv"><span class="kv-k">UDP 探测</span><span class="kv-v">{{ st?.udp ? '一并拦截' : '只处理 TCP' }}</span></div>
          <div class="kv"><span class="kv-k">扫描判定</span><span class="kv-v mono">{{ st?.scan_ports }} 个端口</span></div>
          <div class="kv"><span class="kv-k">最后轮询</span><span class="kv-v mono">{{ st?.last_poll ? fmtTime(st.last_poll) : '—' }}</span></div>
        </div>
      </div>
    </div>

    <div class="two-col">
      <div class="card">
        <div class="card__head"><span class="card__title">内核与能力</span></div>
        <div class="card__body">
          <div class="kv-grid kv-grid--1">
            <div v-for="r in kernelRows" :key="r.key" class="kv">
              <span class="kv-k">{{ r.key }}</span>
              <span class="kv-v" :class="r.ok ? '' : 'is-warn'">{{ r.value }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card__head"><span class="card__title">联动状态</span></div>
        <div class="card__body">
          <div class="kv-grid kv-grid--1">
            <div v-for="r in linkRows" :key="r.key" class="kv">
              <span class="kv-k">{{ r.key }}</span>
              <span class="kv-v" :class="r.ok ? '' : 'is-warn'">{{ r.value }}</span>
            </div>
            <div v-if="!linkRows.length" class="dim">暂无联动信息</div>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card__head">
        <span class="card__title">端口面</span>
        <span class="card__sub">{{ rows.length }} 个蜜罐端口</span>
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
            <tr v-for="p in rows" :key="p.port">
              <td class="num">{{ p.port }}</td>
              <td><span class="tag" :class="p.listening ? 'tag--green' : 'tag--grey'">{{ p.listening ? '在线' : '未监听' }}</span></td>
              <td><span class="tag" :class="p.trapped ? 'tag--green' : 'tag--red'">{{ p.trapped ? '已挂载' : '未挂载' }}</span></td>
              <td class="num">{{ p.hits }}</td>
              <td class="num" :class="p.live ? 'is-hot' : ''">{{ p.live }}</td>
              <td class="num dim">{{ p.last ? fmtTime(p.last) : '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.status-view { display: flex; flex-direction: column; gap: var(--sp-4); }
.two-col { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--sp-4); }
@media (max-width: 1000px) { .two-col { grid-template-columns: 1fr; } }

.kv-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: var(--sp-4); }
.kv-grid--1 { grid-template-columns: 1fr; gap: var(--sp-3); }
@media (max-width: 900px) { .kv-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }

.kv { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.kv-k { font-size: var(--fs-xs); color: var(--text-3); }
.kv-v { font-size: var(--fs-base); color: var(--text-1); }
.kv-v.is-warn { color: var(--color-warning); }
.is-hot { color: var(--color-danger); font-weight: 600; }
</style>
