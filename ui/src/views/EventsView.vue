<script setup lang="ts">
import { computed, ref } from 'vue'
import { state, geoOf, fmtTime } from '@/store/state'

const FILTERS = [
  { key: 'all', label: '全部' },
  { key: 'over', label: '已封禁' },
  { key: 'hfish', label: '蜜罐告警' },
  { key: 'scan', label: '端口扫描' },
  { key: 'manual', label: '手动封禁' },
  { key: 'expired', label: '已解封' }
] as const

type FilterKey = typeof FILTERS[number]['key']
const filter = ref<FilterKey>('all')
const query = ref('')
const page = ref(1)
const pageSize = 20

const VERDICT_TAG: Record<string, { label: string; cls: string }> = {
  over: { label: '已封禁', cls: 'tag--red' },
  hfish: { label: '蜜罐告警', cls: 'tag--orange' },
  scan: { label: '端口扫描', cls: 'tag--blue' },
  manual: { label: '手动封禁', cls: 'tag--grey' },
  expired: { label: '已解封', cls: 'tag--green' },
  normal: { label: '仅计包', cls: 'tag--grey' }
}

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase()
  return state.events.filter(e => {
    if (filter.value !== 'all' && e.verdict !== filter.value) return false
    if (!q) return true
    const g = geoOf(e.ip)
    const hay = [e.ip, String(e.port), e.action, e.detail, g?.cn || '', g?.cc || ''].join(' ').toLowerCase()
    return hay.includes(q)
  })
})

const totalPages = computed(() => Math.max(1, Math.ceil(filtered.value.length / pageSize)))
const rows = computed(() => {
  if (page.value > totalPages.value) page.value = totalPages.value
  const start = (page.value - 1) * pageSize
  return filtered.value.slice(start, start + pageSize)
})

function tagOf(v: string) { return VERDICT_TAG[v] || { label: v, cls: 'tag--grey' } }

function geoText(ip: string): string {
  const g = geoOf(ip)
  if (!g || !g.cn) return ''
  return g.city && g.city !== '-' ? `${g.cn} · ${g.city}` : g.cn
}

function reset(): void {
  filter.value = 'all'
  query.value = ''
  page.value = 1
}
</script>

<template>
  <div class="card">
    <div class="card__head">
      <div class="row">
        <span class="card__title">事件流</span>
        <span class="card__sub">{{ filtered.length }} 条 / 共 {{ state.events.length }} 条</span>
      </div>
      <div class="row">
        <div class="filters">
          <button
            v-for="f in FILTERS" :key="f.key"
            class="chip-btn" :class="{ 'is-on': filter === f.key }"
            type="button" @click="filter = f.key; page = 1"
          >{{ f.label }}</button>
        </div>
        <input v-model="query" class="input search" placeholder="搜索 IP / 端口 / 地域" @input="page = 1">
      </div>
    </div>

    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>时间</th>
            <th>来源 IP</th>
            <th>归属地</th>
            <th>端口</th>
            <th>判定</th>
            <th>动作</th>
            <th>详情</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in rows" :key="e.id">
            <td class="num dim">{{ fmtTime(e.ts) }}</td>
            <td class="num">{{ e.ip }}</td>
            <td class="dim">{{ geoText(e.ip) || '—' }}</td>
            <td class="num">{{ e.port || '—' }}</td>
            <td><span class="tag" :class="tagOf(e.verdict).cls">{{ tagOf(e.verdict).label }}</span></td>
            <td>{{ e.action }}</td>
            <td class="dim detail">{{ e.detail }}</td>
          </tr>
          <tr v-if="!rows.length">
            <td colspan="7" class="empty">没有匹配的事件</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="pager">
      <button class="btn btn--default btn--sm" :disabled="page <= 1" @click="page--">上一页</button>
      <span class="dim">第 {{ page }} / {{ totalPages }} 页</span>
      <button class="btn btn--default btn--sm" :disabled="page >= totalPages" @click="page++">下一页</button>
      <span class="grow"></span>
      <button v-if="filter !== 'all' || query" class="btn btn--ghost btn--sm" @click="reset">清除筛选</button>
    </div>
  </div>
</template>

<style scoped>
.filters { display: flex; gap: 4px; }
.chip-btn {
  padding: 4px 10px; border: 1px solid transparent; border-radius: var(--radius-sm);
  background: transparent; color: var(--text-2);
  font-family: inherit; font-size: var(--fs-sm); cursor: pointer;
  transition: background-color 0.15s, color 0.15s;
}
.chip-btn:hover { background: var(--bg-hover); color: var(--text-1); }
.chip-btn.is-on { background: var(--color-primary-bg); color: var(--brand-6); font-weight: 500; }
.search { width: 200px; min-height: 28px; font-size: var(--fs-sm); }
.detail { max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pager {
  display: flex; align-items: center; gap: var(--sp-3);
  padding: var(--sp-3) var(--sp-4);
  border-top: 1px solid var(--border);
  font-size: var(--fs-sm);
}
</style>
