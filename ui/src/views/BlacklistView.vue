<script setup lang="ts">
import { computed, ref } from 'vue'
import { state, geoOf, fmtTime, fmtDuration, notify, sync } from '@/store/state'
import { api } from '@/api/guard'

const query = ref('')
const busy = ref('')

const rows = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return state.blacklist
  return state.blacklist.filter(b => {
    const g = geoOf(b.ip)
    return [b.ip, b.reason, g?.cn || '', g?.cc || ''].join(' ').toLowerCase().includes(q)
  })
})

function geoText(ip: string): string {
  const g = geoOf(ip)
  if (!g || !g.cn) return ''
  return g.city && g.city !== '-' ? `${g.cn} · ${g.city}` : g.cn
}

async function unblock(ip: string): Promise<void> {
  busy.value = ip
  try {
    await api.delBlack(ip)
    await sync(true)
    notify('已解封 ' + ip, 'ok')
  } catch (e) {
    notify('解封失败：' + ((e as Error).message || '接口不可用'), 'err')
  } finally {
    busy.value = ''
  }
}
</script>

<template>
  <div class="card">
    <div class="card__head">
      <div class="row">
        <span class="card__title">黑名单</span>
        <span class="card__sub">{{ rows.length }} 条生效中</span>
      </div>
      <input v-model="query" class="input search" placeholder="搜索 IP / 地域 / 原因">
    </div>

    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>IP</th>
            <th>归属地</th>
            <th>端口</th>
            <th>封禁时间</th>
            <th>剩余</th>
            <th>原因</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in rows" :key="b.ip">
            <td class="num">{{ b.ip }}</td>
            <td class="dim">{{ geoText(b.ip) || '—' }}</td>
            <td class="num">{{ b.port || '—' }}</td>
            <td class="num dim">{{ fmtTime(b.at) }}</td>
            <td class="num">{{ b.permanent ? '永久' : fmtDuration(b.left) }}</td>
            <td class="dim reason">{{ b.reason }}</td>
            <td>
              <button
                class="btn btn--default btn--sm"
                :disabled="busy === b.ip"
                @click="unblock(b.ip)"
              >{{ busy === b.ip ? '处理中' : '解封' }}</button>
            </td>
          </tr>
          <tr v-if="!rows.length">
            <td colspan="7" class="empty">黑名单为空</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.search { width: 240px; min-height: 28px; font-size: var(--fs-sm); }
.reason { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
