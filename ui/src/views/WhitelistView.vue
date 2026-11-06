<script setup lang="ts">
import { ref } from 'vue'
import { state, fmtTime, notify, sync } from '@/store/state'
import { api } from '@/api/guard'

const cidr = ref('')
const note = ref('')
const err = ref('')
const busy = ref(false)

async function add(): Promise<void> {
  const c = cidr.value.trim()
  if (!c) { err.value = '请输入网段或地址'; return }
  busy.value = true
  err.value = ''
  try {
    await api.addWhite(c, note.value.trim())
    cidr.value = ''
    note.value = ''
    await sync(true)
    notify('已加入白名单 ' + c, 'ok')
  } catch (e) {
    err.value = (e as Error).message || '添加失败'
  } finally {
    busy.value = false
  }
}

async function remove(c: string): Promise<void> {
  try {
    await api.delWhite(c)
    await sync(true)
    notify('已移出白名单 ' + c, 'ok')
  } catch (e) {
    notify('删除失败：' + ((e as Error).message || '接口不可用'), 'err')
  }
}
</script>

<template>
  <div class="wl">
    <div class="card">
      <div class="card__head">
        <div class="row">
          <span class="card__title">新增白名单</span>
          <span class="card__sub">内核侧直接豁免，不计包、不产生事件</span>
        </div>
      </div>
      <div class="card__body">
        <form class="wl-form" @submit.prevent="add">
          <div class="field">
            <label class="field-label" for="wlCidr">网段 / 地址<span class="req">*</span></label>
            <input id="wlCidr" v-model="cidr" class="input mono" placeholder="192.168.1.0/24 或 2409:8a20::/48">
            <div class="err">{{ err }}</div>
          </div>
          <div class="field">
            <label class="field-label" for="wlNote">备注</label>
            <input id="wlNote" v-model="note" class="input" placeholder="例如：自家网关 / 监控探针">
          </div>
          <button class="btn btn--primary" type="submit" :disabled="busy" style="align-self: end">
            {{ busy ? '添加中…' : '加入白名单' }}
          </button>
        </form>
      </div>
    </div>

    <div class="card">
      <div class="card__head">
        <div class="row">
          <span class="card__title">白名单列表</span>
          <span class="card__sub">{{ state.whitelist.length }} 条</span>
        </div>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>网段 / 地址</th>
              <th>备注</th>
              <th>加入时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="w in state.whitelist" :key="w.cidr">
              <td class="num">{{ w.cidr }}</td>
              <td class="dim">{{ w.note || '—' }}</td>
              <td class="num dim">{{ fmtTime(w.at) }}</td>
              <td>
                <button class="btn btn--default btn--sm" @click="remove(w.cidr)">移除</button>
              </td>
            </tr>
            <tr v-if="!state.whitelist.length">
              <td colspan="4" class="empty">白名单为空</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.wl { display: flex; flex-direction: column; gap: var(--sp-4); }
.wl-form { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr) auto; gap: var(--sp-4); align-items: start; }
@media (max-width: 900px) { .wl-form { grid-template-columns: 1fr; } }
</style>
