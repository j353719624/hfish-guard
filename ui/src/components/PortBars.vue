<script setup lang="ts">
/** 端口命中柱图 */
import { computed } from 'vue'

const props = defineProps<{
  items: { label: string; value: number }[]
  max?: number
}>()

const top = computed(() => {
  const list = [...props.items].sort((a, b) => b.value - a.value)
  const m = props.max ?? Math.max(1, ...list.map(x => x.value))
  return { list: list.slice(0, 10), max: m }
})
</script>

<template>
  <div class="bars">
    <div v-for="it in top.list" :key="it.label" class="bar-row">
      <span class="bar-label mono">{{ it.label }}</span>
      <div class="bar-track">
        <div class="bar-fill" :style="{ width: (it.value / top.max * 100).toFixed(1) + '%' }"></div>
      </div>
      <span class="bar-val mono">{{ it.value }}</span>
    </div>
    <p v-if="!top.list.length" class="dim">暂无端口命中数据</p>
  </div>
</template>

<style scoped>
.bars { display: flex; flex-direction: column; gap: 7px; }
.bar-row { display: flex; align-items: center; gap: var(--sp-2); font-size: var(--fs-xs); }
.bar-label { width: 42px; color: var(--text-2); flex: 0 0 42px; }
.bar-track { flex: 1; height: 7px; background: var(--bg-hover); border-radius: var(--radius-full); overflow: hidden; }
.bar-fill { height: 100%; background: var(--color-primary); border-radius: var(--radius-full); transition: width 0.4s; }
.bar-val { width: 42px; text-align: right; color: var(--text-2); flex: 0 0 42px; }
</style>
