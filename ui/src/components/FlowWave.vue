<script setup lang="ts">
/** 流量曲线 —— 每 poll 秒一个采样点，纯 SVG path 绘制 */
import { computed } from 'vue'
import { state } from '@/store/state'

const W = 560
// 高度要跟卡片宽度配得上：卡片有 700+px 宽，120px 高的图会被压得很扁
const H = 170
const PAD = 6

const series = computed(() => {
  const s = state.status?.window_series || []
  return s.slice(-60).map(x => Number(x[1]) || 0)
})

const max = computed(() => Math.max(1, ...series.value))

/** 平滑折线（Catmull-Rom 转贝塞尔），比折线好看 */
const path = computed(() => {
  const v = series.value
  if (v.length < 2) return ''
  const n = v.length
  const step = (W - PAD * 2) / (n - 1)
  const pts = v.map((val, i) => {
    const x = PAD + i * step
    const y = H - PAD - (val / max.value) * (H - PAD * 2)
    return [x, y] as [number, number]
  })
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[Math.max(0, i - 1)]
    const p1 = pts[i]
    const p2 = pts[i + 1]
    const p3 = pts[Math.min(pts.length - 1, i + 2)]
    const c1x = p1[0] + (p2[0] - p0[0]) / 6
    const c1y = p1[1] + (p2[1] - p0[1]) / 6
    const c2x = p2[0] - (p3[0] - p1[0]) / 6
    const c2y = p2[1] - (p3[1] - p1[1]) / 6
    d += ` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`
  }
  return d
})

const areaPath = computed(() => {
  if (!path.value) return ''
  return `${path.value} L${(W - PAD).toFixed(1)},${H - PAD} L${PAD},${H - PAD} Z`
})

const last = computed(() => series.value[series.value.length - 1] ?? 0)

/**
 * 空态：窗口内一个包都没有时，画一条平线看起来像「坏了」。
 * 这里明确告诉用户「当前窗口无流量」，并说明数据来自哪一路。
 */
const idle = computed(() => {
  const s = state.status
  if (!s) return false
  // 有任何非零采样就不算空态
  if (series.value.some(v => v > 0)) return false
  // 但如果累计包数不为 0，说明链路是通的，只是这个窗口没流量
  return (s.total_packets ?? 0) > 0 || (s.window_sum ?? 0) === 0
})
</script>

<template>
  <div class="wave">
    <svg :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none" role="img" aria-label="流量趋势">
      <defs>
        <linearGradient id="waveFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--color-primary)" stop-opacity="0.22" />
          <stop offset="100%" stop-color="var(--color-primary)" stop-opacity="0.01" />
        </linearGradient>
      </defs>
      <line
        v-for="i in 3" :key="i"
        :x1="PAD" :x2="W - PAD"
        :y1="PAD + (i - 1) * ((H - PAD * 2) / 2)"
        :y2="PAD + (i - 1) * ((H - PAD * 2) / 2)"
        class="wave-grid"
      />
      <path v-if="areaPath" :d="areaPath" fill="url(#waveFill)" />
      <path v-if="path" :d="path" class="wave-line" />
      <text
        v-if="idle"
        :x="W / 2" :y="H / 2 - 4"
        class="wave-idle" text-anchor="middle"
      >当前窗口无流量</text>
      <text
        v-if="idle"
        :x="W / 2" :y="H / 2 + 16"
        class="wave-idle wave-idle--sub" text-anchor="middle"
      >告警来自蜜罐链路，已自动封禁</text>
    </svg>
    <div class="wave-foot">
      <span class="wave-val mono">{{ last }}</span>
      <span class="dim">包 / {{ state.status?.poll ?? 10 }}s</span>
      <span class="grow"></span>
      <span class="dim">峰值 <b class="mono">{{ max }}</b></span>
      <span class="dim">·</span>
      <span class="dim">累计 <b class="mono">{{ state.status?.total_packets ?? 0 }}</b></span>
    </div>
  </div>
</template>

<style scoped>
.wave { display: flex; flex-direction: column; gap: var(--sp-2); }
.wave svg { width: 100%; height: 170px; display: block; }
.wave-grid { stroke: var(--border); stroke-width: 1; }
.wave-line { fill: none; stroke: var(--color-primary); stroke-width: 2; stroke-linejoin: round; }
.wave-idle { fill: var(--text-3); font-size: 13px; font-family: var(--font); }
.wave-idle--sub { fill: var(--text-4); font-size: 11px; }
.wave-foot { display: flex; align-items: baseline; gap: 6px; font-size: var(--fs-xs); }
.wave-val { font-size: var(--fs-lg); font-weight: 600; color: var(--text-1); }
</style>
