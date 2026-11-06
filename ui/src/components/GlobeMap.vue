<script setup lang="ts">
/**
 * 网状地球仪 —— 纯 SVG 绘制（不引图表库，控制产物体积）
 * 落点来自事件与黑名单里的公网 IP，按经纬度投影到球面。
 */
import { computed, onUnmounted, ref } from 'vue'
import LAND from './land'
import { state, geoOf } from '@/store/state'

const size = 360
const CX = size / 2
// 球面半径 —— 必须和画出来的圆一致，否则落点/陆地图块会溢出到球外
const R = CX * 0.92

// 自动旋转：球面地图只能看到前半球，缓慢旋转让后半球的攻击源也轮流可见
const rot = ref(0)
const autoRotate = ref(true)
let rotTimer = 0

function startRotate(): void {
  stopRotate()
  rotTimer = window.setInterval(() => {
    if (autoRotate.value) rot.value = (rot.value + 0.004) % (Math.PI * 2)
  }, 40)
}
function stopRotate(): void {
  if (rotTimer) { clearInterval(rotTimer); rotTimer = 0 }
}
startRotate()
onUnmounted(stopRotate)

interface Node {
  ip: string
  lat: number
  lon: number
  cn: string
  cc: string
  hits: number
  kind: 'event' | 'block'
}

/**
 * 球面 → 平面投影（正交投影，视点在赤道上）。
 *
 * 推导（φ 为极角，θ 为方位角）：
 *   φ = 90° − lat，  cosφ = sin(lat)，  sinφ = cos(lat)
 *   x = R·cos(lat)·sin(lon + rot) = R·sinφ·sinθ
 *   y = R·sin(lat)（屏幕 y 向下，故取负）= R·cosφ
 *   z = cos(lat)·cos(lon + rot)     = sinφ·cosθ   ← z>0 为正面可见
 *
 * 踩过的坑：曾把 cosφ / sinφ 用反（等于把纬度轴翻转），
 * 结果所有落点挤在北极附近、陆地图块溢出球外。
 */
function project(lat: number, lon: number, rot = 0): { x: number; y: number; z: number } {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = lon * (Math.PI / 180) + rot
  const cosPhi = Math.cos(phi)
  const sinPhi = Math.sin(phi)
  const sinTheta = Math.sin(theta)
  const cosTheta = Math.cos(theta)
  return {
    x: CX + R * sinPhi * sinTheta,
    y: CX - R * cosPhi,
    z: sinPhi * cosTheta
  }
}

const nodes = computed<Node[]>(() => {
  const acc = new Map<string, Node>()
  const add = (ip: string, kind: 'event' | 'block') => {
    const g = geoOf(ip)
    if (!g || g.lat === null || g.lon === null) return
    const cur = acc.get(ip)
    if (cur) {
      cur.hits++
      if (kind === 'block') cur.kind = 'block'
      return
    }
    acc.set(ip, { ip, lat: g.lat, lon: g.lon, cn: g.cn, cc: g.cc, hits: 1, kind })
  }
  state.events.forEach(e => add(e.ip, 'event'))
  state.blacklist.forEach(b => add(b.ip, 'block'))
  return [...acc.values()].sort((a, b) => b.hits - a.hits).slice(0, 120)
})

/** 一段折线：正面还是背面（按 z 分段，跨地平线要断开画） */
interface Seg { d: string; front: boolean }

/**
 * 把一条折线按「正面/背面」切成若干段。
 * 正交投影下背面半球与正面在平面上是重叠的，不分段就会看到「透」过来的大陆。
 */
function splitPath(pts: { x: number; y: number; z: number }[], close = false): Seg[] {
  const segs: Seg[] = []
  let cur: { x: number; y: number; z: number }[] = []
  let curFront = false

  const flush = () => {
    if (cur.length >= 2) {
      const d = 'M' + cur.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' L') + (close ? ' Z' : '')
      segs.push({ d, front: curFront })
    }
    cur = []
  }

  for (const p of pts) {
    const front = p.z >= 0
    if (cur.length && front !== curFront) flush()
    if (!cur.length) curFront = front
    cur.push(p)
  }
  flush()
  return segs
}

/** 经纬网格线：正面实线、背面虚线（球面地图的标准画法） */
const grid = computed(() => {
  const front: string[] = []
  const back: string[] = []
  const add = (pts: { x: number; y: number; z: number }[], close = false) => {
    splitPath(pts, close).forEach(s => (s.front ? front : back).push(s.d))
  }
  // 纬线
  for (let lat = -60; lat <= 60; lat += 30) {
    add(Array.from({ length: 181 }, (_, i) => project(lat, -180 + i * 2, rot.value)), true)
  }
  // 经线
  for (let lon = -180; lon < 180; lon += 30) {
    add(Array.from({ length: 91 }, (_, i) => project(-90 + i * 2, lon, rot.value)))
  }
  return { front, back }
})

/** 大陆轮廓：逐条海岸线投影成路径，正面实线、背面虚线 */
const land = computed(() => {
  const front: string[] = []
  const back: string[] = []
  for (const poly of LAND) {
    const pts = poly.map(([lon, lat]) => project(lat, lon, rot.value))
    splitPath(pts, true).forEach(s => (s.front ? front : back).push(s.d))
  }
  return { front, back }
})

const circles = computed(() => [
  { cx: CX, cy: CX, r: R, cls: 'sphere' },
  { cx: CX, cy: CX, r: R * 0.66, cls: 'ring' },
  { cx: CX, cy: CX, r: R * 0.33, cls: 'ring' }
])

const placed = computed(() =>
  nodes.value
    .map(n => {
      const p = project(n.lat, n.lon, rot.value)
      return { ...n, x: p.x, y: p.y, back: p.z < 0 }
    })
    // 背面先画、正面后画 —— 正面落点压在上层
    .sort((a, b) => (a.back ? 0 : 1) - (b.back ? 0 : 1))
)

function nodeLabel(n: Node): string {
  return `${n.ip} · ${n.cn || '--'}${n.hits > 1 ? ' · ' + n.hits + ' 次' : ''}`
}
</script>

<template>
  <div class="globe">
    <div class="globe-sphere">
      <svg
        :viewBox="`0 0 ${size} ${size}`" :width="size" :height="size"
        role="img" aria-label="全球攻击来源分布"
        @click="autoRotate = !autoRotate"
      >
        <circle
          v-for="(c, i) in circles" :key="'c' + i"
          :cx="c.cx" :cy="c.cy" :r="c.r" :class="c.cls"
        />
        <path v-for="(d, i) in land.back" :key="'lb' + i" :d="d" class="land land--back" />
        <path v-for="(d, i) in land.front" :key="'lf' + i" :d="d" class="land" />
        <path v-for="(d, i) in grid.back" :key="'gb' + i" :d="d" class="grid-line grid-line--back" />
        <path v-for="(d, i) in grid.front" :key="'gf' + i" :d="d" class="grid-line" />
        <g v-for="n in placed" :key="n.ip">
          <circle
            :cx="n.x" :cy="n.y" :r="n.kind === 'block' ? 4 : 3"
            :class="['hit', n.kind === 'block' ? 'hit--block' : 'hit--event', n.back ? 'hit--back' : '']"
          />
          <circle :cx="n.x" :cy="n.y" :r="8" class="hit-ring" :class="{ 'hit-ring--back': n.back }" />
          <title>{{ nodeLabel(n) }}</title>
        </g>
      </svg>
    </div>
    <div class="globe-meta">
      <div class="globe-count">
        <b>{{ nodes.length }}</b>
        <span>个来源落点</span>
      </div>
      <div class="globe-legend">
        <span><i class="dot dot--block" />黑名单</span>
        <span><i class="dot dot--event" />事件</span>
        <span class="globe-tip" @click="autoRotate = !autoRotate">
          {{ autoRotate ? '点击暂停旋转' : '点击继续旋转' }}
        </span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.globe { display: flex; flex-direction: column; gap: var(--sp-3); align-items: center; }
.globe-sphere { position: relative; }
.sphere {
  fill: rgba(0, 102, 255, 0.04);
  stroke: var(--border-strong);
  stroke-width: 1;
}
.ring { fill: none; stroke: var(--border); stroke-width: 1; }
.land { fill: rgba(0, 102, 255, 0.07); stroke: var(--border-strong); stroke-width: 0.8; }
.land--back { fill: rgba(0, 102, 255, 0.03); stroke: var(--border); opacity: 0.5; }
.grid-line { fill: none; stroke: var(--border); stroke-width: 0.6; opacity: 0.55; }
.grid-line--back { opacity: 0.24; stroke-dasharray: 3 3; }
.hit--back { opacity: 0.45; }
.hit-ring--back { opacity: 0.1; }
.hit { stroke: none; }
.hit--event { fill: var(--color-info); opacity: 0.85; }
.hit--block { fill: var(--color-danger); }
.hit-ring { fill: none; stroke: var(--color-info); stroke-width: 1; opacity: 0.22; }
.globe-meta { display: flex; gap: var(--sp-4); }
.globe-count { display: flex; align-items: baseline; gap: 5px; }
.globe-count b { font-size: var(--fs-xl); font-family: var(--font-mono); }
.globe-count span { font-size: var(--fs-xs); color: var(--text-3); }
.globe-legend { display: flex; gap: var(--sp-3); font-size: var(--fs-xs); color: var(--text-3); }
.globe-legend span { display: inline-flex; align-items: center; gap: 5px; }
.dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.dot--block { background: var(--color-danger); }
.dot--event { background: var(--color-info); }
.globe-tip { cursor: pointer; color: var(--text-4); }
.globe-tip:hover { color: var(--color-primary); }
</style>
