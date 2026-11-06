/**
 * UI 自检 —— 在页面里跑一组断言，结果写到 document.title 与底部结果条。
 *
 * 用法：访问 /web/?selftest=1
 * 标题格式：SELFTEST PASS :: checks=N :: js-errors=M
 *
 * 为什么要有它：前端出问题时浏览器只报一句 `HG_LIVE is undefined`，
 * 没有任何直观报错（这是 v1.6.1 那次漏引号白屏的教训）。
 * 自检把「界面结构对不对、数据通不通」变成可断言的检查项。
 */
import { nextTick, ref } from 'vue'
import { state, geoOf, fmtTime, fmtDuration, loadDemoData } from '@/store/state'
import { api } from '@/api/guard'

const errors: string[] = []
const bootErrors: string[] = []
let checks = 0

function chk(cond: unknown, tag: string): void {
  checks++
  if (!cond) errors.push(tag)
}

function count(sel: string): number {
  return document.querySelectorAll(sel).length
}

// ---- 捕获启动期的 JS 错误 ----
// 必须在模块加载时就挂上：应用挂载阶段的报错才抓得到，
// 挂晚了只会漏掉「白屏」这类最需要定位的错误。
if (typeof window !== 'undefined') {
  window.addEventListener('error', e => {
    bootErrors.push('error:' + (e.message || 'unknown') + '@' + (e.filename || '').split('/').pop() + ':' + e.lineno)
  })
  window.addEventListener('unhandledrejection', e => {
    bootErrors.push('rejection:' + String((e as PromiseRejectionEvent).reason))
  })
}

/** 自检结果文本（由 App.vue 渲染到底部条上） */
export const selftestResult = ref('')

function sleep(ms: number): Promise<void> {
  return new Promise(res => setTimeout(res, ms))
}

/**
 * 等某个条件成立，最多等 timeout 毫秒。
 * 用于「归属地是异步补查的」这类场景 —— 不能因为查得慢就判失败。
 */
async function waitFor(cond: () => boolean, timeout: number): Promise<boolean> {
  const t0 = Date.now()
  while (Date.now() - t0 < timeout) {
    if (cond()) return true
    await sleep(100)
  }
  return cond()
}

export async function runSelfTest(): Promise<void> {
  // 演示态下没有真实数据，填一份最小样例，让结构断言也能跑。
  // 若已有真实数据（真机带 token 访问），保持真实数据不动。
  if (!state.status) loadDemoData()
  try {
    // ---- 结构 ----
    chk(document.getElementById('app'), 'app:missing')
    chk(document.querySelector('.rail'), 'rail:missing')
    chk(count('.rail .nav-item') === 6, 'rail:nav-count=' + count('.rail .nav-item'))
    chk(document.querySelector('.topbar'), 'topbar:missing')
    chk(document.querySelector('.mode-switch'), 'mode:switch-missing')
    chk(document.querySelector('.banner'), 'banner:missing')

    // ---- 样式令牌（fnOS Semi Design 体系）----
    const rootStyle = getComputedStyle(document.documentElement)
    chk(rootStyle.getPropertyValue('--brand-4').trim() !== '', 'tokens:brand')
    chk(rootStyle.getPropertyValue('--radius-lg').trim() === '12px', 'tokens:radius')
    chk(rootStyle.getPropertyValue('--font').includes('PingFang'), 'tokens:font')

    // ---- 无外部资源（fnOS 可能断网）----
    chk(count('img[src^="http"], link[rel="stylesheet"][href^="http"], script[src^="http"]') === 0,
        'assets:external')

    // ---- 数据已同步 ----
    chk(!!state.status, 'data:status-missing')
    if (state.status) {
      const s = state.status
      chk(typeof s.mode === 'string', 'data:mode')
      chk(Array.isArray(s.ports) && s.ports.length > 0, 'data:ports')
      chk(Array.isArray(s.port_state), 'data:port-state')
      chk(s.kernel && typeof s.kernel.kind === 'string', 'data:kernel')
      chk(Array.isArray(s.window_series), 'data:series')
    }
    chk(Array.isArray(state.events), 'data:events')
    chk(Array.isArray(state.blacklist), 'data:blacklist')
    chk(Array.isArray(state.whitelist), 'data:whitelist')
    // 配置页完全依赖它：缺了整个视图不渲染（v-if="cfg"）
    chk(!!state.config, 'data:config-missing')
    chk(!!state.config?.hfish, 'data:config-hfish-missing')

    await nextTick()

    // ---- 视图切换 ----
    const navs = Array.from(document.querySelectorAll('.rail .nav-item')) as HTMLElement[]
    chk(navs.length === 6, 'nav:count')

    // 逐个视图切过去，确认每个都渲染出内容
    // 顺序对应左侧导航：态势 / 总览 / 事件 / 黑名单 / 白名单 / 配置
    const viewMarkers = ['.kpi-row', '.kv-grid', '.table', '.card', '.card', '.card']
    for (let i = 0; i < navs.length; i++) {
      navs[i].click()
      await nextTick()
      await sleep(30)
      const content = document.querySelector('.content')
      chk(!!content && (content as HTMLElement).innerText.trim().length > 20, 'view:' + i + ':empty')
      chk(count(viewMarkers[i]) > 0, 'view:' + i + ':marker')
    }

    // ---- 事件流表格 ----
    navs[2].click()
    await nextTick()
    await sleep(30)
    const ths = document.querySelectorAll('.content .table thead th')
    chk(ths.length === 7, 'events:cols=' + ths.length)
    chk(count('.content .table tbody tr') > 0, 'events:empty')

    // ---- 归属地（异步补查，要给一点时间）----
    const anyIp = state.events[0]?.ip || state.blacklist[0]?.ip
    if (anyIp) {
      if (!geoOf(anyIp)) {
        // warmGeo 有去重保护（geoAsked），已问过就不会再问，
        // 所以这里直接打后端查一次，保证断言拿到真实结果。
        try {
          const res = await api.geo([anyIp])
          ;(res.items || []).forEach(g => { if (g && g.ip) state.geoCache[g.ip] = g })
        } catch { /* 后端查不到归属地，下面会判失败 */ }
        if (!geoOf(anyIp)) await waitFor(() => !!geoOf(anyIp), 2000)
      }
      const g = geoOf(anyIp)
      chk(!!g, 'geo:missing')
      if (g) {
        chk(!!g.cn, 'geo:cn')
        chk(g.cc.length === 2, 'geo:cc')
      }
    }

    // ---- 黑名单操作按钮 ----
    navs[3].click()
    await nextTick()
    await sleep(30)
    if (state.blacklist.length) {
      chk(count('.content .table tbody tr .btn') >= 1, 'blacklist:unblock-btn')
    }

    // ---- 白名单表 ----
    navs[4].click()
    await nextTick()
    await sleep(30)
    chk(!!document.getElementById('wlCidr'), 'whitelist:form')

    // ---- 配置页 ----
    navs[5].click()
    await nextTick()
    await sleep(30)
    chk(!!document.getElementById('cfgThreshold'), 'config:threshold')
    chk(!!document.getElementById('cfgToken'), 'config:token')
    chk(count('.port-chip') === (state.config?.ports.length ?? -1),
        'config:ports=' + count('.port-chip') + '/' + (state.config?.ports.length ?? -1))

    // ---- 模式切换按钮存在且与状态一致 ----
    const mBtns = Array.from(document.querySelectorAll('.mode-switch button')) as HTMLElement[]
    chk(mBtns.length === 2, 'mode:buttons')
    const onBtn = mBtns.filter(b => b.classList.contains('is-on'))
    chk(onBtn.length === 1, 'mode:highlight=' + onBtn.length)
    if (onBtn.length === 1) {
      chk(onBtn[0].getAttribute('data-mode') === state.status?.mode ||
          (state.status?.mode === 'enforce' && onBtn[0].textContent.includes('封禁')) ||
          (state.status?.mode === 'observe' && onBtn[0].textContent.includes('观察')),
          'mode:match')
    }

    // ---- 格式化函数 ----
    chk(fmtTime(1700000000000).length >= 14, 'fmt:time')
    chk(fmtDuration(0) === '已过期', 'fmt:expired')
    chk(fmtDuration(90).includes('分'), 'fmt:min')
    chk(fmtDuration(7200).includes('小时'), 'fmt:hour')

    // ---- 无横向溢出 ----
    const doc = document.documentElement
    chk(doc.scrollWidth <= doc.clientWidth + 2,
        'overflow:scrollW=' + doc.scrollWidth + ' clientW=' + doc.clientWidth)
  } catch (e) {
    errors.push('exception:' + (e as Error).message)
  }

  const n = errors.length + bootErrors.length
  const text = 'SELFTEST ' + (n ? 'FAIL :: ' + errors.concat(bootErrors).join(' | ') : 'PASS') +
    ' :: checks=' + checks + ' :: js-errors=' + bootErrors.length +
    ' :: innerW=' + window.innerWidth + ' :: scrollW=' + document.documentElement.scrollWidth
  selftestResult.value = text
  document.title = text
}

export function bootSelfTest(): void {
  // 注意：不能在模块顶层用 onMounted —— 那时还没挂载到组件树上，回调不会触发。
  // 这里用轮询等待 AppShell 渲染完成再跑，避免时序竞态。
  if (!/[?&]selftest(=|&|$)/.test(location.search)) return
  const t0 = Date.now()
  const tick = async (): Promise<void> => {
    const ready = state.authed && !!state.status && !!document.querySelector('.rail')
    if (!ready && Date.now() - t0 < 6000) {
      setTimeout(() => { void tick() }, 150)
      return
    }
    if (!state.authed) {
      // 没有凭证也照样能跑结构断言
      state.authed = true
      state.demo = true
      loadDemoData()
      await nextTick()
    }
    await runSelfTest()
  }
  setTimeout(() => { void tick() }, 300)
}
