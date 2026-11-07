<script setup lang="ts">
import { computed, ref } from 'vue'
import { state, sync, setMode, logout, type ViewName } from '@/store/state'
import StatusView from '@/views/StatusView.vue'
import EventsView from '@/views/EventsView.vue'
import BlacklistView from '@/views/BlacklistView.vue'
import WhitelistView from '@/views/WhitelistView.vue'
import ConfigView from '@/views/ConfigView.vue'

const NAV: { key: ViewName; label: string; icon: string; badge?: () => number }[] = [
  { key: 'status', label: '状态总览', icon: 'grid' },
  { key: 'events', label: '事件流', icon: 'list', badge: () => state.events.length },
  { key: 'blacklist', label: '黑名单', icon: 'ban', badge: () => state.blacklist.length },
  { key: 'whitelist', label: '白名单', icon: 'check' },
  { key: 'config', label: '配置', icon: 'sliders' }
]

const view = computed(() => state.view)
const clock = ref('')

function tick(): void {
  const d = new Date()
  const p = (n: number) => String(n).padStart(2, '0')
  clock.value = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
setInterval(tick, 1000)
tick()

async function toggleMode(): Promise<void> {
  const next = state.status?.mode === 'enforce' ? 'observe' : 'enforce'
  try {
    await setMode(next)
  } catch (e) {
    // 失败时重新拉一次状态，让界面回到真实值
    sync(true)
  }
}
</script>

<template>
  <div class="shell">
    <aside class="rail">
      <div class="rail-brand">
        <div class="rail-logo">HG</div>
        <div class="rail-name">
          <b>蜜罐守卫</b>
          <span class="mono">v{{ state.status?.version || '—' }}</span>
        </div>
      </div>

      <nav class="rail-nav">
        <div class="rail-group">监控</div>
        <button
          v-for="n in NAV.slice(0, 1)" :key="n.key"
          class="nav-item" :class="{ 'is-on': view === n.key }"
          type="button" @click="state.view = n.key"
        >
          <span class="nav-ico" :data-ico="n.icon"></span>
          <span class="nav-txt">{{ n.label }}</span>
        </button>

        <div class="rail-group">处置</div>
        <button
          v-for="n in NAV.slice(1, 4)" :key="n.key"
          class="nav-item" :class="{ 'is-on': view === n.key }"
          type="button" @click="state.view = n.key"
        >
          <span class="nav-ico" :data-ico="n.icon"></span>
          <span class="nav-txt">{{ n.label }}</span>
          <span v-if="n.badge && n.badge()" class="nav-badge">{{ n.badge() }}</span>
        </button>

        <div class="rail-group">系统</div>
        <button
          class="nav-item" :class="{ 'is-on': view === 'config' }"
          type="button" @click="state.view = 'config'"
        >
          <span class="nav-ico" data-ico="sliders"></span>
          <span class="nav-txt">配置</span>
        </button>
      </nav>

      <div class="rail-foot">
        <div class="conn" :class="state.connected ? 'is-on' : 'is-off'">
          <i class="conn-dot"></i>
          <span>{{ state.connected ? '已连接守护进程' : (state.demo ? '演示数据' : '连接中断') }}</span>
        </div>
        <button class="btn btn--ghost btn--sm btn--block" type="button" @click="logout">退出登录</button>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="topbar-title">
          <h2>{{ NAV.find(n => n.key === view)?.label }}</h2>
          <span v-if="state.status" class="topbar-sub mono">
            :{{ state.status.ports.length }} 端口 · 阈值 {{ state.status.threshold }}/{{ state.status.window }}s
          </span>
        </div>
        <div class="grow"></div>

        <div class="mode-switch" role="group" aria-label="处置模式">
          <button
            type="button"
            data-mode="observe"
            :class="{ 'is-on': state.status?.mode === 'observe' }"
            @click="state.status?.mode !== 'observe' && toggleMode()"
          >观察模式</button>
          <button
            type="button"
            data-mode="enforce"
            class="is-enforce"
            :class="{ 'is-on': state.status?.mode === 'enforce' }"
            @click="state.status?.mode !== 'enforce' && toggleMode()"
          >封禁模式</button>
        </div>

        <div class="topbar-clock mono">{{ clock }}</div>
      </header>

      <div class="banner" :class="state.status?.mode === 'enforce' ? 'is-enforce' : ''">
        <template v-if="state.status?.mode === 'enforce'">
          封禁模式 · 超阈值源 IP 将写入黑名单并全端口 DROP
        </template>
        <template v-else>
          观察模式 · 超阈值仅记录事件，不下发封禁（最安全默认值）
        </template>
      </div>

      <main class="content">
        <StatusView v-if="view === 'status'" />
        <EventsView v-else-if="view === 'events'" />
        <BlacklistView v-else-if="view === 'blacklist'" />
        <WhitelistView v-else-if="view === 'whitelist'" />
        <ConfigView v-else-if="view === 'config'" />
      </main>
    </div>
  </div>
</template>

<style scoped>
.shell { flex: 1; display: flex; min-height: 0; }

/* ---------- 左侧导航 ---------- */
.rail {
  width: var(--rail-w);
  flex: 0 0 var(--rail-w);
  /* min-height:0 —— 不加的话 flex item 会被内容撑高，
     主区滚动时侧栏跟着一起长，底部「退出登录」就跑到内容中间去了。 */
  min-height: 0;
  display: flex;
  flex-direction: column;
  background: var(--bg-card);
  border-right: 1px solid var(--border);
}
.rail-brand {
  display: flex; align-items: center; gap: var(--sp-3);
  padding: var(--sp-4) var(--sp-4);
  border-bottom: 1px solid var(--border);
}
.rail-logo {
  width: 32px; height: 32px; flex: 0 0 32px;
  display: flex; align-items: center; justify-content: center;
  border-radius: var(--radius-md);
  background: var(--color-primary); color: #fff;
  font-weight: 700; font-size: var(--fs-sm);
}
.rail-name { display: flex; flex-direction: column; line-height: 1.3; }
.rail-name b { font-size: var(--fs-md); }
.rail-name span { font-size: var(--fs-xs); color: var(--text-3); }

.rail-nav { flex: 1; overflow-y: auto; padding: var(--sp-3) var(--sp-2); }
.rail-group {
  padding: var(--sp-3) var(--sp-3) 6px;
  font-size: var(--fs-xs); color: var(--text-4); font-weight: 500;
}
.nav-item {
  display: flex; align-items: center; gap: 10px;
  width: 100%; padding: 8px 10px;
  border: 0; border-radius: var(--radius-md);
  background: transparent; color: var(--text-2);
  font-family: inherit; font-size: var(--fs-base); text-align: left;
  cursor: pointer; transition: background-color 0.15s, color 0.15s;
}
.nav-item:hover { background: var(--bg-hover); color: var(--text-1); }
.nav-item.is-on { background: var(--color-primary-bg); color: var(--brand-6); font-weight: 500; }
.nav-ico {
  width: 16px; height: 16px; flex: 0 0 16px;
  border-radius: 4px; background: currentColor; opacity: 0.55;
}
.nav-item.is-on .nav-ico { opacity: 1; }
.nav-txt { flex: 1; }
.nav-badge {
  min-width: 18px; padding: 0 5px;
  border-radius: var(--radius-full);
  background: var(--bg-hover); color: var(--text-2);
  font-size: var(--fs-xs); font-family: var(--font-mono); text-align: center;
}
.nav-item.is-on .nav-badge { background: var(--color-primary); color: #fff; }

.rail-foot { padding: var(--sp-3); border-top: 1px solid var(--border); }
.conn {
  display: flex; align-items: center; gap: 7px;
  padding: 6px 8px; margin-bottom: var(--sp-2);
  font-size: var(--fs-xs); color: var(--text-3);
}
.conn-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--text-4); }
.conn.is-on .conn-dot { background: var(--color-success); }
.conn.is-off .conn-dot { background: var(--color-danger); }

/* ---------- 主区 ---------- */
.main { flex: 1; display: flex; flex-direction: column; min-width: 0; min-height: 0; }.topbar {
  height: var(--topbar-h); flex: 0 0 var(--topbar-h);
  display: flex; align-items: center; gap: var(--sp-4);
  padding: 0 var(--sp-6);
  background: var(--bg-card);
  border-bottom: 1px solid var(--border);
}
.topbar-title h2 { font-size: var(--fs-lg); }
.topbar-sub { font-size: var(--fs-xs); color: var(--text-3); }

.mode-switch {
  display: inline-flex; padding: 2px;
  background: var(--bg-hover); border-radius: var(--radius-md);
}
.mode-switch button {
  padding: 5px 12px; border: 0; border-radius: var(--radius-sm);
  background: transparent; color: var(--text-2);
  font-family: inherit; font-size: var(--fs-sm); font-weight: 500;
  cursor: pointer; transition: background-color 0.15s, color 0.15s;
}
.mode-switch button:hover { color: var(--text-1); }
.mode-switch button.is-on { background: var(--bg-card); color: var(--text-1); box-shadow: var(--shadow-1); }
.mode-switch button.is-on.is-enforce { background: var(--color-danger); color: #fff; }
.topbar-clock { font-size: var(--fs-sm); color: var(--text-2); min-width: 62px; text-align: right; }

.banner {
  padding: 8px var(--sp-6);
  background: var(--color-primary-bg); color: var(--brand-6);
  border-bottom: 1px solid var(--border);
  font-size: var(--fs-sm);
}
.banner.is-enforce { background: var(--color-danger-bg); color: var(--red-6); }

.content { flex: 1; overflow-y: auto; padding: var(--sp-6); min-height: 0; }
</style>
