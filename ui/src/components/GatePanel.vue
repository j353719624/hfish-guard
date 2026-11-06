<script setup lang="ts">
import { ref } from 'vue'
import { login, enterDemo, notify } from '@/store/state'

const token = ref('')
const busy = ref(false)
const err = ref('')

async function submit(): Promise<void> {
  const t = token.value.trim()
  if (!t) {
    err.value = '请输入接口 Token'
    return
  }
  busy.value = true
  err.value = ''
  try {
    await login(t)
    notify('凭证校验通过 · 已连接守护进程', 'ok')
  } catch (e) {
    err.value = (e as Error).message || '凭证无效'
  } finally {
    busy.value = false
  }
}

function demo(): void {
  enterDemo()
  notify('演示模式 · 未连接守护进程，数据为样例', 'warn')
}
</script>

<template>
  <div class="gate">
    <div class="gate-card">
      <div class="gate-head">
        <div class="gate-logo">HG</div>
        <div>
          <h1 class="gate-title">蜜罐守卫</h1>
          <p class="gate-desc">HFish Guard · 蜜罐端口守卫台</p>
        </div>
      </div>

      <p class="gate-lead">请输入接口 Token 以读取状态、事件与黑白名单，凭证仅保存在本次会话。</p>

      <div class="gate-how">
        <div class="gate-how-t">
          <b>Token 从哪拿</b>
          <span>下面三种方式都不需要先进入本页面</span>
        </div>
        <ol>
          <li>
            <b>最省事</b>：关掉这个页面，从<b>飞牛桌面的应用图标</b>打开，会自动带上凭证。
          </li>
          <li>
            <b>在 NAS 上执行</b>（SSH 或终端）：
            <code>curl -s http://127.0.0.1:9705/api/token-local</code>
            <span class="dim">返回 JSON 里的 token 字段就是</span>
          </li>
          <li>
            <b>读配置文件</b>：
            <code>sudo cat /vol2/@appdata/hfish-guard/config.json</code>
            <span class="dim">取其中的 token 字段</span>
          </li>
        </ol>
        <p class="gate-how-n">已经进过一次了？左侧导航<b>「配置 → 接口鉴权」</b>页有 token 与复制按钮。</p>
      </div>

      <form class="gate-form" @submit.prevent="submit">
        <div class="field">
          <label class="field-label" for="tokenInput">API TOKEN<span class="req">*</span></label>
          <input
            id="tokenInput"
            v-model="token"
            class="input mono"
            type="password"
            autocomplete="off"
            placeholder="输入访问凭证"
            :aria-invalid="err ? 'true' : undefined"
            aria-describedby="gateError"
          >
          <div id="gateError" class="err" role="alert">{{ err }}</div>
        </div>
        <button class="btn btn--primary btn--block" type="submit" :disabled="busy">
          {{ busy ? '校验中…' : '进入值守台' }}
        </button>
      </form>

      <div class="gate-foot">
        <button type="button" class="btn btn--ghost btn--sm" @click="demo">
          预览界面（演示数据，非真实监控）
        </button>
        <span>REST · Token 鉴权</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.gate {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--sp-6);
  background:
    radial-gradient(1000px 500px at 20% -10%, rgba(0, 102, 255, 0.07), transparent 60%),
    var(--bg-page);
}
.gate-card {
  width: 100%;
  max-width: 520px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-3);
  padding: var(--sp-8);
}
.gate-head { display: flex; align-items: center; gap: var(--sp-3); margin-bottom: var(--sp-5); }
.gate-logo {
  width: 44px; height: 44px;
  display: flex; align-items: center; justify-content: center;
  border-radius: var(--radius-lg);
  background: var(--color-primary);
  color: #fff;
  font-weight: 700; font-size: var(--fs-lg); letter-spacing: 0.5px;
}
.gate-title { font-size: var(--fs-2xl); }
.gate-desc { margin: 2px 0 0; font-size: var(--fs-sm); color: var(--text-3); }
.gate-lead { margin: 0 0 var(--sp-5); font-size: var(--fs-base); color: var(--text-2); line-height: 1.7; }

.gate-how {
  margin-bottom: var(--sp-5);
  padding: var(--sp-4);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--bg-card-2);
}
.gate-how-t { display: flex; align-items: baseline; gap: var(--sp-2); margin-bottom: var(--sp-2); }
.gate-how-t b { font-size: var(--fs-base); }
.gate-how-t span { font-size: var(--fs-xs); color: var(--text-3); }
.gate-how ol { margin: 0; padding-left: 20px; font-size: var(--fs-sm); line-height: 1.9; color: var(--text-2); }
.gate-how code {
  display: inline-block; margin: 2px 0; padding: 2px 7px;
  border-radius: var(--radius-xs);
  background: var(--bg-hover); border: 1px solid var(--border);
  font-family: var(--font-mono); font-size: var(--fs-xs); color: var(--brand-6);
  word-break: break-all;
}
.gate-how-n {
  margin: var(--sp-3) 0 0; padding-top: var(--sp-3);
  border-top: 1px dashed var(--border);
  font-size: var(--fs-xs); color: var(--text-3);
}
.gate-how-n b { color: var(--text-2); }

.gate-form { display: flex; flex-direction: column; gap: var(--sp-3); }
.gate-foot {
  margin-top: var(--sp-5); padding-top: var(--sp-4);
  border-top: 1px solid var(--border);
  display: flex; justify-content: space-between; align-items: center; gap: var(--sp-3);
  font-size: var(--fs-xs); color: var(--text-3);
}
</style>
