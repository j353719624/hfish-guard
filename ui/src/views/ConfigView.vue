<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { state, saveConfig, notify, sync } from '@/store/state'
import { api, setToken } from '@/api/guard'

const cfg = ref(state.config)
const busy = ref(false)
const portInput = ref('')
const portErr = ref('')
const copyOk = ref(false)

watch(() => state.config, v => { if (v) cfg.value = JSON.parse(JSON.stringify(v)) }, { deep: true })

const hf = computed(() => cfg.value?.hfish)

async function submit(): Promise<void> {
  if (!cfg.value) return
  busy.value = true
  try {
    await saveConfig({
      mode: cfg.value.mode,
      threshold: cfg.value.threshold,
      window: cfg.value.window,
      poll: cfg.value.poll,
      ttl: cfg.value.ttl,
      udp: cfg.value.udp,
      scan_ports: cfg.value.scan_ports,
      scan_block: cfg.value.scan_block,
      ports: cfg.value.ports,
      hfish: {
        enabled: hf.value!.enabled,
        syslog_port: hf.value!.syslog_port,
        auto_block_level: hf.value!.auto_block_level,
        auto_block_max_per_min: hf.value!.auto_block_max_per_min,
        scan_fanout: hf.value!.scan_fanout,
        max_blocks: hf.value!.max_blocks,
        api_base: hf.value!.api_base,
        api_key: hf.value!.api_key,
        webhook_token: hf.value!.webhook_token
      }
    })
  } catch (e) {
    notify('保存失败：' + ((e as Error).message || '接口不可用'), 'err')
  } finally {
    busy.value = false
  }
}

function addPort(): void {
  const p = Number(portInput.value)
  if (!Number.isInteger(p) || p < 1 || p > 65535) {
    portErr.value = '请输入 1–65535 之间的整数'
    return
  }
  if (cfg.value!.ports.includes(p)) {
    portErr.value = '该端口已在监视列表中'
    return
  }
  portErr.value = ''
  cfg.value!.ports.push(p)
  cfg.value!.ports.sort((a, b) => a - b)
  portInput.value = ''
}

function removePort(p: number): void {
  cfg.value!.ports = cfg.value!.ports.filter(x => x !== p)
}

async function copyToken(): Promise<void> {
  try {
    await navigator.clipboard.writeText(cfg.value?.token || '')
    copyOk.value = true
    setTimeout(() => { copyOk.value = false }, 1600)
  } catch {
    notify('复制失败，请手动选中', 'warn')
  }
}

async function regen(): Promise<void> {
  if (!confirm('重新生成 token 后，当前所有会话都会失效，需要用新 token 重新登录。确定继续？')) return
  try {
    const r = await api.regenToken()
    setToken(r.token)
    await sync(true)
    notify('新凭证已生效 · 其他会话需重新登录', 'warn')
  } catch (e) {
    notify('生成失败：' + ((e as Error).message || '接口不可用'), 'err')
  }
}
</script>

<template>
  <div v-if="cfg" class="cfg">
    <!-- 处置模式 -->
    <div class="card">
      <div class="card__head">
        <span class="card__title">处置模式</span>
        <span class="card__sub">切换后内核规则立即重下发</span>
      </div>
      <div class="card__body">
        <div class="mode-grid">
          <label class="radio-card" :class="{ 'is-on': cfg.mode === 'observe' }">
            <input v-model="cfg.mode" type="radio" value="observe">
            <span>
              <b>观察模式（推荐）</b>
              <span>超阈值只记录事件，不写入黑名单。适合上线初期校准阈值，零误封风险。</span>
            </span>
          </label>
          <label class="radio-card" :class="{ 'is-on': cfg.mode === 'enforce' }">
            <input v-model="cfg.mode" type="radio" value="enforce">
            <span>
              <b>封禁模式</b>
              <span>超阈值源 IP 写入黑名单 ipset 并全端口 DROP，按 TTL 自动过期。</span>
            </span>
          </label>
        </div>
      </div>
    </div>

    <!-- 判定与端口 -->
    <div class="card">
      <div class="card__head"><span class="card__title">判定与端口</span></div>
      <div class="card__body">
        <div class="form-grid form-grid--3">
          <div class="field">
            <label class="field-label" for="cfgThreshold">判定阈值（包）</label>
            <input id="cfgThreshold" v-model.number="cfg.threshold" class="input mono" type="number" min="1" max="100000">
          </div>
          <div class="field">
            <label class="field-label" for="cfgWindow">判定窗口（秒）</label>
            <input id="cfgWindow" v-model.number="cfg.window" class="input mono" type="number" min="10" max="3600">
          </div>
          <div class="field">
            <label class="field-label" for="cfgPoll">轮询间隔（秒）</label>
            <input id="cfgPoll" v-model.number="cfg.poll" class="input mono" type="number" min="1" max="300">
          </div>
          <div class="field">
            <label class="field-label" for="cfgTtl">黑名单 TTL（秒）</label>
            <input id="cfgTtl" v-model.number="cfg.ttl" class="input mono" type="number" min="60" max="604800">
          </div>
          <div class="field">
            <label class="field-label" for="cfgUdp">UDP 探测</label>
            <select id="cfgUdp" v-model="cfg.udp" class="input">
              <option :value="true">一并拦截 UDP 扫描</option>
              <option :value="false">只处理 TCP</option>
            </select>
            <div class="hint">蜜罐端口上的 UDP 探测同样计包</div>
          </div>
          <div class="field">
            <label class="field-label" for="cfgScanPorts">扫描判定（端口数）</label>
            <input id="cfgScanPorts" v-model.number="cfg.scan_ports" class="input mono" type="number" min="0" max="64">
            <div class="hint">同源命中多少个不同端口算扫描，0=关闭</div>
          </div>
        </div>

        <div class="ports">
          <div class="ports-head">
            <span class="field-label">监视端口（{{ cfg.ports.length }}）</span>
            <div class="row">
              <input v-model="portInput" class="input mono port-input" placeholder="端口号" @keyup.enter="addPort">
              <button class="btn btn--default btn--sm" type="button" @click="addPort">添加</button>
            </div>
          </div>
          <div v-if="portErr" class="err">{{ portErr }}</div>
          <div class="port-chips">
            <span v-for="p in cfg.ports" :key="p" class="port-chip">
              <span class="mono">{{ p }}</span>
              <button type="button" class="port-x" @click="removePort(p)">×</button>
            </span>
          </div>
        </div>
      </div>
      <div class="card__foot">
        <button class="btn btn--primary" type="button" :disabled="busy" @click="submit">
          {{ busy ? '保存中…' : '保存并热加载' }}
        </button>
        <span class="dim">无需重启 guard.service</span>
      </div>
    </div>

    <!-- HFish 联动 -->
    <div class="card">
      <div class="card__head">
        <span class="card__title">HFish 联动</span>
        <span class="card__sub">蜜罐告警 → 自动封禁</span>
      </div>
      <div class="card__body">
        <div class="form-grid form-grid--3">
          <div class="field">
            <label class="field-label" for="cfgHfEnabled">告警接收</label>
            <select id="cfgHfEnabled" v-model="hf!.enabled" class="input">
              <option :value="true">开启（监听 syslog）</option>
              <option :value="false">关闭</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label" for="cfgHfishLevel">按告警等级自动封禁</label>
            <select id="cfgHfishLevel" v-model="hf!.auto_block_level" class="input">
              <option value="">不自动封禁</option>
              <option value="all">全部等级（含 other，收到即封）</option>
              <option value="critical">严重及以上</option>
              <option value="high">高危及以上</option>
              <option value="mid">中危及以上</option>
              <option value="low">低危及以上</option>
            </select>
            <div class="hint">HFish 对蜜罐命中给的是 other，必须选「全部等级」才会封</div>
          </div>
          <div class="field">
            <label class="field-label" for="cfgBlockRate">封禁速率熔断（个/分钟）</label>
            <input id="cfgBlockRate" v-model.number="hf!.auto_block_max_per_min" class="input mono" type="number" min="0" max="10000">
            <div class="hint">超限只记事件不封禁，防止上游误配刷爆黑名单</div>
          </div>
          <div class="field">
            <label class="field-label" for="cfgScanFanout">扫描判定扇出</label>
            <input id="cfgScanFanout" v-model.number="hf!.scan_fanout" class="input mono" type="number" min="0" max="64">
            <div class="hint">同源命中多少个端口判为扫描者</div>
          </div>
          <div class="field">
            <label class="field-label" for="cfgMaxBlocks">黑名单容量上限</label>
            <input id="cfgMaxBlocks" v-model.number="hf!.max_blocks" class="input mono" type="number" min="0" max="1000000">
          </div>
          <div class="field">
            <label class="field-label" for="cfgHfishKey">HFish API Key（可选）</label>
            <input id="cfgHfishKey" v-model="hf!.api_key" class="input mono" placeholder="用于拉取攻击来源情报">
          </div>
        </div>
      </div>
      <div class="card__foot">
        <button class="btn btn--primary" type="button" :disabled="busy" @click="submit">
          {{ busy ? '保存中…' : '保存并热加载' }}
        </button>
      </div>
    </div>

    <!-- 接口鉴权 -->
    <div class="card">
      <div class="card__head">
        <span class="card__title">接口鉴权</span>
        <span class="card__sub">REST · Bearer Token</span>
      </div>
      <div class="card__body">
        <div class="field">
          <label class="field-label" for="cfgToken">当前 Token</label>
          <div class="row">
            <input id="cfgToken" :value="cfg.token" class="input mono grow" readonly>
            <button class="btn btn--default" type="button" @click="copyToken">{{ copyOk ? '已复制' : '复制' }}</button>
            <button class="btn btn--danger" type="button" @click="regen">重新生成</button>
          </div>
          <div class="hint">
            页面入口在<strong>内网</strong>访问时会自动带上凭证；外网访问必须手填。
            在 NAS 上执行 <code class="mono">curl -s http://127.0.0.1:9705/api/token-local</code> 可取回。
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.cfg { display: flex; flex-direction: column; gap: var(--sp-4); }
.mode-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--sp-4); }
@media (max-width: 800px) { .mode-grid { grid-template-columns: 1fr; } }

.card__foot {
  display: flex; align-items: center; gap: var(--sp-3);
  padding: var(--sp-4) var(--sp-5);
  border-top: 1px solid var(--border);
  font-size: var(--fs-sm);
}

.ports { margin-top: var(--sp-5); }
.ports-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--sp-2); }
.port-input { width: 100px; min-height: 26px; font-size: var(--fs-sm); }
.port-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: var(--sp-2); }
.port-chip {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 2px 4px 2px 9px;
  border-radius: var(--radius-sm);
  background: var(--bg-hover);
  font-size: var(--fs-xs); color: var(--text-2);
}
.port-x {
  width: 16px; height: 16px; padding: 0;
  border: 0; border-radius: 4px;
  background: transparent; color: var(--text-3);
  cursor: pointer; line-height: 1;
}
.port-x:hover { background: var(--color-danger-bg); color: var(--color-danger); }
</style>
