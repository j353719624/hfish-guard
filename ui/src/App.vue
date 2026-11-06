<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { state, initAuth, startPolling, stopPolling } from '@/store/state'
import { bootSelfTest, selftestResult } from '@/selftest'
import GatePanel from '@/components/GatePanel.vue'
import AppShell from '@/components/AppShell.vue'
import ToastHost from '@/components/ToastHost.vue'

onMounted(() => {
  initAuth()
  startPolling()
  bootSelfTest()
})
onUnmounted(() => stopPolling())
</script>

<template>
  <div class="root">
    <GatePanel v-if="!state.authed" />
    <AppShell v-else />
    <ToastHost />
    <!-- 自检结果条：只有 ?selftest=1 时才显示 -->
    <div v-if="selftestResult" class="selftest-bar" id="selftest-result">{{ selftestResult }}</div>
  </div>
</template>

<style scoped>
.root {
  height: 100%;
  display: flex;
  flex-direction: column;
}

.selftest-bar {
  position: fixed;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 999;
  padding: 10px 16px;
  background: rgba(11, 11, 12, 0.92);
  color: #7df3c4;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.6;
  word-break: break-all;
}
</style>
