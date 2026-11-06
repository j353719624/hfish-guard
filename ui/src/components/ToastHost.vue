<script setup lang="ts">
import { state } from '@/store/state'
</script>

<template>
  <Transition name="toast">
    <div v-if="state.toast" class="toast" :class="'toast--' + state.toast.kind">
      {{ state.toast.text }}
    </div>
  </Transition>
</template>

<style scoped>
.toast {
  position: fixed;
  left: 50%;
  bottom: 40px;
  transform: translateX(-50%);
  z-index: 999;
  max-width: 560px;
  padding: 10px 18px;
  border-radius: var(--radius-md);
  background: var(--bg-card);
  border: 1px solid var(--border);
  box-shadow: var(--shadow-dropdown);
  font-size: var(--fs-base);
  color: var(--text-1);
}
.toast--ok { border-left: 3px solid var(--color-success); }
.toast--warn { border-left: 3px solid var(--color-warning); }
.toast--err { border-left: 3px solid var(--color-danger); }

.toast-enter-active, .toast-leave-active { transition: opacity 0.2s, transform 0.2s; }
.toast-enter-from, .toast-leave-to { opacity: 0; transform: translate(-50%, 8px); }
</style>
