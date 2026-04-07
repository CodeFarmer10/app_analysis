<script setup>
import { computed } from 'vue'

const props = defineProps({
  status: {
    type: String,
    default: '',
  },
})

const STATUS_META = {
  downloading: { text: '下载中', tone: 'processing', pulse: true },
  download_failed: { text: '下载失败', tone: 'error', pulse: false },
  static_analyzing: { text: '静态分析中', tone: 'processing', pulse: true },
  static_failed: { text: '静态分析失败', tone: 'error', pulse: false },
  waiting_device: { text: '等待设备', tone: 'warning', pulse: false },
  dynamic_tracing: { text: '动态溯源中', tone: 'processing', pulse: true },
  dynamic_failed: { text: '动态溯源失败', tone: 'error', pulse: false },
  completed: { text: '已完成', tone: 'success', pulse: false },
}

const displayMeta = computed(() => {
  return STATUS_META[props.status] || { text: props.status || '未知状态', tone: 'default', pulse: false }
})
</script>

<template>
  <span class="status-tag" :class="[`tone-${displayMeta.tone}`, { pulsing: displayMeta.pulse }]">
    <span class="status-dot" />
    <span>{{ displayMeta.text }}</span>
  </span>
</template>

<style scoped>
.status-tag {
  --tone-color: #94a3b8;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 26px;
  padding: 0 10px 0 8px;
  border-radius: 4px;
  border: 1px solid rgba(148, 163, 184, 0.35);
  background: rgba(148, 163, 184, 0.14);
  color: var(--tone-color);
  font-size: 12px;
  font-weight: 600;
}

.status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--tone-color);
}

.pulsing .status-dot {
  animation: pulse-dot 1.2s ease-in-out infinite;
}

.tone-processing {
  --tone-color: #3b82f6;
  border-color: rgba(59, 130, 246, 0.45);
  background: rgba(59, 130, 246, 0.15);
}

.tone-success {
  --tone-color: #10b981;
  border-color: rgba(16, 185, 129, 0.45);
  background: rgba(16, 185, 129, 0.15);
}

.tone-warning {
  --tone-color: #f59e0b;
  border-color: rgba(245, 158, 11, 0.45);
  background: rgba(245, 158, 11, 0.15);
}

.tone-error {
  --tone-color: #ef4444;
  border-color: rgba(239, 68, 68, 0.45);
  background: rgba(239, 68, 68, 0.15);
}

.tone-default {
  --tone-color: #64748b;
  border-color: rgba(100, 116, 139, 0.45);
  background: rgba(100, 116, 139, 0.16);
}

@keyframes pulse-dot {
  0%,
  100% {
    transform: scale(1);
    box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.45);
  }
  50% {
    transform: scale(0.88);
    box-shadow: 0 0 0 5px rgba(59, 130, 246, 0);
  }
}
</style>
