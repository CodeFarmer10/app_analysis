<script setup>
import { computed } from 'vue'

const props = defineProps({
  status: {
    type: String,
    default: '',
  },
})

const STATUS_META = {
  downloading: { text: '下载中', color: 'processing' },
  download_failed: { text: '下载失败', color: 'error' },
  static_analyzing: { text: '静态分析中', color: 'processing' },
  static_failed: { text: '静态分析失败', color: 'error' },
  waiting_device: { text: '等待设备', color: 'warning' },
  dynamic_tracing: { text: '动态溯源中', color: 'processing' },
  dynamic_failed: { text: '动态溯源失败', color: 'error' },
  completed: { text: '已完成', color: 'success' },
}

const displayMeta = computed(() => {
  return STATUS_META[props.status] || { text: props.status || '未知状态', color: 'default' }
})
</script>

<template>
  <a-tag :color="displayMeta.color">
    {{ displayMeta.text }}
  </a-tag>
</template>
