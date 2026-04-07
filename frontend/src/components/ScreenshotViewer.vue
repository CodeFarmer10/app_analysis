<script setup>
const props = defineProps({
  screenshots: {
    type: Array,
    default: () => [],
  },
})
</script>

<template>
  <a-empty v-if="!screenshots.length" description="暂无截图" />
  <a-image-preview-group v-else>
    <div class="screenshot-grid">
      <div v-for="(item, index) in screenshots" :key="item.url || index" class="screenshot-item">
        <a-image :src="item.url" :alt="item.label || `截图 ${index + 1}`" :width="180" />
        <div v-if="item.label" class="screenshot-label">{{ item.label }}</div>
      </div>
    </div>
  </a-image-preview-group>
</template>

<style scoped>
.screenshot-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 12px;
}

.screenshot-item {
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 6px;
  background: rgba(255, 255, 255, 0.02);
  transition: transform var(--dur-hover) ease;
}

.screenshot-item :deep(.ant-image) {
  display: block;
  overflow: hidden;
  border-radius: 6px;
}

.screenshot-item :deep(.ant-image-img) {
  transition: transform var(--dur-expand) ease;
}

.screenshot-item:hover {
  transform: translateY(-2px);
}

.screenshot-item:hover :deep(.ant-image-img) {
  transform: scale(1.05);
}

.screenshot-label {
  margin-top: 6px;
  color: var(--text-secondary);
  font-size: 12px;
}
</style>
