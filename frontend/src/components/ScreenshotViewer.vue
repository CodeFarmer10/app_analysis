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
  border: none;
  padding: 0;
}

.screenshot-label {
  margin-top: 6px;
  color: #595959;
  font-size: 12px;
}
</style>
