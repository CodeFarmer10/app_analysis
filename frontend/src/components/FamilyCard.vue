<script setup>
import { computed } from 'vue'

import { formatDateTime } from '../utils/format'

const props = defineProps({
  family: { type: Object, required: true },
  candidate: { type: Boolean, default: false },
})

defineEmits(['view', 'review', 'rule'])

const latestTime = computed(() => formatDateTime(props.family.latestTaskAt))
</script>

<template>
  <article class="family-card">
    <div class="card-topline">
      <div class="family-type-badge" :class="{ 'family-type-pending': candidate }">
        <strong :title="family.type || '待确认'">{{ family.type || '待确认' }}</strong>
      </div>
      <a-button class="view-detail-btn" size="small" @click="$emit('view', family)">
        查看详情 <span aria-hidden="true">→</span>
      </a-button>
    </div>

    <div class="card-main">
      <h3 :title="family.name">{{ family.name }}</h3>
      <p :title="family.description">{{ family.description || '暂无家族简介' }}</p>
    </div>

    <div class="card-metrics">
      <div>
        <span class="metric-label">关联数量</span>
        <strong>{{ family.count ?? 0 }}</strong>
      </div>
      <div>
        <span class="metric-label">最近关联任务时间</span>
        <span class="metric-value">{{ latestTime }}</span>
      </div>
    </div>

    <div v-if="candidate" class="card-actions">
      <a-button size="small" @click="$emit('rule', family)">家族规则</a-button>
      <a-button type="primary" size="small" @click="$emit('review', family)">审核入库</a-button>
    </div>
  </article>
</template>

<style scoped>
.family-card {
  min-height: 254px;
  display: flex;
  flex-direction: column;
  padding: 20px;
  border: 1px solid var(--border-normal);
  border-radius: 10px;
  background: var(--bg-card);
  transition: border-color 160ms ease, transform 160ms ease;
}

.family-card:hover {
  border-color: rgba(96, 165, 250, 0.48);
  transform: translateY(-2px);
}

.card-topline,
.card-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.metric-label {
  color: var(--text-secondary);
  font-size: 12px;
}

.family-type-badge {
  display: inline-flex;
  align-items: center;
  max-width: 62%;
  min-height: 32px;
  padding: 5px 10px;
  border: 1px solid rgba(248, 113, 113, 0.72);
  border-radius: 7px;
  background: rgba(127, 29, 29, 0.42);
  box-shadow: inset 0 0 0 1px rgba(248, 113, 113, 0.1);
}

.family-type-badge strong {
  overflow: hidden;
  color: #fff1f2;
  font-size: 14px;
  font-weight: 700;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.family-type-pending {
  border-color: rgba(251, 191, 36, 0.68);
  background: rgba(120, 53, 15, 0.4);
  box-shadow: inset 0 0 0 1px rgba(251, 191, 36, 0.08);
}

.family-type-pending strong { color: #fffbeb; }

@media (max-width: 480px) {
  .family-type-badge { max-width: 60%; }
}

.card-topline :deep(.view-detail-btn) {
  height: 29px;
  padding: 0 10px;
  border: 1px solid rgba(96, 165, 250, 0.64);
  border-radius: 6px;
  background: rgba(59, 130, 246, 0.18);
  box-shadow: inset 0 0 0 1px rgba(96, 165, 250, 0.08);
  color: #dbeafe;
  font-weight: 600;
}

.card-topline :deep(.view-detail-btn:hover) {
  border-color: #93c5fd;
  background: rgba(59, 130, 246, 0.3);
  color: #fff;
}

.view-detail-btn span { margin-left: 3px; }

.card-main {
  flex: 1;
  padding-top: 18px;
}

.card-main h3 {
  margin: 0 0 9px;
  overflow: hidden;
  color: var(--text-primary);
  font-size: 19px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.card-main p {
  display: -webkit-box;
  min-height: 44px;
  margin: 0;
  overflow: hidden;
  color: var(--text-secondary);
  line-height: 1.55;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.card-metrics {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding: 15px 0;
  border-top: 1px solid var(--border-subtle);
}

.card-metrics > div {
  display: flex;
  flex-direction: column;
  gap: 7px;
}

.card-metrics strong {
  color: var(--text-primary);
  font-size: 21px;
  line-height: 1;
}

.metric-value {
  color: var(--text-primary);
  font-size: 12px;
  white-space: nowrap;
}

.card-actions {
  justify-content: flex-end;
  padding-top: 14px;
  border-top: 1px solid var(--border-subtle);
}

@media (max-width: 480px) {
  .family-card { padding: 16px; }
  .card-actions { flex-wrap: wrap; }
}
</style>
