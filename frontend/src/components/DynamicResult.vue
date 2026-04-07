<script setup>
import { computed, h } from 'vue'

import ScreenshotViewer from './ScreenshotViewer.vue'
import { formatDateTime } from '../utils/format'

const props = defineProps({
  dynamicResults: {
    type: Object,
    default: () => ({
      items: [],
      total: 0,
      page: 1,
      size: 20,
    }),
  },
  stepTrafficLogs: {
    type: Object,
    default: () => ({}),
  },
  loading: {
    type: Boolean,
    default: false,
  },
})

const emit = defineEmits(['change-dynamic-page'])

const dynamicColumns = [
  { title: '步骤', dataIndex: 'seq', key: 'seq', width: 80 },
  { title: '操作', dataIndex: 'action', key: 'action', width: 220 },
  { title: '操作时间', dataIndex: 'action_time', key: 'action_time', width: 180 },
  { title: '结果', dataIndex: 'is_success', key: 'is_success', width: 100 },
]
const stepTrafficColumns = [
  { title: '源IP', dataIndex: 'src_ip', key: 'src_ip', width: 140 },
  { title: '源端口', dataIndex: 'src_port', key: 'src_port', width: 90 },
  { title: '目的IP', dataIndex: 'dst_ip', key: 'dst_ip', width: 140 },
  {
    title: '目的端口',
    dataIndex: 'dst_port',
    key: 'dst_port',
    width: 100,
    customHeaderCell: () => ({ class: 'nowrap-header-cell' }),
  },
  { title: '协议', dataIndex: 'protocol', key: 'protocol', width: 100 },
  { title: '域名', dataIndex: 'domain', key: 'domain', width: 180 },
  { title: 'URL', dataIndex: 'url', key: 'url', width: 300 },
  {
    title: '解析IP',
    dataIndex: 'resolved_ip',
    key: 'resolved_ip',
    width: 150,
    customHeaderCell: () => ({ class: 'nowrap-header-cell' }),
  },
]

const dynamicPagination = computed(() => ({
  current: props.dynamicResults?.page || 1,
  pageSize: props.dynamicResults?.size || 20,
  total: props.dynamicResults?.total || 0,
  showSizeChanger: true,
  showTotal: (total) => `共 ${total} 条`,
}))

function getScreenshotItems(record) {
  const items = []
  if (record?.screenshot_after_url) {
    items.push({
      url: record.screenshot_after_url,
    })
  }
  return items
}

function getTrafficItemsByStep(record) {
  const stepSeq = Number(record?.seq)
  if (!Number.isFinite(stepSeq)) {
    return []
  }
  const mappedItems =
    props.stepTrafficLogs?.[stepSeq] || props.stepTrafficLogs?.[String(stepSeq)]
  return Array.isArray(mappedItems) ? mappedItems : []
}

function rowExpandable(record) {
  return getScreenshotItems(record).length > 0 || getTrafficItemsByStep(record).length > 0
}

function hasStepTraffic(record) {
  return getTrafficItemsByStep(record).length > 0
}

function handleDynamicTableChange(pager) {
  emit('change-dynamic-page', {
    page: pager.current || 1,
    size: pager.pageSize || dynamicPagination.value.pageSize,
  })
}

function renderExpandIcon({ expanded, onExpand, record }) {
  return h(
    'button',
    {
      type: 'button',
      class: ['custom-expand-btn', expanded ? 'is-expanded' : 'is-collapsed'],
      onClick: (event) => onExpand(record, event),
      'aria-label': expanded ? '收起' : '展开',
      title: expanded ? '收起' : '展开',
    },
    [h('span', { class: ['expand-shape', expanded ? 'minus' : 'plus'] })]
  )
}

function getDynamicRowClass(record) {
  if (record?.is_success === true) {
    return 'row-success'
  }
  if (record?.is_success === false) {
    return 'row-failed'
  }
  return ''
}
</script>

<template>
  <div class="dynamic-result">
    <a-card :bordered="false" class="section-card">
      <template #title>操作记录</template>
      <a-table
        row-key="id"
        :columns="dynamicColumns"
        :data-source="dynamicResults.items || []"
        :loading="loading"
        :pagination="dynamicPagination"
        :scroll="{ x: 960 }"
        :expandable="{ rowExpandable, expandIcon: renderExpandIcon }"
        :row-class-name="getDynamicRowClass"
        @change="handleDynamicTableChange"
      >
        <template #bodyCell="{ column, record, text }">
          <template v-if="column.key === 'action_time'">
            {{ formatDateTime(text) }}
          </template>
          <template v-else-if="column.key === 'is_success'">
            <span class="result-badge" :class="record.is_success ? 'result-success' : 'result-failed'">
              <span class="result-dot" />
              {{ record.is_success ? '成功' : '失败' }}
            </span>
          </template>
          <template v-else>
            {{ text || '--' }}
          </template>
        </template>

        <template #expandedRowRender="{ record }">
          <div class="expanded-content parallel-layout">
            <div class="expanded-panel screenshot-panel">
              <ScreenshotViewer :screenshots="getScreenshotItems(record)" />
            </div>
            <div v-if="hasStepTraffic(record)" class="expanded-panel step-traffic-wrap">
              <a-table
                row-key="id"
                size="small"
                :columns="stepTrafficColumns"
                :data-source="getTrafficItemsByStep(record)"
                :pagination="false"
                :scroll="{ x: 1180 }"
              >
                <template #bodyCell="{ column, text }">
                  <template v-if="column.key === 'domain' || column.key === 'url'">
                    <a-typography-text class="ellipsis-text traffic-link-text" :ellipsis="{ tooltip: text || '--' }">
                      {{ text || '--' }}
                    </a-typography-text>
                  </template>
                  <template v-else-if="column.key === 'protocol'">
                    <span class="protocol-badge" :class="`protocol-${String(text || '').toLowerCase()}`">
                      {{ text || '--' }}
                    </span>
                  </template>
                  <template v-else-if="column.key === 'resolved_ip'">
                    <span class="mono-text resolved-ip-text">{{ text || '--' }}</span>
                  </template>
                  <template v-else>
                    <span class="mono-text">{{ text || '--' }}</span>
                  </template>
                </template>
              </a-table>
            </div>
          </div>
        </template>
      </a-table>
    </a-card>
  </div>
</template>

<style scoped>
.dynamic-result {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.section-card {
  border-radius: 8px;
}

.expanded-content {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.parallel-layout {
  display: grid;
  grid-template-columns: 186px minmax(0, 1fr);
  align-items: start;
  column-gap: 0;
  row-gap: 0;
}

.expanded-panel {
  min-width: 0;
}

.screenshot-panel {
  min-height: 220px;
}

.screenshot-panel :deep(.screenshot-grid) {
  grid-template-columns: 180px;
  justify-content: start;
  gap: 0;
}

.step-traffic-wrap {
  display: flex;
  flex-direction: column;
  gap: 0;
  min-width: 0;
}

.step-traffic-wrap :deep(.nowrap-header-cell) {
  white-space: nowrap;
}

.step-traffic-wrap :deep(.ant-table-thead > tr > th) {
  color: #cbd9ee !important;
}

.step-traffic-wrap :deep(.ant-table-tbody > tr > td) {
  color: #e2e8f0;
}

.dynamic-result :deep(.custom-expand-btn) {
  width: 34px;
  height: 34px;
  padding: 0;
  border-radius: 6px;
  border: 3px solid #000000;
  background: #ffffff !important;
  line-height: 1;
  cursor: pointer;
  display: grid;
  place-items: center;
  transition: all var(--dur-hover) ease;
  box-shadow:
    0 0 0 2px rgba(255, 255, 255, 0.95),
    0 0 0 4px rgba(0, 0, 0, 0.85),
    0 2px 8px rgba(2, 6, 23, 0.25);
  opacity: 1 !important;
}

.dynamic-result :deep(.custom-expand-btn:hover) {
  background: #f8fafc !important;
  border-color: #000000;
}

.dynamic-result :deep(.custom-expand-btn.is-expanded) {
  background: #000000 !important;
  border-color: #ffffff;
  box-shadow:
    0 0 0 2px rgba(191, 219, 254, 0.95),
    0 0 0 4px rgba(30, 64, 175, 0.82),
    0 2px 8px rgba(2, 6, 23, 0.35);
}

.dynamic-result :deep(.expand-shape) {
  position: relative;
  display: block;
  width: 18px;
  height: 18px;
}

.dynamic-result :deep(.expand-shape::before),
.dynamic-result :deep(.expand-shape::after) {
  content: '';
  position: absolute;
  border-radius: 99px;
  background: #000000;
}

.dynamic-result :deep(.expand-shape::before) {
  left: 0;
  right: 0;
  top: 50%;
  height: 4px;
  transform: translateY(-50%);
}

.dynamic-result :deep(.expand-shape.plus::after) {
  top: 0;
  bottom: 0;
  left: 50%;
  width: 4px;
  transform: translateX(-50%);
}

.dynamic-result :deep(.custom-expand-btn.is-expanded .expand-shape::before),
.dynamic-result :deep(.custom-expand-btn.is-expanded .expand-shape::after) {
  background: #ffffff;
}

.dynamic-result :deep(.row-success td:first-child) {
  box-shadow: inset 2px 0 0 rgba(16, 185, 129, 0.9);
}

.dynamic-result :deep(.row-failed td:first-child) {
  box-shadow: inset 2px 0 0 rgba(239, 68, 68, 0.9);
}

.dynamic-result :deep(.row-success:hover > td) {
  background: rgba(16, 185, 129, 0.08) !important;
}

.dynamic-result :deep(.row-failed:hover > td) {
  background: rgba(239, 68, 68, 0.08) !important;
}

.result-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 26px;
  padding: 0 10px 0 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 700;
  border: 1px solid transparent;
}

.result-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.result-success {
  color: #86efac;
  border-color: rgba(16, 185, 129, 0.5);
  background: rgba(16, 185, 129, 0.18);
}

.result-success .result-dot {
  background: #10b981;
}

.result-failed {
  color: #fda4af;
  border-color: rgba(239, 68, 68, 0.56);
  background: rgba(239, 68, 68, 0.2);
}

.result-failed .result-dot {
  background: #ef4444;
}

.protocol-badge {
  display: inline-block;
  min-width: 56px;
  text-align: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  border: 1px solid rgba(148, 163, 184, 0.4);
  background: rgba(148, 163, 184, 0.15);
  color: #d1d9e4;
}

.protocol-http,
.protocol-https {
  border-color: rgba(59, 130, 246, 0.45);
  background: rgba(59, 130, 246, 0.16);
  color: #bfdbfe;
}

.protocol-tcp {
  border-color: rgba(139, 92, 246, 0.45);
  background: rgba(139, 92, 246, 0.16);
  color: #ddd6fe;
}

.protocol-udp {
  border-color: rgba(245, 158, 11, 0.46);
  background: rgba(245, 158, 11, 0.16);
  color: #fcd34d;
}

.protocol-dns {
  border-color: rgba(16, 185, 129, 0.5);
  background: rgba(16, 185, 129, 0.16);
  color: #a7f3d0;
}

.ellipsis-text {
  display: inline-block;
  max-width: 100%;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.traffic-link-text {
  color: #f8fafc !important;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 4px;
  border: 1px solid rgba(96, 165, 250, 0.42);
  background: rgba(59, 130, 246, 0.14);
}

.traffic-link-text:hover {
  border-color: rgba(191, 219, 254, 0.88);
  background: rgba(59, 130, 246, 0.24);
}

.resolved-ip-text {
  color: #67e8f9;
  font-weight: 700;
}

@media (max-width: 1200px) {
  .parallel-layout {
    grid-template-columns: 1fr;
  }
}
</style>
