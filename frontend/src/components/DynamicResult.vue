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
  dynamicSummary: {
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
  { title: '归属地', dataIndex: 'ip_country', key: 'ip_country', width: 110 },
  { title: 'URL', dataIndex: 'url', key: 'url', width: 300 },
  {
    title: '主控打标',
    dataIndex: 'is_real_controller',
    key: 'is_real_controller',
    width: 120,
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
  const label = expanded ? '−' : '+'
  return h(
    'button',
    {
      type: 'button',
      class: ['custom-expand-btn', expanded ? 'is-expanded' : 'is-collapsed'],
      onClick: (event) => onExpand(record, event),
      'aria-label': label,
      title: label,
    },
    [h('span', { class: 'expand-glyph', 'aria-hidden': 'true' }, label)]
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

function isRealController(value) {
  if (value === true) {
    return true
  }
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed === 1
}

const protocolRatioItems = computed(() => props.dynamicSummary?.protocol_ratio_items || [])
const domainRatioItems = computed(() => props.dynamicSummary?.domain_ratio_items || [])
const ipRatioItems = computed(() => props.dynamicSummary?.ip_ratio_items || [])
const realControllerTargets = computed(() => props.dynamicSummary?.real_controller_targets || [])
</script>

<template>
  <div class="dynamic-result">
    <a-card :bordered="false" class="section-card summary-card">
      <template #title>动态溯源总览</template>

      <div class="ratio-layout">
        <div class="ratio-card">
          <h3 class="ratio-title">协议占比</h3>
          <div class="ratio-body">
            <template v-if="protocolRatioItems.length">
              <div v-for="item in protocolRatioItems" :key="`protocol-${item.label}`" class="ratio-row">
                <div class="ratio-meta">
                  <div class="ratio-label">{{ item.label }}</div>
                  <div class="ratio-number">{{ item.count }} / {{ item.percent_text }}</div>
                </div>
                <div class="ratio-bar">
                  <div class="ratio-fill" :style="{ width: `${item.bar_width}%` }" />
                </div>
              </div>
            </template>
            <div v-else class="ratio-empty">暂无上行流量统计</div>
          </div>
        </div>

        <div class="ratio-card">
          <h3 class="ratio-title">域名占比</h3>
          <div class="ratio-body">
            <template v-if="domainRatioItems.length">
              <div v-for="item in domainRatioItems" :key="`domain-${item.label}`" class="ratio-row">
                <div class="ratio-meta">
                  <div class="ratio-label">{{ item.label }}</div>
                  <div class="ratio-number">{{ item.count }} / {{ item.percent_text }}</div>
                </div>
                <div class="ratio-bar">
                  <div class="ratio-fill" :style="{ width: `${item.bar_width}%` }" />
                </div>
              </div>
            </template>
            <div v-else class="ratio-empty">暂无上行流量统计</div>
          </div>
        </div>

        <div class="ratio-card">
          <h3 class="ratio-title">IP占比</h3>
          <div class="ratio-body">
            <template v-if="ipRatioItems.length">
              <div v-for="item in ipRatioItems" :key="`ip-${item.label}`" class="ratio-row">
                <div class="ratio-meta">
                  <div class="ratio-label">{{ item.label }}</div>
                  <div class="ratio-number">{{ item.count }} / {{ item.percent_text }}</div>
                </div>
                <div class="ratio-bar">
                  <div class="ratio-fill" :style="{ width: `${item.bar_width}%` }" />
                </div>
              </div>
            </template>
            <div v-else class="ratio-empty">暂无上行流量统计</div>
          </div>
        </div>
      </div>

      <div class="controller-panel">
        <div class="controller-header">诈骗主控</div>
        <a-table
          class="controller-table"
          size="small"
          :pagination="false"
          :data-source="realControllerTargets.length ? realControllerTargets : [{ row_no: 1, domain_text: '--', ip_text: '--', country_text: '--' }]"
          :columns="[
            { title: '域名', dataIndex: 'domain_text', key: 'domain_text', width: 280 },
            { title: 'IP', dataIndex: 'ip_text', key: 'ip_text', width: 220 },
            { title: '归属地', dataIndex: 'country_text', key: 'country_text', width: 160 },
          ]"
          row-key="row_no"
          :scroll="{ x: 720 }"
        >
          <template #bodyCell="{ text }">
            <span class="mono-text">{{ text || '--' }}</span>
          </template>
        </a-table>
      </div>
    </a-card>

    <a-card :bordered="false" class="section-card">
      <template #title>操作记录</template>
      <a-table
        row-key="id"
        :columns="dynamicColumns"
        :data-source="dynamicResults.items || []"
        :loading="loading"
        :pagination="dynamicPagination"
        :scroll="{ x: 960 }"
        :row-expandable="rowExpandable"
        :expand-icon="renderExpandIcon"
        :expand-column-width="46"
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
                  <template v-else-if="column.key === 'ip_country'">
                    <span class="country-chip">{{ text || '--' }}</span>
                  </template>
                  <template v-else-if="column.key === 'protocol'">
                    <span class="protocol-badge" :class="`protocol-${String(text || '').toLowerCase()}`">
                      {{ text || '--' }}
                    </span>
                  </template>
                  <template v-else-if="column.key === 'is_real_controller'">
                    <span class="controller-tag" :class="isRealController(text) ? 'controller-yes' : 'controller-no'">
                      {{ isRealController(text) ? '主控' : '非主控' }}
                    </span>
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

.summary-card {
  overflow: hidden;
}

.ratio-layout {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.ratio-card {
  border: 1px solid rgba(125, 160, 210, 0.28);
  border-radius: 14px;
  overflow: hidden;
  background: rgba(15, 23, 42, 0.42);
}

.ratio-title,
.controller-header {
  margin: 0;
  padding: 10px 14px;
  background: linear-gradient(90deg, rgba(30, 64, 175, 0.3) 0%, rgba(37, 99, 235, 0.2) 100%);
  color: #dbeafe;
  font-size: 13px;
  font-weight: 800;
  border-bottom: 1px solid rgba(125, 160, 210, 0.22);
}

.ratio-body {
  padding: 12px 14px;
}

.ratio-empty {
  color: #94a3b8;
  font-size: 12px;
}

.ratio-row + .ratio-row {
  margin-top: 10px;
}

.ratio-meta {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 5px;
  font-size: 11px;
}

.ratio-label {
  flex: 1;
  color: #f8fafc;
  font-weight: 700;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.ratio-number {
  color: #8fa6c6;
  white-space: nowrap;
}

.ratio-bar {
  width: 100%;
  height: 8px;
  border-radius: 999px;
  background: rgba(37, 99, 235, 0.14);
  overflow: hidden;
}

.ratio-fill {
  height: 100%;
  border-radius: 999px;
  background: linear-gradient(90deg, #2563eb 0%, #60a5fa 100%);
}

.controller-panel {
  border: 1px solid rgba(125, 160, 210, 0.28);
  border-radius: 14px;
  overflow: hidden;
  background: rgba(15, 23, 42, 0.42);
}

.controller-table :deep(.ant-table) {
  background: transparent;
}

.controller-table :deep(.ant-table-thead > tr > th) {
  color: #cbd5e1 !important;
  background: rgba(15, 23, 42, 0.28) !important;
}

.controller-table :deep(.ant-table-tbody > tr > td) {
  color: #e2e8f0;
  background: rgba(15, 23, 42, 0.08);
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
  width: 20px;
  min-width: 20px;
  height: 20px;
  padding: 0;
  border-radius: 6px;
  border: 1px solid rgba(125, 160, 210, 0.4);
  background: rgba(73, 121, 194, 0.28) !important;
  color: rgba(226, 232, 240, 0.92) !important;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 800;
  line-height: 1;
  transition: all var(--dur-hover) ease;
  opacity: 1 !important;
  visibility: visible !important;
  box-shadow:
    0 0 0 1px rgba(73, 121, 194, 0.08),
    0 1px 4px rgba(15, 23, 42, 0.14);
}

.dynamic-result :deep(.custom-expand-btn:hover) {
  transform: translateY(-1px);
  border-color: rgba(147, 197, 253, 0.5);
  background: rgba(73, 121, 194, 0.4) !important;
  box-shadow:
    0 0 0 1px rgba(96, 165, 250, 0.12),
    0 3px 8px rgba(15, 23, 42, 0.16);
}

.dynamic-result :deep(.custom-expand-btn.is-expanded) {
  transform: none;
  border-color: rgba(125, 160, 210, 0.52);
  background: rgba(96, 165, 250, 0.46) !important;
  color: rgba(239, 246, 255, 0.96) !important;
}

.dynamic-result :deep(.expand-glyph) {
  display: block;
  min-width: 1ch;
  text-align: center;
  line-height: 1;
  transform: translateY(-0.5px);
  text-shadow: none;
}

.dynamic-result :deep(.ant-table-row-expand-icon-cell) {
  text-align: center;
}

.dynamic-result :deep(.ant-table-row-expand-icon-cell .custom-expand-btn) {
  margin-inline: auto;
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

.controller-tag {
  display: inline-block;
  min-width: 56px;
  text-align: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 700;
  border: 1px solid rgba(148, 163, 184, 0.45);
  background: rgba(148, 163, 184, 0.15);
  color: #d1d9e4;
}

.controller-yes {
  border-color: rgba(239, 68, 68, 0.56);
  background: rgba(239, 68, 68, 0.2);
  color: #fecaca;
}

.country-chip {
  display: inline-block;
  min-width: 42px;
  text-align: center;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  border: 1px solid rgba(56, 189, 248, 0.34);
  background: rgba(14, 165, 233, 0.14);
  color: #bae6fd;
}

@media (max-width: 1200px) {
  .ratio-layout {
    grid-template-columns: 1fr;
  }

  .parallel-layout {
    grid-template-columns: 1fr;
  }
}
</style>
