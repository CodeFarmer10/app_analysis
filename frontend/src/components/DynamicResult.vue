<script setup>
import { computed } from 'vue'

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
  { title: '目的端口', dataIndex: 'dst_port', key: 'dst_port', width: 90 },
  { title: '协议', dataIndex: 'protocol', key: 'protocol', width: 100 },
  { title: '域名', dataIndex: 'domain', key: 'domain', width: 180 },
  { title: 'URL', dataIndex: 'url', key: 'url', width: 300 },
  { title: '解析IP', dataIndex: 'resolved_ip', key: 'resolved_ip', width: 140 },
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
        :expandable="{ rowExpandable }"
        @change="handleDynamicTableChange"
      >
        <template #bodyCell="{ column, record, text }">
          <template v-if="column.key === 'action_time'">
            {{ formatDateTime(text) }}
          </template>
          <template v-else-if="column.key === 'is_success'">
            <a-tag :color="record.is_success ? 'success' : 'error'">
              {{ record.is_success ? '成功' : '失败' }}
            </a-tag>
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
                  <template v-if="column.key === 'url'">
                    <a-typography-text :ellipsis="{ tooltip: text || '--' }">
                      {{ text || '--' }}
                    </a-typography-text>
                  </template>
                  <template v-else>
                    {{ text || '--' }}
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

@media (max-width: 1200px) {
  .parallel-layout {
    grid-template-columns: 1fr;
  }
}
</style>
