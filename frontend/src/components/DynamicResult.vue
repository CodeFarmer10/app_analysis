<script setup>
import { computed } from 'vue'

import ScreenshotViewer from './ScreenshotViewer.vue'
import TrafficLogTable from './TrafficLogTable.vue'
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
  trafficLogs: {
    type: Object,
    default: () => ({
      items: [],
      total: 0,
      page: 1,
      size: 50,
    }),
  },
  loading: {
    type: Boolean,
    default: false,
  },
})

const emit = defineEmits(['change-dynamic-page', 'change-traffic-page'])

const dynamicColumns = [
  { title: '步骤', dataIndex: 'seq', key: 'seq', width: 80 },
  { title: '操作', dataIndex: 'action', key: 'action', width: 220 },
  { title: '操作结果', dataIndex: 'action_result', key: 'action_result', width: 280 },
  { title: '操作时间', dataIndex: 'action_time', key: 'action_time', width: 180 },
  { title: '结果', dataIndex: 'is_success', key: 'is_success', width: 100 },
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
  if (record?.screenshot_before_url) {
    items.push({
      url: record.screenshot_before_url,
      label: `步骤 ${record.seq} - 操作前`,
    })
  }
  if (record?.screenshot_after_url) {
    items.push({
      url: record.screenshot_after_url,
      label: `步骤 ${record.seq} - 操作后`,
    })
  }
  return items
}

function rowExpandable(record) {
  return getScreenshotItems(record).length > 0
}

function handleDynamicTableChange(pager) {
  emit('change-dynamic-page', {
    page: pager.current || 1,
    size: pager.pageSize || dynamicPagination.value.pageSize,
  })
}

function handleTrafficTableChange(payload) {
  emit('change-traffic-page', payload)
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
          <template v-else-if="column.key === 'action_result'">
            <a-typography-text :ellipsis="{ tooltip: text || '--' }">
              {{ text || '--' }}
            </a-typography-text>
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
          <ScreenshotViewer :screenshots="getScreenshotItems(record)" />
        </template>
      </a-table>
    </a-card>

    <a-card :bordered="false" class="section-card">
      <template #title>流量日志</template>
      <TrafficLogTable
        :items="trafficLogs.items || []"
        :total="trafficLogs.total || 0"
        :page="trafficLogs.page || 1"
        :size="trafficLogs.size || 50"
        :loading="loading"
        @change="handleTrafficTableChange"
      />
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
</style>
