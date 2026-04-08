<script setup>
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import DynamicResult from '../components/DynamicResult.vue'
import StaticResult from '../components/StaticResult.vue'
import TaskStatusTag from '../components/TaskStatusTag.vue'
import {
  getTaskApkDownload,
  getTaskDetail,
  getTaskDynamicResult,
  getTaskPcapDownload,
  getTaskReportDownload,
  getTaskStaticResult,
  getTaskStatus,
} from '../api/tasks'
import { formatDateTime, formatFileSize } from '../utils/format'
import { TASK_TERMINAL_STATUSES, usePolling } from '../utils/polling'

const route = useRoute()
const router = useRouter()

const taskLoading = ref(false)
const staticLoading = ref(false)
const dynamicLoading = ref(false)
const activeTab = ref('static')
const downloadingType = ref('')
const pollingActive = ref(false)

const task = ref(null)
const staticResult = ref(null)
const dynamicResults = ref({
  items: [],
  total: 0,
  page: 1,
  size: 20,
})
const stepTrafficLogs = ref({})

const terminalStatusSet = new Set(TASK_TERMINAL_STATUSES)
const staticReadyStatusSet = new Set(['waiting_device', 'dynamic_tracing', 'dynamic_failed', 'completed'])
const dynamicReadyStatusSet = new Set(['dynamic_tracing', 'dynamic_failed', 'completed'])

const currentTaskId = computed(() => String(route.params.taskId || ''))
const currentStatus = computed(() => task.value?.status || '')
const isTerminalStatus = computed(() => terminalStatusSet.has(currentStatus.value))
const shouldShowProgressAlert = computed(() => Boolean(task.value && !isTerminalStatus.value))
const taskIconUrl = computed(() => staticResult.value?.icon_url || task.value?.icon_url || '')
const taskName = computed(() => staticResult.value?.app_name || task.value?.app_name || '分析任务')
const taskPackage = computed(() => staticResult.value?.package_name || task.value?.package_name || '--')

const overviewItems = computed(() => {
  if (!task.value) {
    return []
  }

  return [
    { label: '任务ID', value: task.value.id || '--', mono: true },
    { label: '文件MD5', value: task.value.file_md5 || '--', mono: true },
    { label: '分配设备', value: task.value.device_serial || '--', mono: true },
    { label: '文件大小', value: formatFileSize(task.value.file_size), mono: false },
    { label: '提交时间', value: formatDateTime(task.value.created_at), mono: true },
    { label: '更新时间', value: formatDateTime(task.value.updated_at), mono: true },
  ]
})

const progressTextMap = {
  downloading: '任务正在下载 APK，请稍候。',
  static_analyzing: '任务正在进行静态分析，请稍候。',
  waiting_device: '静态分析完成，当前等待设备分配。',
  dynamic_tracing: '任务正在执行动态溯源，请稍候。',
}

const downloadButtons = computed(() => [
  {
    key: 'apk',
    text: '下载APK',
    visible: Boolean(task.value?.apk_path),
    api: getTaskApkDownload,
  },
  {
    key: 'report',
    text: '下载报告',
    visible: Boolean(task.value?.report_path),
    api: getTaskReportDownload,
  },
  {
    key: 'pcap',
    text: '下载PCAP',
    visible: Boolean(task.value?.pcap_path),
    api: getTaskPcapDownload,
  },
])

const { start: startPolling, stop: stopPolling } = usePolling(async () => {
  await refreshTaskStatusByPolling()
}, 30000)

function goBack() {
  void router.push('/tasks')
}

function resetResultState() {
  staticResult.value = null
  dynamicResults.value = { items: [], total: 0, page: 1, size: 20 }
  stepTrafficLogs.value = {}
}

function syncPollingState() {
  if (!task.value || isTerminalStatus.value) {
    if (pollingActive.value) {
      pollingActive.value = false
      stopPolling()
    }
    return
  }

  if (!pollingActive.value) {
    pollingActive.value = true
    void startPolling(false)
  }
}

async function fetchTaskBase() {
  const taskId = currentTaskId.value
  if (!taskId) {
    return
  }

  const data = await getTaskDetail(taskId)
  task.value = data?.task || null
}

async function fetchStaticResult() {
  if (!task.value || !staticReadyStatusSet.has(task.value.status)) {
    staticResult.value = null
    return
  }

  staticLoading.value = true
  try {
    const data = await getTaskStaticResult(currentTaskId.value)
    staticResult.value = data?.static_result || null
  } finally {
    staticLoading.value = false
  }
}

async function fetchDynamicResult(options = {}) {
  if (!task.value || !dynamicReadyStatusSet.has(task.value.status)) {
    dynamicResults.value = { items: [], total: 0, page: 1, size: 20 }
    stepTrafficLogs.value = {}
    return
  }

  const {
    dynamicPage = dynamicResults.value.page,
    dynamicSize = dynamicResults.value.size,
  } = options

  dynamicLoading.value = true
  try {
    const data = await getTaskDynamicResult(currentTaskId.value, {
      dynamic_page: dynamicPage,
      dynamic_size: dynamicSize,
    })
    dynamicResults.value = data?.dynamic_results || {
      items: [],
      total: 0,
      page: dynamicPage,
      size: dynamicSize,
    }
    stepTrafficLogs.value = data?.step_traffic_logs || {}
  } finally {
    dynamicLoading.value = false
  }
}

async function loadTaskDetail(taskId) {
  if (!taskId) {
    return
  }

  stopPolling()
  pollingActive.value = false
  resetResultState()
  activeTab.value = 'static'

  taskLoading.value = true
  try {
    await fetchTaskBase()
    await fetchStaticResult()
    if (activeTab.value === 'dynamic') {
      await fetchDynamicResult()
    }
  } finally {
    taskLoading.value = false
    syncPollingState()
  }
}

async function refreshTaskStatusByPolling() {
  if (!task.value) {
    return
  }

  const oldStatus = task.value.status
  const statusData = await getTaskStatus(task.value.id)
  task.value = { ...task.value, ...statusData }
  const statusChanged = oldStatus !== task.value.status

  if (statusChanged) {
    await fetchTaskBase()
    await fetchStaticResult()
  }

  if (activeTab.value === 'dynamic') {
    await fetchDynamicResult()
  }

  syncPollingState()
}

async function handleDownload(button) {
  if (!task.value?.id || !button?.api) {
    return
  }

  downloadingType.value = button.key
  try {
    const data = await button.api(task.value.id)
    if (data?.download_url) {
      window.open(data.download_url, '_blank', 'noopener')
    }
  } finally {
    downloadingType.value = ''
  }
}

async function handleTabChange(tabKey) {
  activeTab.value = tabKey
  if (tabKey === 'dynamic' && dynamicResults.value.items.length === 0) {
    await fetchDynamicResult()
  }
}

async function handleDynamicPageChange(payload) {
  await fetchDynamicResult({
    dynamicPage: payload.page,
    dynamicSize: payload.size,
  })
}

watch(
  () => currentTaskId.value,
  async (taskId) => {
    await loadTaskDetail(taskId)
  },
  { immediate: true }
)

onBeforeUnmount(() => {
  pollingActive.value = false
  stopPolling()
})
</script>

<template>
  <div class="task-detail-page">
    <a-card :bordered="false" class="section-card">
      <template #title>
        <div class="header-row page-header">
          <span>任务详情</span>
          <a-button @click="goBack">返回任务列表</a-button>
        </div>
      </template>

      <a-spin :spinning="taskLoading">
        <div v-if="task" class="task-overview">
          <div class="app-info">
            <div class="app-icon-box">
              <a-image v-if="taskIconUrl" :src="taskIconUrl" :width="80" :preview="false" />
              <a-avatar v-else shape="square" :size="80" class="fallback-icon">
                {{ taskName.slice(0, 1) }}
              </a-avatar>
            </div>
            <div class="app-main">
              <div class="app-title-row">
                <h2 class="app-name title-text">{{ taskName }}</h2>
                <TaskStatusTag :status="task.status" />
              </div>
              <div class="app-package mono-text">{{ taskPackage }}</div>
              <div class="task-remark">
                <span class="label">任务描述：</span>
                <span>{{ task.task_description || '--' }}</span>
              </div>
            </div>
          </div>
          <div class="download-group">
            <a-space wrap>
              <a-button
                v-for="button in downloadButtons.filter((item) => item.visible)"
                :key="button.key"
                :loading="downloadingType === button.key"
                @click="handleDownload(button)"
              >
                {{ button.text }}
              </a-button>
            </a-space>
          </div>
          <div class="meta-grid">
            <div v-for="item in overviewItems" :key="item.label" class="meta-item">
              <div class="meta-label">{{ item.label }}</div>
              <div class="meta-value" :class="{ 'mono-text': item.mono }">{{ item.value }}</div>
            </div>
          </div>
        </div>

        <a-alert v-if="task?.error_message" type="error" show-icon :message="task.error_message" />

        <a-alert
          v-if="shouldShowProgressAlert"
          type="info"
          show-icon
          :message="progressTextMap[currentStatus] || '任务处理中，请稍候。'"
          style="margin-top: 12px"
        />
      </a-spin>
    </a-card>

    <a-card :bordered="false" class="section-card">
      <a-tabs :active-key="activeTab" @change="handleTabChange">
        <a-tab-pane key="static" tab="静态分析">
          <StaticResult :task="task || {}" :result="staticResult" :loading="staticLoading" />
        </a-tab-pane>
        <a-tab-pane key="dynamic" tab="动态溯源">
          <DynamicResult
            :dynamic-results="dynamicResults"
            :step-traffic-logs="stepTrafficLogs"
            :loading="dynamicLoading"
            @change-dynamic-page="handleDynamicPageChange"
          />
        </a-tab-pane>
      </a-tabs>
    </a-card>
  </div>
</template>

<style scoped>
.task-detail-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.section-card {
  border-radius: 8px;
}

.header-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.page-header {
  font-family: var(--font-title);
  font-size: 16px;
}

.task-overview {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.app-info {
  display: flex;
  gap: 16px;
  align-items: center;
}

.app-icon-box {
  width: 80px;
  height: 80px;
  border-radius: 12px;
  overflow: hidden;
  border: 1px solid var(--border-normal);
  background: rgba(59, 130, 246, 0.12);
}

.fallback-icon {
  background: rgba(59, 130, 246, 0.22);
  color: #dbeafe;
}

.app-main {
  min-width: 0;
  flex: 1;
}

.app-title-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 4px;
}

.app-name {
  margin: 0;
  font-size: 20px;
  color: var(--text-primary);
}

.app-package {
  color: #9fb4cb;
  font-size: 13px;
  margin-bottom: 6px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.task-remark {
  color: var(--text-secondary);
  font-size: 13px;
}

.task-remark .label {
  color: #7e95af;
}

.download-group {
  display: flex;
  justify-content: flex-end;
}

.meta-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px 12px;
}

.meta-item {
  border: 1px solid var(--border-subtle);
  background: rgba(255, 255, 255, 0.02);
  border-radius: 8px;
  padding: 10px 12px;
}

.meta-label {
  color: #7e95af;
  font-size: 12px;
  margin-bottom: 6px;
}

.meta-value {
  color: #e4edf8;
  font-size: 13px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.task-detail-page :deep(.ant-tabs-tabpane) {
  padding-top: 4px;
}

.task-detail-page :deep(.ant-tabs-tab) {
  font-size: 14px;
}

@media (max-width: 768px) {
  .header-row {
    gap: 10px;
    flex-wrap: wrap;
  }

  .app-info {
    align-items: flex-start;
  }

  .download-group {
    justify-content: flex-start;
  }

  .meta-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 560px) {
  .meta-grid {
    grid-template-columns: 1fr;
  }
}
</style>
