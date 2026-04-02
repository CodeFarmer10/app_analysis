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
        <div class="header-row">
          <span>任务详情</span>
          <a-button @click="goBack">返回任务列表</a-button>
        </div>
      </template>

      <a-spin :spinning="taskLoading">
        <a-descriptions v-if="task" :column="3" size="small" class="task-base-desc">
          <a-descriptions-item label="任务ID">
            <span class="desc-value">{{ task.id }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="批次号">
            <span class="desc-value">{{ task.batch_id || '--' }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="任务描述">
            <span class="desc-value">{{ task.task_description || '--' }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="来源" class="source-item">
            <a-tooltip :title="task.source_name || '--'">
              <span class="desc-value source-link-text">{{ task.source_name || '--' }}</span>
            </a-tooltip>
          </a-descriptions-item>
          <a-descriptions-item label="状态">
            <TaskStatusTag :status="task.status" />
          </a-descriptions-item>
          <a-descriptions-item label="文件MD5">
            <span class="desc-value">{{ task.file_md5 || '--' }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="文件大小">
            <span class="desc-value">{{ formatFileSize(task.file_size) }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="分配设备">
            <span class="desc-value">{{ task.device_id || '--' }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="提交时间">
            <span class="desc-value">{{ formatDateTime(task.created_at) }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="更新时间">
            <span class="desc-value">{{ formatDateTime(task.updated_at) }}</span>
          </a-descriptions-item>
        </a-descriptions>

        <a-alert v-if="task?.error_message" type="error" show-icon :message="task.error_message" />

        <a-alert
          v-if="shouldShowProgressAlert"
          type="info"
          show-icon
          :message="progressTextMap[currentStatus] || '任务处理中，请稍候。'"
          style="margin-top: 12px"
        />

        <div class="download-row">
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

.download-row {
  margin-top: 12px;
}

.source-link-text {
  display: inline-block;
  max-width: 240px;
  vertical-align: middle;
}

.task-detail-page :deep(.source-item .ant-descriptions-item-content) {
  white-space: nowrap;
}

.task-base-desc :deep(.ant-descriptions-view table) {
  table-layout: fixed;
}

.task-base-desc :deep(.ant-descriptions-item-label) {
  white-space: nowrap;
  padding-right: 1ch;
  padding-bottom: 14px;
}

.task-base-desc :deep(.ant-descriptions-item-label::after) {
  margin-inline: 0;
}

.task-base-desc :deep(.ant-descriptions-item-content) {
  padding-right: 24px;
  padding-bottom: 14px;
}

.desc-value {
  display: inline-block;
  width: 100%;
  vertical-align: middle;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
</style>
