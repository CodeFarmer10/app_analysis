<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'

import TaskStatusTag from '../components/TaskStatusTag.vue'
import TaskUploadModal from '../components/TaskUploadModal.vue'
import { getTaskApkDownload, getTaskPcapDownload, getTaskReportDownload } from '../api/tasks'
import { useTaskStore } from '../stores/task'
import { formatDateTime } from '../utils/format'
import { TASK_TERMINAL_STATUSES, usePolling } from '../utils/polling'

const router = useRouter()
const taskStore = useTaskStore()

const showUploadModal = ref(false)
const pollingActive = ref(false)

const searchForm = reactive({
  md5: '',
  name: '',
  package: '',
  status: '',
  timeRange: [],
})

const STATUS_OPTIONS = [
  { label: '下载中', value: 'downloading' },
  { label: '下载失败', value: 'download_failed' },
  { label: '静态分析中', value: 'static_analyzing' },
  { label: '静态分析失败', value: 'static_failed' },
  { label: '等待设备', value: 'waiting_device' },
  { label: '动态溯源中', value: 'dynamic_tracing' },
  { label: '动态溯源失败', value: 'dynamic_failed' },
  { label: '已完成', value: 'completed' },
]

const TABLE_COLUMNS = [
  { title: '图标', key: 'icon', width: 70 },
  { title: 'APP名称/包名', key: 'app', width: 220 },
  { title: '来源', key: 'source', width: 260 },
  { title: '文件MD5', key: 'file_md5', dataIndex: 'file_md5', width: 240 },
  { title: '提交时间', key: 'created_at', dataIndex: 'created_at', width: 180 },
  { title: '状态', key: 'status', dataIndex: 'status', width: 140 },
  { title: '分配设备', key: 'device_id', dataIndex: 'device_id', width: 180 },
  { title: '操作', key: 'actions', fixed: 'right', width: 280 },
]

const TERMINAL_SET = new Set(TASK_TERMINAL_STATUSES)

const hasRunningTasks = computed(() =>
  taskStore.tasks.some((task) => !TERMINAL_SET.has(task.status))
)

const pagination = computed(() => ({
  current: taskStore.page,
  pageSize: taskStore.size,
  total: taskStore.total,
  showSizeChanger: true,
  showTotal: (total) => `共 ${total} 条`,
}))

const { start: startPolling, stop: stopPolling } = usePolling(async () => {
  await taskStore.fetchTasks()
  syncPollingState()
}, 30000)

function getAppInitial(appName) {
  if (!appName) {
    return 'APP'
  }
  return appName.slice(0, 1).toUpperCase()
}

function getSourceText(record) {
  if (record.source_type === 'apk_upload') {
    return `APK：${record.source_name}`
  }
  return `URL：${record.source_name}`
}

function buildFilterPayload() {
  let start = ''
  let end = ''

  if (Array.isArray(searchForm.timeRange) && searchForm.timeRange.length === 2) {
    start = searchForm.timeRange[0].startOf('day').toISOString()
    end = searchForm.timeRange[1].endOf('day').toISOString()
  }

  return {
    md5: searchForm.md5.trim(),
    name: searchForm.name.trim(),
    package: searchForm.package.trim(),
    status: searchForm.status,
    start,
    end,
  }
}

function syncPollingState() {
  if (hasRunningTasks.value && !pollingActive.value) {
    pollingActive.value = true
    void startPolling(false)
    return
  }

  if (!hasRunningTasks.value && pollingActive.value) {
    pollingActive.value = false
    stopPolling()
  }
}

async function fetchList() {
  await taskStore.fetchTasks()
  syncPollingState()
}

async function handleSearch() {
  taskStore.setFilters(buildFilterPayload())
  taskStore.setPage(1, taskStore.size)
  await fetchList()
}

async function handleReset() {
  searchForm.md5 = ''
  searchForm.name = ''
  searchForm.package = ''
  searchForm.status = ''
  searchForm.timeRange = []

  taskStore.setFilters({
    md5: '',
    name: '',
    package: '',
    status: '',
    start: '',
    end: '',
  })
  taskStore.setPage(1, taskStore.size)
  await fetchList()
}

async function handleTableChange(pager) {
  taskStore.setPage(pager.current || 1, pager.pageSize || taskStore.size)
  await fetchList()
}

async function handleModalSuccess() {
  await fetchList()
}

function openTaskDetail(taskId) {
  void router.push(`/tasks/${taskId}`)
}

async function handleDownload(taskId, type) {
  const fetcher = {
    apk: getTaskApkDownload,
    report: getTaskReportDownload,
    pcap: getTaskPcapDownload,
  }[type]

  if (!fetcher) {
    return
  }

  const data = await fetcher(taskId)
  if (data?.download_url) {
    window.open(data.download_url, '_blank', 'noopener')
  }
}

onMounted(async () => {
  await fetchList()
})

onBeforeUnmount(() => {
  pollingActive.value = false
  stopPolling()
})
</script>

<template>
  <div class="task-list-page">
    <a-card class="search-card" :bordered="false">
      <a-form layout="inline">
        <a-form-item label="MD5">
          <a-input v-model:value="searchForm.md5" placeholder="输入 MD5" allow-clear />
        </a-form-item>
        <a-form-item label="名称">
          <a-input v-model:value="searchForm.name" placeholder="输入 APP 名称" allow-clear />
        </a-form-item>
        <a-form-item label="包名">
          <a-input v-model:value="searchForm.package" placeholder="输入包名" allow-clear />
        </a-form-item>
        <a-form-item label="状态">
          <a-select
            v-model:value="searchForm.status"
            :options="STATUS_OPTIONS"
            allow-clear
            placeholder="选择状态"
            style="width: 170px"
          />
        </a-form-item>
        <a-form-item label="时间范围">
          <a-range-picker v-model:value="searchForm.timeRange" />
        </a-form-item>
        <a-form-item>
          <a-space>
            <a-button type="primary" @click="handleSearch">查询</a-button>
            <a-button @click="handleReset">重置</a-button>
          </a-space>
        </a-form-item>
      </a-form>
    </a-card>

    <a-card :bordered="false">
      <template #title>
        <div class="table-header">
          <span>任务列表</span>
          <a-space>
            <a-button @click="fetchList">刷新</a-button>
            <a-button type="primary" @click="showUploadModal = true">上传/提交分析</a-button>
          </a-space>
        </div>
      </template>

      <a-table
        row-key="id"
        :columns="TABLE_COLUMNS"
        :data-source="taskStore.tasks"
        :loading="taskStore.loading"
        :pagination="pagination"
        :scroll="{ x: 1450 }"
        @change="handleTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'icon'">
            <a-avatar shape="square" class="task-icon">{{ getAppInitial(record.app_name) }}</a-avatar>
          </template>

          <template v-else-if="column.key === 'app'">
            <div class="app-cell">
              <div class="app-name">{{ record.app_name || '分析中' }}</div>
              <div class="app-package">{{ record.package_name || '--' }}</div>
            </div>
          </template>

          <template v-else-if="column.key === 'source'">
            <a-typography-text :ellipsis="{ tooltip: record.source_name }">
              {{ getSourceText(record) }}
            </a-typography-text>
          </template>

          <template v-else-if="column.key === 'created_at'">
            {{ formatDateTime(record.created_at) }}
          </template>

          <template v-else-if="column.key === 'status'">
            <TaskStatusTag :status="record.status" />
          </template>

          <template v-else-if="column.key === 'device_id'">
            {{ record.device_id || '--' }}
          </template>

          <template v-else-if="column.key === 'actions'">
            <a-space>
              <a-button type="link" @click="openTaskDetail(record.id)">查看</a-button>
              <template v-if="record.status === 'completed'">
                <a-button type="link" @click="handleDownload(record.id, 'apk')">下载APK</a-button>
                <a-button type="link" @click="handleDownload(record.id, 'report')">
                  下载报告
                </a-button>
                <a-button type="link" @click="handleDownload(record.id, 'pcap')">下载PCAP</a-button>
              </template>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <TaskUploadModal v-model:open="showUploadModal" @success="handleModalSuccess" />
  </div>
</template>

<style scoped>
.task-list-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.search-card :deep(.ant-form-item) {
  margin-bottom: 12px;
}

.table-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.task-icon {
  background: #e8f0ff;
  color: #2f54eb;
  font-weight: 600;
}

.app-cell {
  line-height: 1.5;
}

.app-name {
  color: #1f2d3d;
}

.app-package {
  color: #7a869a;
  font-size: 12px;
}
</style>
