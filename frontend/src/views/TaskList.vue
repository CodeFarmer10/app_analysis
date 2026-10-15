<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'

import TaskRecordsTable from '../components/TaskRecordsTable.vue'
import TaskUploadModal from '../components/TaskUploadModal.vue'
import { getTaskApkDownload, getTaskPcapDownload, getTaskReportDownload } from '../api/tasks'
import { useTaskStore } from '../stores/task'
import { TASK_TERMINAL_STATUSES, usePolling } from '../utils/polling'

const router = useRouter()
const taskStore = useTaskStore()

const showUploadModal = ref(false)
const pollingActive = ref(false)

const searchForm = reactive({
  md5: '',
  name: '',
  task_description: '',
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

const TERMINAL_SET = new Set(TASK_TERMINAL_STATUSES)
const DOWNLOAD_FLAG_MAP = {
  apk: 'can_download_apk',
  report: 'can_download_report',
  pcap: 'can_download_pcap',
}

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
    task_description: searchForm.task_description.trim(),
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
  searchForm.task_description = ''
  searchForm.package = ''
  searchForm.status = ''
  searchForm.timeRange = []

  taskStore.setFilters({
    md5: '',
    name: '',
    task_description: '',
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
  const task = taskStore.tasks.find((item) => item.id === taskId)
  if (!isDownloadEnabled(task, type)) {
    return
  }

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

function isDownloadEnabled(record, type) {
  if (!record || !DOWNLOAD_FLAG_MAP[type]) {
    return false
  }

  const flag = record[DOWNLOAD_FLAG_MAP[type]]
  return typeof flag === 'boolean' ? flag : false
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
      <a-form layout="inline" class="search-form">
        <div class="search-row-top">
          <a-form-item label="MD5" class="search-item">
            <a-input v-model:value="searchForm.md5" placeholder="输入 MD5" allow-clear />
          </a-form-item>
          <a-form-item label="名称" class="search-item">
            <a-input v-model:value="searchForm.name" placeholder="输入 APP 名称" allow-clear />
          </a-form-item>
          <a-form-item label="任务描述" class="search-item">
            <a-input
              v-model:value="searchForm.task_description"
              placeholder="输入任务描述"
              allow-clear
            />
          </a-form-item>
          <a-form-item label="包名" class="search-item">
            <a-input v-model:value="searchForm.package" placeholder="输入包名" allow-clear />
          </a-form-item>
        </div>
        <div class="search-row-bottom">
          <a-form-item label="时间范围" class="search-item range-item">
            <a-range-picker v-model:value="searchForm.timeRange" style="width: 100%" />
          </a-form-item>
          <a-form-item label="状态" class="search-item status-item">
            <a-select
              v-model:value="searchForm.status"
              :options="STATUS_OPTIONS"
              allow-clear
              placeholder="选择状态"
            />
          </a-form-item>
          <div class="search-form-right">
            <a-space>
              <a-button type="primary" @click="handleSearch">查询</a-button>
              <a-button @click="handleReset">重置</a-button>
            </a-space>
          </div>
        </div>
      </a-form>
    </a-card>

    <a-card :bordered="false">
      <template #title>
        <div class="table-header">
          <span>任务列表</span>
          <a-space>
            <a-button @click="fetchList">刷新</a-button>
            <a-button type="primary" @click="showUploadModal = true">新建任务</a-button>
          </a-space>
        </div>
      </template>

      <TaskRecordsTable
        :tasks="taskStore.tasks"
        :loading="taskStore.loading"
        :pagination="pagination"
        @change="handleTableChange"
        @view="openTaskDetail"
        @download="handleDownload"
      />
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

.search-card {
  background: var(--bg-card-deep);
}

.search-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.search-row-top {
  display: grid;
  grid-template-columns:
    minmax(176px, 1fr)
    minmax(204px, 1.15fr)
    minmax(240px, 1.3fr)
    minmax(200px, 1.1fr);
  gap: 16px;
}

.search-row-bottom {
  display: flex;
  align-items: center;
  gap: 16px;
  min-width: 0;
}

.search-form-right {
  margin-left: auto;
  display: flex;
  align-items: center;
  justify-content: flex-end;
}

.search-item {
  margin-bottom: 0;
  width: 100%;
}

.range-item {
  width: 360px;
}

.status-item {
  width: 210px;
}

.search-form :deep(.ant-form-item-row) {
  display: flex;
  align-items: center;
  flex-wrap: nowrap;
}

.search-form :deep(.ant-form-item-label) {
  padding: 0;
  line-height: 36px;
  flex: 0 0 auto;
}

.search-form :deep(.ant-form-item-control) {
  flex: 1 1 auto;
}

.search-form :deep(.ant-form-item-control-input) {
  min-height: 36px;
}

.search-form :deep(.ant-input),
.search-form :deep(.ant-select-selector),
.search-form :deep(.ant-picker) {
  height: 36px;
}

@media (max-width: 1200px) {
  .search-row-top {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }

  .range-item {
    width: 320px;
  }

  .status-item {
    width: 180px;
  }
}

@media (max-width: 900px) {
  .search-row-top {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
    width: 100%;
  }

  .search-row-bottom {
    gap: 12px;
    width: 100%;
  }

  .search-form-right {
    margin-left: 0;
  }
}

@media (max-width: 640px) {
  .search-row-top {
    display: flex;
    width: 100%;
    flex-direction: column;
    align-items: stretch;
    gap: 12px;
  }

  .search-row-bottom {
    flex-direction: column;
    align-items: stretch;
  }

  .search-item,
  .range-item {
    width: 100%;
  }
}

.table-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  color: var(--text-primary);
  font-family: var(--font-title);
  font-size: 16px;
}

</style>
