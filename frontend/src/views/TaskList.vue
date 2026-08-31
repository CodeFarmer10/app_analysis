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

const TABLE_COLUMNS = [
  { title: '序号', key: 'index', width: 70, fixed: 'left' },
  { title: '图标', key: 'icon', width: 70 },
  { title: 'APP名称/包名', key: 'app', width: 170 },
  { title: '来源', key: 'source', width: 180 },
  { title: '任务描述', key: 'task_description', dataIndex: 'task_description', width: 150 },
  { title: '诈骗类型', key: 'model_type_name', dataIndex: 'model_type_name', width: 110 },
  { title: '状态', key: 'status', dataIndex: 'status', width: 140 },
  { title: '提交时间', key: 'created_at', dataIndex: 'created_at', width: 160 },
  { title: '分配设备', key: 'device_id', dataIndex: 'device_id', width: 180 },
  { title: '操作', key: 'actions', fixed: 'right', width: 160 },
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

function getRowClassName() {
  return 'task-row'
}

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
  return record.source_name || '--'
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

function hasAnyDownload(record) {
  return (
    isDownloadEnabled(record, 'apk') ||
    isDownloadEnabled(record, 'report') ||
    isDownloadEnabled(record, 'pcap')
  )
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

      <a-table
        class="task-table"
        row-key="id"
        :columns="TABLE_COLUMNS"
        :data-source="taskStore.tasks"
        :loading="taskStore.loading"
        :pagination="pagination"
        :scroll="{ x: 1580 }"
        :row-class-name="getRowClassName"
        @change="handleTableChange"
      >
        <template #bodyCell="{ column, record, index }">
          <template v-if="column.key === 'index'">
            {{ (taskStore.page - 1) * taskStore.size + index + 1 }}
          </template>
          <template v-else-if="column.key === 'icon'">
            <a-avatar shape="square" class="task-icon" :src="record.icon_url">
              {{ getAppInitial(record.app_name) }}
            </a-avatar>
          </template>

          <template v-else-if="column.key === 'app'">
            <a-tooltip placement="topLeft">
              <template #title>
                <div class="app-tooltip">
                  <div>名称：{{ record.app_name || '分析中' }}</div>
                  <div class="mono-text">包名：{{ record.package_name || '--' }}</div>
                </div>
              </template>
              <div class="app-cell">
                <div class="app-name">{{ record.app_name || '分析中' }}</div>
                <div class="app-package mono-text">{{ record.package_name || '--' }}</div>
              </div>
            </a-tooltip>
          </template>

          <template v-else-if="column.key === 'source'">
            <a-tooltip :title="record.source_name || '--'">
              <div class="source-text mono-text">{{ getSourceText(record) }}</div>
            </a-tooltip>
          </template>

          <template v-else-if="column.key === 'task_description'">
            <a-typography-text class="desc-text" :ellipsis="{ tooltip: record.task_description || '--' }">
              {{ record.task_description || '--' }}
            </a-typography-text>
          </template>

          <template v-else-if="column.key === 'model_type_name'">
            <a-tag v-if="record.model_type_name" color="red">{{ record.model_type_name }}</a-tag>
            <span v-else>--</span>
          </template>

          <template v-else-if="column.key === 'created_at'">
            {{ formatDateTime(record.created_at) }}
          </template>

          <template v-else-if="column.key === 'status'">
            <TaskStatusTag :status="record.status" />
          </template>

          <template v-else-if="column.key === 'device_id'">
            {{ record.device_serial || record.device_id || '--' }}
          </template>

          <template v-else-if="column.key === 'actions'">
            <a-space size="small">
              <a-button type="link" @click="openTaskDetail(record.id)">查看</a-button>
              <a-dropdown placement="bottomRight" :trigger="hasAnyDownload(record) ? ['click'] : []">
                <a-button type="link" :disabled="!hasAnyDownload(record)">下载</a-button>
                <template #overlay>
                  <a-menu @click="({ key }) => handleDownload(record.id, key)">
                    <a-menu-item key="apk" :disabled="!isDownloadEnabled(record, 'apk')">
                      下载APK
                    </a-menu-item>
                    <a-menu-item key="report" :disabled="!isDownloadEnabled(record, 'report')">
                      下载报告
                    </a-menu-item>
                    <a-menu-item key="pcap" :disabled="!isDownloadEnabled(record, 'pcap')">
                      下载PCAP
                    </a-menu-item>
                  </a-menu>
                </template>
              </a-dropdown>
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

.task-icon {
  background: rgba(59, 130, 246, 0.14);
  color: #bfdbfe;
  border: 1px solid rgba(59, 130, 246, 0.42);
  font-weight: 600;
}

.app-cell {
  line-height: 1.5;
  width: 150px;
  display: flex;
  flex-direction: column;
}

.app-name,
.app-package {
  display: inline-block;
  width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.app-name {
  color: var(--text-primary);
}

.app-package {
  color: var(--text-secondary);
  font-size: 12px;
  font-family: var(--font-mono);
}

.app-tooltip {
  max-width: 460px;
  line-height: 1.6;
  white-space: normal;
  word-break: break-all;
}

.source-text {
  width: 170px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #9fb4cb;
}

.desc-text {
  width: 140px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #d7e3ef;
}

.task-list-page :deep(.task-table .ant-table-expanded-row > td) {
  background: rgba(59, 130, 246, 0.02) !important;
}

.task-list-page :deep(.task-table .ant-table-cell-fix-left),
.task-list-page :deep(.task-table .ant-table-cell-fix-right) {
  background: #151c2b !important;
  z-index: 4;
  background-clip: padding-box;
}

.task-list-page :deep(.task-table .ant-table-tbody > tr:hover .ant-table-cell-fix-left),
.task-list-page :deep(.task-table .ant-table-tbody > tr:hover .ant-table-cell-fix-right) {
  background: #1a2740 !important;
}

.task-list-page :deep(.task-table .ant-table-tbody > tr > td.ant-table-cell-row-hover) {
  background: #1a2740 !important;
}

.task-list-page :deep(.task-table .ant-table-tbody > tr.ant-table-row-selected > td) {
  background: #2a4f85 !important;
  color: #eef5ff !important;
}

.task-list-page :deep(.task-table .ant-table-tbody > tr.ant-table-row-selected:hover > td),
.task-list-page :deep(.task-table .ant-table-tbody > tr.ant-table-row-selected > td.ant-table-cell-row-hover) {
  background: #315b97 !important;
}

.task-list-page :deep(.task-table .ant-table-tbody > tr.ant-table-row-selected .ant-table-cell-fix-left),
.task-list-page :deep(.task-table .ant-table-tbody > tr.ant-table-row-selected .ant-table-cell-fix-right) {
  background: #2a4f85 !important;
  color: #eef5ff !important;
}

.task-list-page :deep(.task-table .ant-table-tbody > tr.ant-table-row-selected:hover .ant-table-cell-fix-left),
.task-list-page :deep(.task-table .ant-table-tbody > tr.ant-table-row-selected:hover .ant-table-cell-fix-right),
.task-list-page :deep(.task-table .ant-table-tbody > tr.ant-table-row-selected .ant-table-cell-fix-left.ant-table-cell-row-hover),
.task-list-page :deep(.task-table .ant-table-tbody > tr.ant-table-row-selected .ant-table-cell-fix-right.ant-table-cell-row-hover) {
  background: #315b97 !important;
}

.task-list-page :deep(.task-table .ant-table-tbody > tr > td.ant-table-cell-fix-left),
.task-list-page :deep(.task-table .ant-table-tbody > tr > td.ant-table-cell-fix-right) {
  background: #151c2b !important;
}

.task-list-page :deep(.task-table .ant-table-thead > tr > .ant-table-cell-fix-left),
.task-list-page :deep(.task-table .ant-table-thead > tr > .ant-table-cell-fix-right) {
  background: #1a2232 !important;
}

.task-list-page :deep(.task-table .ant-table-cell-fix-left-last::after),
.task-list-page :deep(.task-table .ant-table-cell-fix-right-first::after) {
  display: none !important;
}

.task-list-page :deep(.task-table .ant-btn-link) {
  color: #9ec5ff;
}

.task-list-page :deep(.task-table .ant-btn-link:hover) {
  color: #c7defd;
}
</style>
