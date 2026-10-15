<script setup>
import { computed } from 'vue'

import TaskStatusTag from './TaskStatusTag.vue'
import { formatDateTime } from '../utils/format'

const props = defineProps({
  tasks: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  pagination: { type: [Object, Boolean], default: false },
  showMd5: { type: Boolean, default: false },
  compact: { type: Boolean, default: false },
  showActions: { type: Boolean, default: true },
})

const emit = defineEmits(['change', 'view', 'download'])

const columns = computed(() => [
  { title: '序号', key: 'index', width: 70, fixed: 'left' },
  { title: '图标', key: 'icon', width: 70 },
  { title: 'APP名称/包名', key: 'app', width: 170 },
  ...(props.showMd5 ? [{ title: '文件MD5', key: 'file_md5', width: 280 }] : []),
  ...(!props.compact ? [
    { title: '来源', key: 'source', width: 180 },
    { title: '任务描述', key: 'task_description', width: 150 },
  ] : []),
  { title: '诈骗类型', key: 'model_type_name', width: 110 },
  { title: '状态', key: 'status', width: 140 },
  { title: '提交时间', key: 'created_at', width: 160 },
  ...(!props.compact ? [{ title: '分配设备', key: 'device_id', width: 180 }] : []),
  ...(props.showActions ? [{ title: '操作', key: 'actions', fixed: 'right', width: 160 }] : []),
])

const downloadFlagMap = {
  apk: 'can_download_apk',
  report: 'can_download_report',
  pcap: 'can_download_pcap',
}

function isDownloadEnabled(record, type) {
  return !record?.previewOnly && record?.[downloadFlagMap[type]] === true
}

function hasAnyDownload(record) {
  return Object.keys(downloadFlagMap).some((type) => isDownloadEnabled(record, type))
}

function getAppInitial(appName) {
  return appName ? appName.slice(0, 1).toUpperCase() : 'APP'
}

function rowIndex(index) {
  if (!props.pagination || typeof props.pagination !== 'object') return index + 1
  return ((props.pagination.current || 1) - 1) * (props.pagination.pageSize || 20) + index + 1
}
</script>

<template>
  <a-table
    class="task-table"
    row-key="id"
    :columns="columns"
    :data-source="tasks"
    :loading="loading"
    :pagination="pagination"
    :scroll="{ x: compact ? 960 : showMd5 ? 1860 : 1580 }"
    :row-class-name="() => 'task-row'"
    @change="(pager) => emit('change', pager)"
  >
    <template #bodyCell="{ column, record, index }">
      <template v-if="column.key === 'index'">{{ rowIndex(index) }}</template>
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
      <template v-else-if="column.key === 'file_md5'">
        <span class="mono-text">{{ record.file_md5 || '--' }}</span>
      </template>
      <template v-else-if="column.key === 'source'">
        <a-tooltip :title="record.source_name || '--'">
          <div class="source-text mono-text">{{ record.source_name || '--' }}</div>
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
      <template v-else-if="column.key === 'created_at'">{{ formatDateTime(record.created_at) }}</template>
      <template v-else-if="column.key === 'status'"><TaskStatusTag :status="record.status" /></template>
      <template v-else-if="column.key === 'device_id'">
        {{ record.device_serial || record.device_id || '--' }}
      </template>
      <template v-else-if="column.key === 'actions'">
        <a-space size="small">
          <a-button type="link" :disabled="record.previewOnly || !record.id" @click="emit('view', record.id)">查看</a-button>
          <a-dropdown placement="bottomRight" :trigger="hasAnyDownload(record) ? ['click'] : []">
            <a-button type="link" :disabled="!hasAnyDownload(record)">下载</a-button>
            <template #overlay>
              <a-menu @click="({ key }) => emit('download', record.id, key)">
                <a-menu-item key="apk" :disabled="!isDownloadEnabled(record, 'apk')">下载APK</a-menu-item>
                <a-menu-item key="report" :disabled="!isDownloadEnabled(record, 'report')">下载报告</a-menu-item>
                <a-menu-item key="pcap" :disabled="!isDownloadEnabled(record, 'pcap')">下载PCAP</a-menu-item>
              </a-menu>
            </template>
          </a-dropdown>
        </a-space>
      </template>
    </template>
  </a-table>
</template>

<style scoped>
.task-icon { background: rgba(59, 130, 246, 0.14); color: #bfdbfe; border: 1px solid rgba(59, 130, 246, 0.42); font-weight: 600; }
.app-cell { line-height: 1.5; width: 150px; display: flex; flex-direction: column; }
.app-name, .app-package { display: inline-block; width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.app-name { color: var(--text-primary); }
.app-package { color: var(--text-secondary); font-size: 12px; font-family: var(--font-mono); }
.app-tooltip { max-width: 460px; line-height: 1.6; white-space: normal; word-break: break-all; }
.source-text { width: 170px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #9fb4cb; }
.desc-text { width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #d7e3ef; }
:deep(.ant-table-expanded-row > td) { background: rgba(59, 130, 246, 0.02) !important; }
:deep(.ant-table-cell-fix-left), :deep(.ant-table-cell-fix-right),
:deep(.ant-table-tbody > tr > td.ant-table-cell-fix-left), :deep(.ant-table-tbody > tr > td.ant-table-cell-fix-right) { background: #151c2b !important; z-index: 4; background-clip: padding-box; }
:deep(.ant-table-tbody > tr:hover .ant-table-cell-fix-left), :deep(.ant-table-tbody > tr:hover .ant-table-cell-fix-right),
:deep(.ant-table-tbody > tr > td.ant-table-cell-row-hover) { background: #1a2740 !important; }
:deep(.ant-table-tbody > tr.ant-table-row-selected > td),
:deep(.ant-table-tbody > tr.ant-table-row-selected .ant-table-cell-fix-left), :deep(.ant-table-tbody > tr.ant-table-row-selected .ant-table-cell-fix-right) { background: #2a4f85 !important; color: #eef5ff !important; }
:deep(.ant-table-tbody > tr.ant-table-row-selected:hover > td), :deep(.ant-table-tbody > tr.ant-table-row-selected > td.ant-table-cell-row-hover),
:deep(.ant-table-tbody > tr.ant-table-row-selected:hover .ant-table-cell-fix-left), :deep(.ant-table-tbody > tr.ant-table-row-selected:hover .ant-table-cell-fix-right),
:deep(.ant-table-tbody > tr.ant-table-row-selected .ant-table-cell-fix-left.ant-table-cell-row-hover), :deep(.ant-table-tbody > tr.ant-table-row-selected .ant-table-cell-fix-right.ant-table-cell-row-hover) { background: #315b97 !important; }
:deep(.ant-table-thead > tr > .ant-table-cell-fix-left), :deep(.ant-table-thead > tr > .ant-table-cell-fix-right) { background: #1a2232 !important; }
:deep(.ant-table-cell-fix-left-last::after), :deep(.ant-table-cell-fix-right-first::after) { display: none !important; }
:deep(.ant-btn-link) { color: #9ec5ff; }
:deep(.ant-btn-link:hover) { color: #c7defd; }
</style>
