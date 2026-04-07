<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'

import { createDevice, deleteDevice, getDeviceList, updateDevice } from '../api/devices'
import { useDeviceStore } from '../stores/device'
import { formatDateTime } from '../utils/format'
import { usePolling } from '../utils/polling'

const deviceStore = useDeviceStore()

const addModalOpen = ref(false)
const editModalOpen = ref(false)
const submitting = ref(false)
const deletingId = ref('')
const editingDevice = ref(null)
const pollingActive = ref(false)
const validatingConnection = ref(false)
const connectionCheckState = ref('')
const connectionCheckMessage = ref('')

const addForm = reactive({
  serial: '',
  name: '',
})

const editForm = reactive({
  name: '',
})

const deviceList = computed(() => deviceStore.items)

const statusMetaMap = {
  online: { status: 'success', text: '在线' },
  offline: { status: 'error', text: '离线' },
  busy: { status: 'processing', text: '分析中' },
}

const { start: startPolling, stop: stopPolling } = usePolling(async () => {
  await fetchDevices()
}, 5 * 60 * 1000)

function getStatusMeta(status) {
  return statusMetaMap[status] || { status: 'default', text: status || '未知' }
}

function formatCellText(value) {
  if (value === null || value === undefined || value === '') {
    return '--'
  }
  return value
}

function getDeviceTitle(record) {
  return record?.name || record?.model || '未命名设备'
}

function isOffline(record) {
  return record?.status === 'offline'
}

async function handleValidateConnection() {
  const serial = addForm.serial.trim()
  if (!serial) {
    message.warning('请先输入连接地址或序列号')
    return
  }

  validatingConnection.value = true
  connectionCheckState.value = ''
  connectionCheckMessage.value = ''
  try {
    await new Promise((resolve) => setTimeout(resolve, 900))
    const validPattern = /^[a-zA-Z0-9._:-]{4,}$/
    if (!validPattern.test(serial)) {
      connectionCheckState.value = 'error'
      connectionCheckMessage.value = '连接地址格式异常，请检查后重试'
      return
    }
    connectionCheckState.value = 'success'
    connectionCheckMessage.value = '格式校验通过，可提交保存'
  } finally {
    validatingConnection.value = false
  }
}

function resetAddForm() {
  addForm.serial = ''
  addForm.name = ''
  validatingConnection.value = false
  connectionCheckState.value = ''
  connectionCheckMessage.value = ''
}

function resetEditForm() {
  editForm.name = ''
  editingDevice.value = null
}

async function fetchDevices() {
  deviceStore.loading = true
  try {
    const data = await getDeviceList()
    deviceStore.setItems(data?.items || [])
  } finally {
    deviceStore.loading = false
  }
}

function openAddModal() {
  addModalOpen.value = true
}

function closeAddModal() {
  addModalOpen.value = false
  resetAddForm()
}

async function handleCreateDevice() {
  if (!addForm.serial.trim()) {
    message.warning('请输入设备连接地址或序列号')
    return
  }

  submitting.value = true
  try {
    await createDevice({
      serial: addForm.serial.trim(),
      name: addForm.name.trim() || undefined,
    })
    message.success('设备添加成功')
    closeAddModal()
    await fetchDevices()
  } finally {
    submitting.value = false
  }
}

function openEditModal(record) {
  editingDevice.value = record
  editForm.name = record?.name || ''
  editModalOpen.value = true
}

function closeEditModal() {
  editModalOpen.value = false
  resetEditForm()
}

async function handleUpdateDevice() {
  if (!editingDevice.value?.id) {
    return
  }
  if (!editForm.name.trim()) {
    message.warning('请输入设备名称')
    return
  }

  submitting.value = true
  try {
    await updateDevice(editingDevice.value.id, { name: editForm.name.trim() })
    message.success('设备名称更新成功')
    closeEditModal()
    await fetchDevices()
  } finally {
    submitting.value = false
  }
}

async function handleDeleteDevice(deviceId) {
  if (!deviceId) {
    return
  }

  deletingId.value = deviceId
  try {
    await deleteDevice(deviceId)
    message.success('设备删除成功')
    await fetchDevices()
  } finally {
    deletingId.value = ''
  }
}

onMounted(async () => {
  await fetchDevices()
  if (!pollingActive.value) {
    pollingActive.value = true
    await startPolling(false)
  }
})

onBeforeUnmount(() => {
  pollingActive.value = false
  stopPolling()
})
</script>

<template>
  <div class="device-page">
    <a-card :bordered="false" class="section-card">
      <template #title>
        <div class="table-header">
          <span>设备管理</span>
          <a-space>
            <a-button @click="fetchDevices">刷新</a-button>
            <a-button type="primary" @click="openAddModal">添加设备</a-button>
          </a-space>
        </div>
      </template>

      <a-spin :spinning="deviceStore.loading">
        <a-empty v-if="deviceList.length === 0" description="暂无设备" />
        <div v-else class="device-grid">
          <article
            v-for="record in deviceList"
            :key="record.id"
            class="device-card"
            :class="[`status-${record.status || 'unknown'}`, { offline: isOffline(record) }]"
          >
            <div class="device-head">
              <div class="device-title-wrap">
                <h3 class="device-title">{{ getDeviceTitle(record) }}</h3>
                <div class="device-serial mono-text" :title="record.serial">{{ record.serial }}</div>
              </div>
              <div class="device-status">
                <span class="status-dot" />
                <span>{{ getStatusMeta(record.status).text }}</span>
              </div>
            </div>

            <div class="device-body">
              <div class="kv-item">
                <span class="k">型号</span>
                <span class="v">{{ formatCellText(record.model) }}</span>
              </div>
              <div class="kv-item">
                <span class="k">系统版本</span>
                <span class="v mono-text">{{ formatCellText(record.android_version) }}</span>
              </div>
              <div class="kv-item">
                <span class="k">分辨率</span>
                <span class="v mono-text">{{ formatCellText(record.resolution) }}</span>
              </div>
              <div class="kv-item">
                <span class="k">近1天分析APP数</span>
                <span class="v">{{ record.analyzed_app_count_1d || 0 }}</span>
              </div>
              <div class="kv-item">
                <span class="k">最后心跳</span>
                <span class="v mono-text">{{ formatDateTime(record.last_heartbeat_at) }}</span>
              </div>
              <div class="kv-item task-item">
                <span class="k">当前任务</span>
                <span class="v mono-text" :title="record.current_task_id || '无'">
                  {{ record.current_task_id || '无' }}
                </span>
              </div>
            </div>

            <div v-if="record.status === 'busy'" class="busy-progress">
              <div class="busy-progress-bar" />
            </div>

            <div class="device-actions">
              <a-button size="small" @click="openEditModal(record)">重命名</a-button>
              <a-popconfirm
                title="确认删除该设备吗？"
                ok-text="删除"
                cancel-text="取消"
                @confirm="handleDeleteDevice(record.id)"
              >
                <a-button size="small" danger :loading="deletingId === record.id">删除</a-button>
              </a-popconfirm>
            </div>
            <div v-if="isOffline(record)" class="offline-mask">离线</div>
          </article>
        </div>
      </a-spin>
    </a-card>

    <a-modal
      :open="addModalOpen"
      title="添加设备"
      ok-text="保存"
      cancel-text="取消"
      :confirm-loading="submitting"
      @ok="handleCreateDevice"
      @cancel="closeAddModal"
    >
      <a-form layout="vertical">
        <a-form-item label="连接地址/序列号" required>
          <a-input v-model:value="addForm.serial" placeholder="如：192.168.1.10:5555 或 emulator-5554" />
        </a-form-item>
        <a-form-item label="设备名称">
          <a-input v-model:value="addForm.name" placeholder="可选，不填则使用设备型号" />
        </a-form-item>
        <a-form-item label="连接验证">
          <div class="validate-row">
            <a-button :loading="validatingConnection" @click="handleValidateConnection">验证连接</a-button>
            <a-spin v-if="validatingConnection" size="small" />
            <span
              v-else-if="connectionCheckMessage"
              :class="['check-message', connectionCheckState === 'success' ? 'success' : 'error']"
            >
              {{ connectionCheckMessage }}
            </span>
          </div>
        </a-form-item>
      </a-form>
    </a-modal>

    <a-modal
      :open="editModalOpen"
      title="修改设备名称"
      ok-text="保存"
      cancel-text="取消"
      :confirm-loading="submitting"
      @ok="handleUpdateDevice"
      @cancel="closeEditModal"
    >
      <a-form layout="vertical">
        <a-form-item label="设备名称" required>
          <a-input v-model:value="editForm.name" placeholder="请输入设备名称" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<style scoped>
.device-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.section-card {
  border-radius: 8px;
}

.table-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  color: var(--text-primary);
  font-family: var(--font-title);
  font-size: 16px;
}

.device-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
}

.device-card {
  position: relative;
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
  padding: 14px;
  background: var(--bg-card-deep);
  transition:
    transform var(--dur-hover) ease,
    border-color var(--dur-hover) ease,
    opacity var(--dur-hover) ease;
}

.device-card:hover {
  transform: translateY(-2px);
  border-color: var(--border-hover);
}

.device-head {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 12px;
}

.device-title-wrap {
  min-width: 0;
}

.device-title {
  margin: 0;
  color: var(--text-primary);
  font-size: 16px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.device-serial {
  margin-top: 4px;
  color: #8fa4bc;
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.device-status {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: #9ab2cb;
  font-size: 12px;
  white-space: nowrap;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #64748b;
}

.status-online .status-dot {
  background: var(--accent-green);
  box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.42);
  animation: online-pulse 1.4s ease-in-out infinite;
}

.status-busy .status-dot {
  background: var(--accent-amber);
}

.status-offline .status-dot {
  background: var(--accent-red);
}

.device-body {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 8px;
}

.kv-item {
  min-width: 0;
}

.k {
  display: block;
  color: #7790ab;
  font-size: 12px;
  margin-bottom: 4px;
}

.v {
  display: block;
  color: #dbe8f5;
  font-size: 13px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.task-item {
  grid-column: 1 / -1;
}

.busy-progress {
  margin-top: 12px;
  height: 6px;
  border-radius: 99px;
  overflow: hidden;
  background: rgba(148, 163, 184, 0.2);
}

.busy-progress-bar {
  width: 40%;
  height: 100%;
  border-radius: 99px;
  background: linear-gradient(90deg, rgba(245, 158, 11, 0.25), rgba(245, 158, 11, 1));
  animation: indeterminate 1.2s linear infinite;
}

.device-actions {
  margin-top: 12px;
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

.offline {
  opacity: 0.72;
}

.offline-mask {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  border-radius: 10px;
  background: rgba(2, 6, 23, 0.44);
  color: #cbd5e1;
  font-size: 14px;
  font-weight: 600;
  pointer-events: none;
}

.validate-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.check-message {
  font-size: 12px;
}

.check-message.success {
  color: #86efac;
}

.check-message.error {
  color: #fecaca;
}

@keyframes online-pulse {
  0%,
  100% {
    box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.42);
  }
  50% {
    box-shadow: 0 0 0 6px rgba(16, 185, 129, 0);
  }
}

@keyframes indeterminate {
  0% {
    transform: translateX(-130%);
  }
  100% {
    transform: translateX(330%);
  }
}

@media (max-width: 768px) {
  .table-header {
    flex-wrap: wrap;
    align-items: flex-start;
  }
}

@media (max-width: 1380px) {
  .device-grid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 1080px) {
  .device-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 640px) {
  .device-grid {
    grid-template-columns: 1fr;
  }
}
</style>
