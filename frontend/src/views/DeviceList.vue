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

const addForm = reactive({
  serial: '',
  name: '',
})

const editForm = reactive({
  name: '',
})

const columns = [
  { title: '序号', key: 'index', width: 70 },
  { title: '设备名称', dataIndex: 'name', key: 'name', width: 180 },
  { title: '连接地址/序列号', dataIndex: 'serial', key: 'serial', width: 220 },
  { title: '型号', dataIndex: 'model', key: 'model', width: 180 },
  { title: '系统版本', dataIndex: 'android_version', key: 'android_version', width: 130 },
  { title: '分辨率', dataIndex: 'resolution', key: 'resolution', width: 130 },
  { title: '近1天分析APP数', dataIndex: 'analyzed_app_count_1d', key: 'analyzed_app_count_1d', width: 150 },
  { title: '状态', dataIndex: 'status', key: 'status', width: 120 },
  { title: '当前任务', dataIndex: 'current_task_id', key: 'current_task_id', width: 220 },
  { title: '最后心跳', dataIndex: 'last_heartbeat_at', key: 'last_heartbeat_at', width: 180 },
  { title: '操作', key: 'actions', width: 160, fixed: 'right' },
]

const deviceList = computed(() => deviceStore.items)

const statusMetaMap = {
  online: { status: 'success', text: '在线' },
  offline: { status: 'error', text: '离线' },
  busy: { status: 'processing', text: '分析中' },
}

const { start: startPolling, stop: stopPolling } = usePolling(async () => {
  await fetchDevices()
}, 30000)

function getStatusMeta(status) {
  return statusMetaMap[status] || { status: 'default', text: status || '未知' }
}

function formatCellText(value) {
  if (value === null || value === undefined || value === '') {
    return '--'
  }
  return value
}

function resetAddForm() {
  addForm.serial = ''
  addForm.name = ''
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

      <a-table
        row-key="id"
        :columns="columns"
        :data-source="deviceList"
        :loading="deviceStore.loading"
        :pagination="false"
        :scroll="{ x: 1720 }"
      >
        <template #bodyCell="{ column, record, text, index }">
          <template v-if="column.key === 'index'">
            {{ index + 1 }}
          </template>
          <template v-else-if="column.key === 'status'">
            <a-badge :status="getStatusMeta(record.status).status" :text="getStatusMeta(record.status).text" />
          </template>
          <template v-else-if="column.key === 'current_task_id'">
            <a-typography-text :ellipsis="{ tooltip: text || '无' }">
              {{ text || '无' }}
            </a-typography-text>
          </template>
          <template v-else-if="column.key === 'last_heartbeat_at'">
            {{ formatDateTime(text) }}
          </template>
          <template v-else-if="column.key === 'actions'">
            <a-space>
              <a-button type="link" @click="openEditModal(record)">重命名</a-button>
              <a-popconfirm
                title="确认删除该设备吗？"
                ok-text="删除"
                cancel-text="取消"
                @confirm="handleDeleteDevice(record.id)"
              >
                <a-button type="link" danger :loading="deletingId === record.id">删除</a-button>
              </a-popconfirm>
            </a-space>
          </template>
          <template v-else>
            {{ formatCellText(text) }}
          </template>
        </template>
      </a-table>
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
}
</style>
