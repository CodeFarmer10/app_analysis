<script setup>
import { onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'

import { createUser, deleteUser, getUserList } from '../api/users'
import { useAuthStore } from '../stores/auth'
import { formatDateTime } from '../utils/format'

const authStore = useAuthStore()

const loading = ref(false)
const submitting = ref(false)
const deletingId = ref('')
const addModalOpen = ref(false)
const users = ref([])

const addForm = reactive({
  username: '',
  password: '',
  role: 'user',
})

const columns = [
  { title: '序号', key: 'index', width: 70 },
  { title: '用户名', dataIndex: 'username', key: 'username', width: 220 },
  { title: '角色', dataIndex: 'role', key: 'role', width: 120 },
  { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 200 },
  { title: '操作', key: 'actions', width: 180, fixed: 'right' },
]

const roleOptions = [
  { label: '普通用户', value: 'user' },
  { label: '管理员', value: 'admin' },
]

function formatRole(role) {
  return role === 'admin' ? '管理员' : '普通用户'
}

function resetAddForm() {
  addForm.username = ''
  addForm.password = ''
  addForm.role = 'user'
}

async function fetchUsers() {
  loading.value = true
  try {
    const data = await getUserList()
    users.value = data?.items || []
  } finally {
    loading.value = false
  }
}

function openAddModal() {
  addModalOpen.value = true
}

function closeAddModal() {
  addModalOpen.value = false
  resetAddForm()
}

async function handleCreateUser() {
  const username = addForm.username.trim()
  const password = addForm.password.trim()
  if (!username) {
    message.warning('请输入用户名')
    return
  }
  if (password.length < 6) {
    message.warning('密码长度至少6位')
    return
  }

  submitting.value = true
  try {
    await createUser({
      username,
      password,
      role: addForm.role,
    })
    message.success('用户添加成功')
    closeAddModal()
    await fetchUsers()
  } finally {
    submitting.value = false
  }
}

async function handleDeleteUser(userId) {
  if (!userId) {
    return
  }
  deletingId.value = userId
  try {
    await deleteUser(userId)
    message.success('用户删除成功')
    await fetchUsers()
  } finally {
    deletingId.value = ''
  }
}

onMounted(async () => {
  await fetchUsers()
})
</script>

<template>
  <div class="user-page">
    <a-card :bordered="false" class="section-card">
      <template #title>
        <div class="table-header">
          <span>用户管理</span>
          <a-space>
            <a-button @click="fetchUsers">刷新</a-button>
            <a-button type="primary" @click="openAddModal">添加用户</a-button>
          </a-space>
        </div>
      </template>

      <a-table
        row-key="id"
        :columns="columns"
        :data-source="users"
        :loading="loading"
        :pagination="false"
        :scroll="{ x: 780 }"
      >
        <template #bodyCell="{ column, record, text, index }">
          <template v-if="column.key === 'index'">
            {{ index + 1 }}
          </template>
          <template v-else-if="column.key === 'role'">
            {{ formatRole(text) }}
          </template>
          <template v-else-if="column.key === 'created_at'">
            {{ formatDateTime(text) }}
          </template>
          <template v-else-if="column.key === 'actions'">
            <a-popconfirm
              title="确认删除该用户吗？"
              ok-text="删除"
              cancel-text="取消"
              :disabled="record.username === authStore.username"
              @confirm="handleDeleteUser(record.id)"
            >
              <a-button
                type="link"
                danger
                :disabled="record.username === authStore.username"
                :loading="deletingId === record.id"
              >
                删除
              </a-button>
            </a-popconfirm>
          </template>
          <template v-else>
            {{ text || '--' }}
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal
      :open="addModalOpen"
      title="添加用户"
      ok-text="保存"
      cancel-text="取消"
      :confirm-loading="submitting"
      @ok="handleCreateUser"
      @cancel="closeAddModal"
    >
      <a-form layout="vertical">
        <a-form-item label="用户名" required>
          <a-input v-model:value="addForm.username" placeholder="请输入用户名" />
        </a-form-item>
        <a-form-item label="密码" required>
          <a-input-password v-model:value="addForm.password" placeholder="请输入密码（至少6位）" />
        </a-form-item>
        <a-form-item label="角色" required>
          <a-select v-model:value="addForm.role" :options="roleOptions" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<style scoped>
.user-page {
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
}

@media (max-width: 768px) {
  .table-header {
    flex-wrap: wrap;
    align-items: flex-start;
  }
}
</style>
