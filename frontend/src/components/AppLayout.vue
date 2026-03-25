<script setup>
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { useAuthStore } from '../stores/auth'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

const logoutLoading = ref(false)

const menuItems = [
  { key: '/dashboard', label: '主页' },
  { key: '/tasks', label: '任务管理' },
  { key: '/devices', label: '设备管理' },
]

const selectedMenuKey = computed(() => {
  if (route.path.startsWith('/tasks')) {
    return '/tasks'
  }
  if (route.path.startsWith('/devices')) {
    return '/devices'
  }
  return '/dashboard'
})

async function handleMenuClick({ key }) {
  if (typeof key === 'string' && key !== route.path) {
    await router.push(key)
  }
}

async function handleLogout() {
  logoutLoading.value = true
  try {
    await authStore.logout()
    await router.replace('/login')
  } finally {
    logoutLoading.value = false
  }
}
</script>

<template>
  <a-layout class="app-layout">
    <a-layout-sider class="app-sider" :width="220">
      <div class="logo">诈骗APP分析系统</div>
      <a-menu
        mode="inline"
        theme="dark"
        :selected-keys="[selectedMenuKey]"
        :items="menuItems"
        @click="handleMenuClick"
      />
    </a-layout-sider>

    <a-layout>
      <a-layout-header class="app-header">
        <div class="header-right">
          <span class="username">当前用户：{{ authStore.username || '--' }}</span>
          <a-button type="link" :loading="logoutLoading" @click="handleLogout">退出登录</a-button>
        </div>
      </a-layout-header>

      <a-layout-content class="app-content">
        <router-view />
      </a-layout-content>
    </a-layout>
  </a-layout>
</template>

<style scoped>
.app-layout {
  min-height: 100vh;
}

.app-sider {
  background: linear-gradient(180deg, #1f56bb 0%, #245ec6 55%, #2a64c8 100%);
  border-right: 1px solid #4b7fd4;
  box-shadow: inset -1px 0 0 rgba(140, 179, 245, 0.48);
}

.logo {
  height: 64px;
  line-height: 64px;
  padding: 0 16px;
  font-size: 16px;
  font-weight: 600;
  color: #f4f8ff;
  border-bottom: 1px solid #4b7fd4;
  background: rgba(188, 214, 255, 0.18);
}

.app-header {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  padding: 0 20px;
  background: #f9fbff;
  border-bottom: 1px solid #e8edf7;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.username {
  color: #4a5568;
}

.app-content {
  padding: 16px;
}

.app-sider :deep(.ant-layout-sider-children) {
  display: flex;
  flex-direction: column;
}

.app-sider :deep(.ant-menu) {
  background: transparent;
  border-inline-end: none;
  padding: 10px 10px 0;
}

.app-sider :deep(.ant-menu-item) {
  margin: 6px 0;
  border-radius: 8px;
  color: #edf4ff;
}

.app-sider :deep(.ant-menu-item:hover) {
  color: #ffffff;
  background: rgba(179, 209, 255, 0.3);
}

.app-sider :deep(.ant-menu-item-selected) {
  background: rgba(168, 202, 255, 0.48);
  color: #ffffff;
}
</style>
