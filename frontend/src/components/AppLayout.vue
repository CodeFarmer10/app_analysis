<script setup>
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { useAuthStore } from '../stores/auth'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

const logoutLoading = ref(false)
const roleText = computed(() => (authStore.role === 'admin' ? '管理员' : '普通用户'))
const currentPageTitle = computed(() => {
  if (typeof route.meta?.title === 'string' && route.meta.title.trim()) {
    return route.meta.title.trim()
  }
  return '工作台'
})

const menuItems = computed(() => {
  const items = [
    { key: '/dashboard', label: '主页' },
    { key: '/tasks', label: '任务管理' },
    { key: '/devices', label: '设备管理' },
  ]
  if (authStore.role === 'admin') {
    items.push({ key: '/users', label: '用户管理' })
  }
  return items
})

const selectedMenuKey = computed(() => {
  if (route.path.startsWith('/tasks')) {
    return '/tasks'
  }
  if (route.path.startsWith('/devices')) {
    return '/devices'
  }
  if (route.path.startsWith('/users')) {
    return '/users'
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
      <div class="logo">
        <div class="logo-text">
          <div class="logo-title">诈骗APP分析系统</div>
        </div>
      </div>
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
        <div class="header-left">
          <div class="header-title">{{ currentPageTitle }}</div>
        </div>
        <div class="header-right">
          <a-tag color="blue" class="role-tag">{{ roleText }}</a-tag>
          <span class="username">当前用户：{{ authStore.username || '--' }}</span>
          <a-button type="link" :loading="logoutLoading" @click="handleLogout">退出登录</a-button>
        </div>
      </a-layout-header>

      <a-layout-content class="app-content">
        <div class="content-shell">
          <router-view />
        </div>
      </a-layout-content>
    </a-layout>
  </a-layout>
</template>

<style scoped>
.app-layout {
  min-height: 100vh;
}

.app-sider {
  background: linear-gradient(180deg, #123f70 0%, #103760 55%, #0c2d4f 100%);
  border-right: 1px solid #2c4f72;
  box-shadow: inset -1px 0 0 rgba(118, 150, 184, 0.35);
}

.logo {
  display: flex;
  align-items: center;
  height: 72px;
  padding: 0 14px;
  border-bottom: 1px solid #2c4f72;
  background: rgba(206, 225, 246, 0.14);
}

.logo-text {
  min-width: 0;
}

.logo-title {
  color: #edf5ff;
  font-size: 15px;
  font-weight: 600;
  letter-spacing: 0.2px;
}

.app-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 20px;
  background: linear-gradient(180deg, #f8fbfe 0%, #f1f6fc 100%);
  border-bottom: 1px solid #d9e4f0;
}

.header-left {
  display: flex;
  align-items: center;
}

.header-title {
  color: #1d344f;
  font-size: 18px;
  font-weight: 600;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 10px;
}

.role-tag {
  margin-right: 2px;
}

.username {
  color: #2f445d;
  font-weight: 500;
}

.app-content {
  padding: 14px;
}

.content-shell {
  border: 1px solid #d9e4ef;
  border-radius: 10px;
  padding: 14px;
  background: rgba(255, 255, 255, 0.74);
  backdrop-filter: blur(1px);
}

.app-sider :deep(.ant-layout-sider-children) {
  display: flex;
  flex-direction: column;
}

.app-sider :deep(.ant-menu) {
  background: transparent;
  border-inline-end: none;
  padding: 12px 10px 0;
}

.app-sider :deep(.ant-menu-item) {
  margin: 6px 0;
  border-radius: 6px;
  color: #e5effa;
}

.app-sider :deep(.ant-menu-item:hover) {
  color: #ffffff;
  background: rgba(123, 164, 206, 0.28);
}

.app-sider :deep(.ant-menu-item-selected) {
  background: rgba(140, 185, 230, 0.44);
  color: #ffffff;
}

@media (max-width: 960px) {
  .app-sider {
    width: 180px !important;
    min-width: 180px !important;
    max-width: 180px !important;
    flex: 0 0 180px !important;
  }

  .app-header {
    padding: 0 12px;
  }

  .header-title {
    font-size: 16px;
  }

  .content-shell {
    padding: 10px;
  }
}
</style>
