<script setup>
import { computed, h, ref } from 'vue'
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

function createMenuLabel(text, iconClass) {
  return h('span', { class: 'menu-entry' }, [
    h('span', { class: ['menu-icon', iconClass], 'aria-hidden': 'true' }),
    h('span', { class: 'menu-text' }, text),
  ])
}

const menuItems = computed(() => {
  const items = [
    { key: '/dashboard', label: createMenuLabel('主页', 'icon-dashboard') },
    { key: '/tasks', label: createMenuLabel('任务管理', 'icon-task') },
    { key: '/devices', label: createMenuLabel('设备管理', 'icon-device') },
  ]
  if (authStore.role === 'admin') {
    items.push({ key: '/users', label: createMenuLabel('用户管理', 'icon-user') })
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
  background: linear-gradient(180deg, #0f344d 0%, #0d2d42 62%, #0a2334 100%);
  border-right: 1px solid #1a4d6b;
  box-shadow: inset -1px 0 0 rgba(93, 166, 206, 0.28);
}

.logo {
  display: flex;
  align-items: center;
  height: 72px;
  padding: 0 14px;
  border-bottom: 1px solid #1a4d6b;
  background: rgba(53, 117, 154, 0.2);
}

.logo-text {
  min-width: 0;
}

.logo-title {
  color: #f2fbff;
  font-size: 15px;
  font-weight: 600;
  letter-spacing: 0.3px;
}

.app-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 20px;
  background: linear-gradient(180deg, #fbfdff 0%, #f3f8fc 100%);
  border-bottom: 1px solid #d2e0ec;
}

.header-left {
  display: flex;
  align-items: center;
}

.header-title {
  color: #18374e;
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
  color: #35546b;
  font-weight: 500;
}

.app-content {
  padding: 14px;
}

.content-shell {
  border: 1px solid #d2e1ec;
  border-radius: 10px;
  padding: 14px;
  background: rgba(255, 255, 255, 0.8);
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
  color: #dcecf8;
}

.app-sider :deep(.ant-menu-item:hover) {
  color: #ffffff;
  background: rgba(64, 145, 194, 0.3);
}

.app-sider :deep(.ant-menu-item-selected) {
  background: rgba(86, 180, 230, 0.35);
  color: #ffffff;
}

.app-sider :deep(.ant-menu-title-content) {
  width: 100%;
}

.app-sider :deep(.menu-entry) {
  display: inline-flex;
  align-items: center;
  gap: 10px;
}

.app-sider :deep(.menu-icon) {
  width: 16px;
  height: 16px;
  border-radius: 4px;
  border: 1px solid rgba(214, 239, 255, 0.58);
  background: rgba(191, 227, 249, 0.22);
  position: relative;
  flex: 0 0 16px;
}

.app-sider :deep(.menu-icon::after) {
  content: '';
  position: absolute;
  inset: 3px;
  background: rgba(233, 248, 255, 0.86);
  border-radius: 2px;
}

.app-sider :deep(.icon-dashboard::before),
.app-sider :deep(.icon-task::before),
.app-sider :deep(.icon-device::before),
.app-sider :deep(.icon-user::before) {
  content: '';
  position: absolute;
  z-index: 1;
}

.app-sider :deep(.icon-dashboard::before) {
  width: 8px;
  height: 8px;
  left: 3px;
  top: 3px;
  border: 1px solid rgba(15, 63, 94, 0.9);
  box-shadow:
    6px 0 0 -1px rgba(15, 63, 94, 0.9),
    0 6px 0 -1px rgba(15, 63, 94, 0.9),
    6px 6px 0 -1px rgba(15, 63, 94, 0.9);
}

.app-sider :deep(.icon-task::before) {
  width: 8px;
  height: 10px;
  left: 3px;
  top: 2px;
  border: 1px solid rgba(15, 63, 94, 0.95);
  border-radius: 1px;
  background:
    linear-gradient(rgba(15, 63, 94, 0.9), rgba(15, 63, 94, 0.9)) 1px 2px / 6px 1px no-repeat,
    linear-gradient(rgba(15, 63, 94, 0.9), rgba(15, 63, 94, 0.9)) 1px 5px / 5px 1px no-repeat,
    linear-gradient(rgba(15, 63, 94, 0.9), rgba(15, 63, 94, 0.9)) 1px 8px / 4px 1px no-repeat;
}

.app-sider :deep(.icon-device::before) {
  width: 8px;
  height: 6px;
  left: 3px;
  top: 3px;
  border: 1px solid rgba(15, 63, 94, 0.95);
  border-radius: 1px;
  box-shadow: 0 7px 0 -2px rgba(15, 63, 94, 0.95);
}

.app-sider :deep(.icon-user::before) {
  width: 8px;
  height: 8px;
  left: 3px;
  top: 3px;
  border-radius: 50%;
  background:
    radial-gradient(circle at 50% 32%, rgba(15, 63, 94, 0.96) 2px, transparent 2px),
    linear-gradient(
      180deg,
      transparent 45%,
      rgba(15, 63, 94, 0.96) 45%,
      rgba(15, 63, 94, 0.96) 100%
    );
}

.app-sider :deep(.menu-text) {
  font-weight: 500;
  letter-spacing: 0.1px;
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
