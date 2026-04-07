<script setup>
import { computed, h, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { useAuthStore } from '../stores/auth'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

const logoutLoading = ref(false)
const collapsed = ref(false)
const isMobile = ref(false)
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
    if (isMobile.value) {
      collapsed.value = true
    }
  }
}

function handleBreakpoint(broken) {
  isMobile.value = Boolean(broken)
  collapsed.value = Boolean(broken)
}

function handleCollapse(nextCollapsed) {
  collapsed.value = Boolean(nextCollapsed)
}

function toggleCollapsed() {
  collapsed.value = !collapsed.value
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
    <a-layout-sider
      class="app-sider"
      :width="232"
      :collapsed="collapsed"
      :collapsed-width="isMobile ? 0 : 72"
      breakpoint="md"
      :trigger="null"
      @breakpoint="handleBreakpoint"
      @collapse="handleCollapse"
    >
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
          <button class="collapse-btn" type="button" @click="toggleCollapsed">
            <span class="collapse-icon" />
          </button>
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
  background: transparent;
}

.app-sider {
  background: var(--bg-sidebar);
  border-right: 1px solid var(--border-subtle);
  box-shadow: inset -1px 0 0 rgba(255, 255, 255, 0.02);
}

.logo {
  display: flex;
  align-items: center;
  min-height: 68px;
  padding: 0 16px;
  border-bottom: 1px solid var(--border-subtle);
  background: linear-gradient(180deg, rgba(59, 130, 246, 0.12) 0%, rgba(59, 130, 246, 0) 100%);
}

.logo-text {
  min-width: 0;
}

.logo-title {
  color: var(--text-primary);
  font-size: 16px;
  font-weight: 600;
  font-family: var(--font-title);
  letter-spacing: 0.35px;
}

.app-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  height: 62px;
  line-height: 62px;
  padding: 0 20px 0 14px;
  background: rgba(12, 18, 31, 0.9);
  border-bottom: 1px solid var(--border-subtle);
  backdrop-filter: blur(10px);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.collapse-btn {
  width: 34px;
  height: 34px;
  padding: 0;
  display: grid;
  place-items: center;
  line-height: 1;
  border: 1px solid var(--border-normal);
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.02);
  cursor: pointer;
  color: var(--text-secondary);
  transition: all var(--dur-hover) ease;
}

.collapse-btn:hover {
  border-color: var(--border-hover);
  background: rgba(59, 130, 246, 0.16);
}

.collapse-icon {
  position: relative;
  display: block;
  width: 14px;
  height: 2px;
  background: currentColor;
  border-radius: 99px;
}

.collapse-icon::before,
.collapse-icon::after {
  content: '';
  position: absolute;
  left: 0;
  width: 14px;
  height: 2px;
  background: currentColor;
  border-radius: 99px;
}

.collapse-icon::before {
  top: -4px;
}

.collapse-icon::after {
  top: 4px;
}

.header-title {
  color: var(--text-primary);
  font-size: 20px;
  font-weight: 600;
  font-family: var(--font-title);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.role-tag {
  margin-right: 2px;
}

.username {
  color: var(--text-secondary);
  font-weight: 500;
}

.app-content {
  padding: 14px 16px 16px;
}

.content-shell {
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 16px;
  background: rgba(21, 28, 43, 0.56);
  transition: background var(--dur-expand) ease;
}

.app-sider :deep(.ant-layout-sider-children) {
  display: flex;
  flex-direction: column;
}

.app-sider :deep(.ant-menu) {
  background: transparent;
  border-inline-end: none;
  padding: 12px 12px 0;
}

.app-sider :deep(.ant-menu-item) {
  margin: 6px 0;
  border-radius: 6px;
  color: var(--text-secondary);
  height: 42px;
  line-height: 42px;
  transition: all var(--dur-hover) ease;
}

.app-sider :deep(.ant-menu-item:hover) {
  color: var(--text-primary);
  background: rgba(59, 130, 246, 0.18);
}

.app-sider :deep(.ant-menu-item-selected) {
  background: rgba(59, 130, 246, 0.24);
  color: #dbeafe;
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
  border: 1px solid rgba(148, 163, 184, 0.36);
  background: rgba(148, 163, 184, 0.1);
  position: relative;
  flex: 0 0 16px;
  transition: all var(--dur-hover) ease;
}

.app-sider :deep(.menu-icon::after) {
  content: '';
  position: absolute;
  inset: 3px;
  background: rgba(241, 245, 249, 0.85);
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
  border: 1px solid rgba(15, 23, 42, 0.92);
  box-shadow:
    6px 0 0 -1px rgba(15, 23, 42, 0.92),
    0 6px 0 -1px rgba(15, 23, 42, 0.92),
    6px 6px 0 -1px rgba(15, 23, 42, 0.92);
}

.app-sider :deep(.icon-task::before) {
  width: 8px;
  height: 10px;
  left: 3px;
  top: 2px;
  border: 1px solid rgba(15, 23, 42, 0.95);
  border-radius: 1px;
  background:
    linear-gradient(rgba(15, 23, 42, 0.95), rgba(15, 23, 42, 0.95)) 1px 2px / 6px 1px no-repeat,
    linear-gradient(rgba(15, 23, 42, 0.95), rgba(15, 23, 42, 0.95)) 1px 5px / 5px 1px no-repeat,
    linear-gradient(rgba(15, 23, 42, 0.95), rgba(15, 23, 42, 0.95)) 1px 8px / 4px 1px no-repeat;
}

.app-sider :deep(.icon-device::before) {
  width: 8px;
  height: 6px;
  left: 3px;
  top: 3px;
  border: 1px solid rgba(15, 23, 42, 0.95);
  border-radius: 1px;
  box-shadow: 0 7px 0 -2px rgba(15, 23, 42, 0.95);
}

.app-sider :deep(.icon-user::before) {
  width: 8px;
  height: 8px;
  left: 3px;
  top: 3px;
  border-radius: 50%;
  background:
    radial-gradient(circle at 50% 32%, rgba(15, 23, 42, 0.95) 2px, transparent 2px),
    linear-gradient(
      180deg,
      transparent 45%,
      rgba(15, 23, 42, 0.95) 45%,
      rgba(15, 23, 42, 0.95) 100%
    );
}

.app-sider :deep(.menu-text) {
  font-weight: 500;
  letter-spacing: 0.1px;
}

@media (max-width: 768px) {
  .app-header {
    padding: 0 10px;
  }

  .header-right {
    gap: 8px;
  }

  .username {
    display: none;
  }

  .content-shell {
    padding: 10px;
  }
}
</style>
