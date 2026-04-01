import { createRouter, createWebHistory } from 'vue-router'

import { useAuthStore } from '../stores/auth'

const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('../views/Login.vue'),
    meta: { title: '登录' },
  },
  {
    path: '/',
    component: () => import('../components/AppLayout.vue'),
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        redirect: '/dashboard',
      },
      {
        path: 'dashboard',
        name: 'dashboard',
        component: () => import('../views/Dashboard.vue'),
        meta: { title: '看板' },
      },
      {
        path: 'tasks',
        name: 'tasks',
        component: () => import('../views/TaskList.vue'),
        meta: { title: '任务列表' },
      },
      {
        path: 'tasks/:taskId',
        name: 'task-detail',
        component: () => import('../views/TaskDetail.vue'),
        meta: { title: '任务详情' },
      },
      {
        path: 'devices',
        name: 'devices',
        component: () => import('../views/DeviceList.vue'),
        meta: { title: '设备管理' },
      },
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/dashboard',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

const APP_TITLE = '诈骗APP分析系统'

router.beforeEach((to) => {
  const authStore = useAuthStore()
  const hasToken = Boolean(authStore.token)

  if (to.meta.requiresAuth && !hasToken) {
    return {
      path: '/login',
      query: { redirect: to.fullPath },
    }
  }

  if (to.path === '/login' && hasToken) {
    const redirectTarget =
      typeof to.query.redirect === 'string' && to.query.redirect
        ? to.query.redirect
        : '/dashboard'
    return redirectTarget
  }

  return true
})

router.afterEach((to) => {
  const pageTitle = typeof to.meta.title === 'string' ? to.meta.title.trim() : ''
  document.title = pageTitle ? `${pageTitle} - ${APP_TITLE}` : APP_TITLE
})

export default router
