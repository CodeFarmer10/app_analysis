import { createRouter, createWebHistory } from 'vue-router'

import { useAuthStore } from '../stores/auth'

const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('../views/Login.vue'),
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
      },
      {
        path: 'tasks',
        name: 'tasks',
        component: () => import('../views/TaskList.vue'),
      },
      {
        path: 'tasks/:taskId',
        name: 'task-detail',
        component: () => import('../views/TaskDetail.vue'),
      },
      {
        path: 'devices',
        name: 'devices',
        component: () => import('../views/DeviceList.vue'),
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

export default router
