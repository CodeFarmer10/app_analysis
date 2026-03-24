import axios from 'axios'
import { message } from 'ant-design-vue'

import { useAuthStore } from '../stores/auth'

const request = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

request.interceptors.request.use(
  (config) => {
    const authStore = useAuthStore()
    const nextConfig = { ...config }

    if (authStore.token) {
      nextConfig.headers = nextConfig.headers || {}
      nextConfig.headers.Authorization = `Bearer ${authStore.token}`
    }

    return nextConfig
  },
  (error) => Promise.reject(error)
)

request.interceptors.response.use(
  (response) => {
    const payload = response.data || {}

    if (payload.code !== 0) {
      const errMsg = payload.message || '请求失败'
      message.error(errMsg)
      return Promise.reject(new Error(errMsg))
    }

    return payload.data
  },
  async (error) => {
    const statusCode = error?.response?.status
    const backendMessage = error?.response?.data?.message
    const fallbackMessage = backendMessage || error.message || '网络异常，请稍后重试'

    if (statusCode === 401) {
      const authStore = useAuthStore()
      await authStore.logout({ remote: false })

      const { default: router } = await import('../router')
      const currentPath = router.currentRoute.value.fullPath
      const redirect = encodeURIComponent(currentPath || '/dashboard')

      if (router.currentRoute.value.path !== '/login') {
        await router.replace(`/login?redirect=${redirect}`)
      }
    } else {
      message.error(fallbackMessage)
    }

    return Promise.reject(error)
  }
)

export default request
