import { defineStore } from 'pinia'

const TOKEN_STORAGE_KEY = 'fraud_app_token'
const USERNAME_STORAGE_KEY = 'fraud_app_username'
const ROLE_STORAGE_KEY = 'fraud_app_role'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem(TOKEN_STORAGE_KEY) || '',
    username: localStorage.getItem(USERNAME_STORAGE_KEY) || '',
    role: localStorage.getItem(ROLE_STORAGE_KEY) || '',
  }),

  getters: {
    isLoggedIn: (state) => Boolean(state.token),
    isAdmin: (state) => state.role === 'admin',
  },

  actions: {
    async login(payload, redirect = '/dashboard') {
      const { login: loginApi } = await import('../api/auth')
      const data = await loginApi(payload)

      this.token = data?.token || ''
      this.username = data?.username || payload?.username || ''
      this.role = data?.role || ''

      localStorage.setItem(TOKEN_STORAGE_KEY, this.token)
      localStorage.setItem(USERNAME_STORAGE_KEY, this.username)
      localStorage.setItem(ROLE_STORAGE_KEY, this.role)

      const safeRedirect =
        typeof redirect === 'string' && redirect.startsWith('/') ? redirect : '/dashboard'
      const { default: router } = await import('../router')
      await router.replace(safeRedirect)

      return data
    },

    async logout(options = { remote: true }) {
      const { remote = true } = options

      if (remote && this.token) {
        try {
          const { logout } = await import('../api/auth')
          await logout()
        } catch (_error) {}
      }

      this.token = ''
      this.username = ''
      this.role = ''

      localStorage.removeItem(TOKEN_STORAGE_KEY)
      localStorage.removeItem(USERNAME_STORAGE_KEY)
      localStorage.removeItem(ROLE_STORAGE_KEY)
    },
  },
})
