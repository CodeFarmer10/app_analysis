import { defineStore } from 'pinia'

const TOKEN_STORAGE_KEY = 'fraud_app_token'
const USERNAME_STORAGE_KEY = 'fraud_app_username'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem(TOKEN_STORAGE_KEY) || '',
    username: localStorage.getItem(USERNAME_STORAGE_KEY) || '',
  }),

  getters: {
    isLoggedIn: (state) => Boolean(state.token),
  },

  actions: {
    async login(payload) {
      const { login } = await import('../api/auth')
      const data = await login(payload)

      this.token = data?.token || ''
      this.username = data?.username || payload?.username || ''

      localStorage.setItem(TOKEN_STORAGE_KEY, this.token)
      localStorage.setItem(USERNAME_STORAGE_KEY, this.username)

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

      localStorage.removeItem(TOKEN_STORAGE_KEY)
      localStorage.removeItem(USERNAME_STORAGE_KEY)
    },
  },
})
