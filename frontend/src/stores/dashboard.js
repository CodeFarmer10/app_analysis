import { defineStore } from 'pinia'

import { getDashboardStats, getDashboardTrend } from '../api/dashboard'

export const useDashboardStore = defineStore('dashboard', {
  state: () => ({
    stats: {
      total_tasks: 0,
      today_submitted: 0,
      today_completed: 0,
      analyzing_tasks: 0,
      online_devices: 0,
      success_rate: 0,
    },
    trendDays: 7,
    trendItems: [],
    loadingStats: false,
    loadingTrend: false,
  }),

  actions: {
    async fetchStats() {
      this.loadingStats = true
      try {
        const data = await getDashboardStats()
        this.stats = {
          total_tasks: Number(data?.total_tasks || 0),
          today_submitted: Number(data?.today_submitted || 0),
          today_completed: Number(data?.today_completed || 0),
          analyzing_tasks: Number(data?.analyzing_tasks || 0),
          online_devices: Number(data?.online_devices || 0),
          success_rate: Number(data?.success_rate || 0),
        }
      } finally {
        this.loadingStats = false
      }
    },

    async fetchTrend(days = this.trendDays) {
      const normalizedDays = Number(days) === 30 ? 30 : 7
      this.loadingTrend = true
      try {
        const data = await getDashboardTrend(normalizedDays)
        this.trendDays = normalizedDays
        this.trendItems = Array.isArray(data?.items) ? data.items : []
      } finally {
        this.loadingTrend = false
      }
    },

    setTrendDays(days) {
      this.trendDays = Number(days) === 30 ? 30 : 7
    },
  },
})
