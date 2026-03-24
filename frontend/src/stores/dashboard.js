import { defineStore } from 'pinia'

export const useDashboardStore = defineStore('dashboard', {
  state: () => ({
    stats: {
      total_tasks: 0,
      today_submitted: 0,
      today_completed: 0,
      processing_count: 0,
      online_devices: 0,
      success_rate: 0,
    },
    trendDays: 7,
    trendItems: [],
    loadingStats: false,
    loadingTrend: false,
  }),

  actions: {
    setTrendDays(days) {
      this.trendDays = days
    },
  },
})
