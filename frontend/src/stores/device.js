import { defineStore } from 'pinia'

export const useDeviceStore = defineStore('device', {
  state: () => ({
    items: [],
    total: 0,
    loading: false,
  }),

  actions: {
    setItems(items) {
      this.items = items
      this.total = items.length
    },
  },
})
