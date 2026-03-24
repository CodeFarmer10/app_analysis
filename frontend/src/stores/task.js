import { defineStore } from 'pinia'

export const useTaskStore = defineStore('task', {
  state: () => ({
    items: [],
    total: 0,
    page: 1,
    size: 20,
    filters: {
      md5: '',
      name: '',
      package: '',
      status: '',
      start: '',
      end: '',
    },
    loading: false,
  }),

  actions: {
    setPage(page) {
      this.page = page
    },

    setSize(size) {
      this.size = size
    },

    setFilters(partialFilters) {
      this.filters = { ...this.filters, ...partialFilters }
    },
  },
})
