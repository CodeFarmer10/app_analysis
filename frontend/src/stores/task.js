import { defineStore } from 'pinia'

import { getTaskList, getTaskStatus } from '../api/tasks'

export const useTaskStore = defineStore('task', {
  state: () => ({
    tasks: [],
    total: 0,
    page: 1,
    size: 20,
    filters: {
      md5: '',
      name: '',
      task_description: '',
      package: '',
      status: '',
      start: '',
      end: '',
    },
    loading: false,
  }),

  getters: {
    items: (state) => state.tasks,
  },

  actions: {
    async fetchTasks() {
      this.loading = true
      try {
        const params = {
          page: this.page,
          size: this.size,
          md5: this.filters.md5 || undefined,
          name: this.filters.name || undefined,
          task_description: this.filters.task_description || undefined,
          package: this.filters.package || undefined,
          status: this.filters.status || undefined,
          start: this.filters.start || undefined,
          end: this.filters.end || undefined,
        }
        const data = await getTaskList(params)
        this.tasks = data.items || []
        this.total = data.total || 0
        this.page = data.page || this.page
        this.size = data.size || this.size
      } finally {
        this.loading = false
      }
    },

    setPage(page, size = this.size) {
      this.page = page
      this.size = size
    },

    setFilters(partialFilters) {
      this.filters = { ...this.filters, ...partialFilters }
    },

    async refreshTaskStatus(taskId) {
      if (!taskId) {
        return null
      }

      const data = await getTaskStatus(taskId)
      const index = this.tasks.findIndex((task) => task.id === taskId)
      if (index >= 0) {
        this.tasks[index] = {
          ...this.tasks[index],
          status: data.status,
          device_id: data.device_id,
          error_message: data.error_message,
        }
      }
      return data
    },
  },
})
