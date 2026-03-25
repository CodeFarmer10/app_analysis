<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

import { useDashboardStore } from '../stores/dashboard'
import { usePolling } from '../utils/polling'

use([CanvasRenderer, LineChart, GridComponent, TooltipComponent, LegendComponent])

const dashboardStore = useDashboardStore()
const pollingActive = ref(false)

const statCards = computed(() => [
  { key: 'total_tasks', title: '总任务数', value: dashboardStore.stats.total_tasks },
  { key: 'today_submitted', title: '今日提交任务', value: dashboardStore.stats.today_submitted },
  { key: 'today_completed', title: '今日完成任务', value: dashboardStore.stats.today_completed },
  { key: 'analyzing_tasks', title: '分析中任务', value: dashboardStore.stats.analyzing_tasks },
  { key: 'online_devices', title: '在线设备数', value: dashboardStore.stats.online_devices },
  { key: 'success_rate', title: '任务成功率', value: `${dashboardStore.stats.success_rate}%` },
])

const trendChartOption = computed(() => {
  const items = dashboardStore.trendItems || []
  const xAxis = items.map((item) => {
    const rawDate = item?.date || ''
    return typeof rawDate === 'string' && rawDate.length >= 10 ? rawDate.slice(5) : rawDate
  })
  const submitSeries = items.map((item) => Number(item?.submitted || 0))
  const completedSeries = items.map((item) => Number(item?.completed || 0))

  return {
    tooltip: { trigger: 'axis' },
    legend: {
      data: ['提交数', '完成数'],
      top: 8,
    },
    grid: {
      left: 40,
      right: 20,
      top: 56,
      bottom: 30,
    },
    xAxis: {
      type: 'category',
      data: xAxis,
      boundaryGap: false,
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
    },
    series: [
      {
        name: '提交数',
        type: 'line',
        smooth: true,
        data: submitSeries,
      },
      {
        name: '完成数',
        type: 'line',
        smooth: true,
        data: completedSeries,
      },
    ],
  }
})

const { start: startPolling, stop: stopPolling } = usePolling(async () => {
  await refreshDashboard()
}, 30000)

async function refreshDashboard() {
  await Promise.all([dashboardStore.fetchStats(), dashboardStore.fetchTrend(dashboardStore.trendDays)])
}

async function handleTrendDaysChange(event) {
  const nextDays = Number(event?.target?.value) === 30 ? 30 : 7
  dashboardStore.setTrendDays(nextDays)
  await dashboardStore.fetchTrend(nextDays)
}

onMounted(async () => {
  await refreshDashboard()
  if (!pollingActive.value) {
    pollingActive.value = true
    await startPolling(false)
  }
})

onBeforeUnmount(() => {
  pollingActive.value = false
  stopPolling()
})
</script>

<template>
  <div class="dashboard-page">
    <a-row :gutter="[16, 16]">
      <a-col v-for="card in statCards" :key="card.key" :xs="24" :sm="12" :lg="8">
        <a-card :bordered="false" class="stat-card" :loading="dashboardStore.loadingStats">
          <a-statistic :title="card.title" :value="card.value" />
        </a-card>
      </a-col>
    </a-row>

    <a-card :bordered="false" class="trend-card">
      <template #title>
        <div class="trend-header">
          <span>任务趋势</span>
          <a-space>
            <a-radio-group
              :value="dashboardStore.trendDays"
              button-style="solid"
              @change="handleTrendDaysChange"
            >
              <a-radio-button :value="7">近7天</a-radio-button>
              <a-radio-button :value="30">近30天</a-radio-button>
            </a-radio-group>
            <a-button @click="refreshDashboard">刷新</a-button>
          </a-space>
        </div>
      </template>

      <a-spin :spinning="dashboardStore.loadingTrend">
        <VChart class="trend-chart" :option="trendChartOption" autoresize />
      </a-spin>
    </a-card>
  </div>
</template>

<style scoped>
.dashboard-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.stat-card,
.trend-card {
  border-radius: 8px;
}

.trend-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.trend-chart {
  height: 360px;
}
</style>
