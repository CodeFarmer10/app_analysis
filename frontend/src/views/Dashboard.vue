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
  {
    key: 'total_tasks',
    title: '总任务数',
    value: Number(dashboardStore.stats.total_tasks || 0),
    icon: 'icon-total',
    accent: 'blue',
  },
  {
    key: 'today_submitted',
    title: '今日提交任务',
    value: Number(dashboardStore.stats.today_submitted || 0),
    icon: 'icon-submit',
    accent: 'cyan',
  },
  {
    key: 'today_completed',
    title: '今日完成任务',
    value: Number(dashboardStore.stats.today_completed || 0),
    icon: 'icon-done',
    accent: 'green',
  },
  {
    key: 'analyzing_tasks',
    title: '分析中任务',
    value: Number(dashboardStore.stats.analyzing_tasks || 0),
    icon: 'icon-process',
    accent: 'amber',
  },
  {
    key: 'online_devices',
    title: '在线设备数',
    value: Number(dashboardStore.stats.online_devices || 0),
    icon: 'icon-device',
    accent: 'purple',
  },
])

const successRate = computed(() => {
  const value = Number(dashboardStore.stats.success_rate || 0)
  return Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0))
})

const successRateText = computed(() => {
  const value = successRate.value
  return Number.isInteger(value) ? `${value}` : value.toFixed(1)
})

const successCircle = computed(() => {
  const radius = 41
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (successRate.value / 100) * circumference
  return {
    dasharray: circumference,
    dashoffset: offset,
  }
})

const trendChartOption = computed(() => {
  const items = dashboardStore.trendItems || []
  const xAxis = items.map((item) => {
    const rawDate = item?.date || ''
    return typeof rawDate === 'string' && rawDate.length >= 10 ? rawDate.slice(5) : rawDate
  })
  const submitSeries = items.map((item) => Number(item?.submitted || 0))
  const completedSeries = items.map((item) => Number(item?.completed || 0))

  return {
    backgroundColor: 'transparent',
    color: ['#3b82f6', '#10b981'],
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#111827',
      borderColor: 'rgba(148, 163, 184, 0.45)',
      textStyle: {
        color: '#e2e8f0',
      },
      borderRadius: 10,
    },
    legend: {
      data: ['提交数', '完成数'],
      top: 8,
      textStyle: {
        color: '#94a3b8',
      },
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
      axisLine: {
        lineStyle: {
          color: 'rgba(148, 163, 184, 0.35)',
        },
      },
      axisLabel: {
        color: '#8ea3be',
      },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLine: {
        show: false,
      },
      splitLine: {
        lineStyle: {
          color: 'rgba(148, 163, 184, 0.16)',
        },
      },
      axisLabel: {
        color: '#8ea3be',
      },
    },
    series: [
      {
        name: '提交数',
        type: 'line',
        smooth: true,
        symbol: 'circle',
        symbolSize: 6,
        lineStyle: {
          width: 2,
        },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(59, 130, 246, 0.32)' },
              { offset: 1, color: 'rgba(59, 130, 246, 0)' },
            ],
          },
        },
        data: submitSeries,
      },
      {
        name: '完成数',
        type: 'line',
        smooth: true,
        symbol: 'circle',
        symbolSize: 6,
        lineStyle: {
          width: 2,
        },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(16, 185, 129, 0.28)' },
              { offset: 1, color: 'rgba(16, 185, 129, 0)' },
            ],
          },
        },
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
    <div class="stats-panel">
      <a-row :gutter="[16, 16]">
        <a-col v-for="card in statCards" :key="card.key" :xs="24" :sm="12" :lg="8">
          <a-card
            :bordered="false"
            :class="['stat-card', `accent-${card.accent}`]"
            :loading="dashboardStore.loadingStats"
          >
            <div class="stat-card-inner">
              <div class="stat-left">
                <div class="stat-title">{{ card.title }}</div>
                <div class="stat-number title-text" :style="{ '--target': Math.max(0, card.value) }">
                  <span class="stat-number-fallback">{{ card.value }}</span>
                </div>
              </div>
              <div class="stat-icon-wrap">
                <span class="stat-icon" :class="card.icon" />
              </div>
            </div>
          </a-card>
        </a-col>
        <a-col :xs="24" :sm="12" :lg="8">
          <a-card
            :bordered="false"
            class="stat-card success-rate-card accent-green"
            :loading="dashboardStore.loadingStats"
          >
            <div class="stat-card-inner">
              <div class="stat-left">
                <div class="stat-title">任务成功率</div>
                <div class="stat-desc">完成任务 / 总任务</div>
              </div>
              <div class="progress-ring">
                <svg viewBox="0 0 100 100" class="ring-svg">
                  <circle class="ring-bg" cx="50" cy="50" r="41" />
                  <circle
                    class="ring-fg"
                    cx="50"
                    cy="50"
                    r="41"
                    :stroke-dasharray="successCircle.dasharray"
                    :stroke-dashoffset="successCircle.dashoffset"
                  />
                </svg>
                <span class="ring-value title-text">{{ successRateText }}%</span>
              </div>
            </div>
          </a-card>
        </a-col>
      </a-row>
    </div>

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
@property --num {
  syntax: '<integer>';
  inherits: false;
  initial-value: 0;
}

.dashboard-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.stats-panel {
  padding: 4px 2px;
}

.stat-card,
.trend-card {
  border-radius: 8px;
}

.stat-card {
  transition:
    transform var(--dur-hover) ease,
    border-color var(--dur-hover) ease;
  border: 1px solid var(--border-subtle);
  overflow: hidden;
  position: relative;
}

.stat-card::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 2px;
  opacity: 0;
  transition: opacity var(--dur-hover) ease;
}

.stat-card:hover {
  transform: translateY(-2px);
  border-color: var(--border-hover);
}

.stat-card:hover::before {
  opacity: 1;
}

.stat-card.accent-blue::before {
  background: var(--accent-blue);
}

.stat-card.accent-cyan::before {
  background: var(--accent-cyan);
}

.stat-card.accent-green::before {
  background: var(--accent-green);
}

.stat-card.accent-amber::before {
  background: var(--accent-amber);
}

.stat-card.accent-purple::before {
  background: var(--accent-purple);
}

.stat-card-inner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 108px;
  gap: 12px;
}

.stat-left {
  min-width: 0;
}

.stat-title {
  color: var(--text-secondary);
  font-size: 14px;
  margin-bottom: 8px;
}

.stat-number {
  --num: 0;
  position: relative;
  margin: 0;
  font-size: 30px;
  line-height: 1.1;
  font-weight: 600;
  color: transparent;
  counter-reset: num var(--num);
  animation: count-up 900ms ease-out forwards;
}

.stat-number::before {
  content: counter(num);
  color: #f8fbff;
}

.stat-number-fallback {
  position: absolute;
  left: 0;
  top: 0;
  color: #f8fbff;
  opacity: 0;
  animation: show-fallback 900ms steps(1, end) forwards;
}

.stat-desc {
  color: #60738d;
  font-size: 12px;
}

.stat-icon-wrap {
  width: 44px;
  height: 44px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  position: relative;
}

.accent-blue .stat-icon-wrap {
  background: rgba(59, 130, 246, 0.2);
  color: #93c5fd;
}

.accent-cyan .stat-icon-wrap {
  background: rgba(6, 182, 212, 0.2);
  color: #67e8f9;
}

.accent-green .stat-icon-wrap {
  background: rgba(16, 185, 129, 0.2);
  color: #86efac;
}

.accent-amber .stat-icon-wrap {
  background: rgba(245, 158, 11, 0.2);
  color: #fcd34d;
}

.accent-purple .stat-icon-wrap {
  background: rgba(139, 92, 246, 0.2);
  color: #d8b4fe;
}

.stat-icon {
  width: 18px;
  height: 18px;
  border: 2px solid currentColor;
  border-radius: 4px;
  position: relative;
}

.icon-total::after {
  content: '';
  position: absolute;
  left: 3px;
  right: 3px;
  bottom: 3px;
  height: 2px;
  background: currentColor;
  box-shadow:
    0 -5px 0 currentColor,
    5px -3px 0 currentColor;
}

.icon-submit {
  border-radius: 50%;
}

.icon-submit::after {
  content: '';
  position: absolute;
  left: 6px;
  top: 2px;
  width: 4px;
  height: 9px;
  border-right: 2px solid currentColor;
  border-bottom: 2px solid currentColor;
  transform: rotate(45deg);
}

.icon-done {
  transform: rotate(-45deg);
  border-radius: 50%;
}

.icon-done::after {
  content: '';
  position: absolute;
  left: 6px;
  top: 3px;
  width: 4px;
  height: 8px;
  border-right: 2px solid currentColor;
  border-bottom: 2px solid currentColor;
}

.icon-process::after {
  content: '';
  position: absolute;
  left: 3px;
  top: 3px;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  border: 2px solid currentColor;
  border-left-color: transparent;
}

.icon-device::after {
  content: '';
  position: absolute;
  left: 2px;
  right: 2px;
  top: 3px;
  height: 8px;
  border: 2px solid currentColor;
  border-radius: 2px;
}

.icon-device::before {
  content: '';
  position: absolute;
  left: 5px;
  right: 5px;
  bottom: 2px;
  height: 2px;
  background: currentColor;
}

.success-rate-card .stat-card-inner {
  min-height: 108px;
}

.progress-ring {
  position: relative;
  width: 92px;
  height: 92px;
}

.ring-svg {
  width: 92px;
  height: 92px;
  transform: rotate(-90deg);
}

.ring-bg,
.ring-fg {
  fill: none;
  stroke-width: 8;
}

.ring-bg {
  stroke: rgba(148, 163, 184, 0.22);
}

.ring-fg {
  stroke: var(--accent-green);
  transition: stroke-dashoffset 0.8s ease;
  stroke-linecap: round;
}

.ring-value {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  font-size: 21px;
  font-weight: 600;
  color: #dcfce7;
}

.trend-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  color: var(--text-primary);
  font-weight: 600;
}

.trend-chart {
  height: 360px;
}

.trend-card {
  background: var(--bg-card-deep);
}

@keyframes count-up {
  from {
    --num: 0;
  }
  to {
    --num: var(--target);
  }
}

@keyframes show-fallback {
  to {
    opacity: 1;
  }
}

@media (max-width: 768px) {
  .trend-header {
    flex-direction: column;
    align-items: flex-start;
  }

  .trend-chart {
    height: 280px;
  }
}
</style>
