<script setup>
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import TaskRecordsTable from '../components/TaskRecordsTable.vue'
import {
  getFamilyDetail,
  getFamilyMembers,
  getFamilyRecommendation,
  getFamilyRecommendationMembers,
} from '../api/families'
import { getTaskApkDownload, getTaskPcapDownload, getTaskReportDownload } from '../api/tasks'
import { formatDateTime } from '../utils/format'

const route = useRoute()
const router = useRouter()
const isRecommendation = computed(() => route.meta.familySource === 'recommendation')
const detailId = computed(() => String(route.params.familyId || ''))
const family = ref(null)
const members = ref([])
const memberTotal = ref(0)
const memberPage = ref(1)
const memberPageSize = 20
const familyLoading = ref(false)
const membersLoading = ref(false)
const familyError = ref('')
const membersError = ref(false)
let familyRequestSequence = 0
let memberRequestSequence = 0

const memberPagination = computed(() => ({
  current: memberPage.value,
  pageSize: memberPageSize,
  total: memberTotal.value,
  showSizeChanger: false,
}))

async function loadMembers(modelId) {
  const sequence = ++memberRequestSequence
  membersLoading.value = true
  membersError.value = false
  try {
    const loader = isRecommendation.value ? getFamilyRecommendationMembers : getFamilyMembers
    const data = await loader(modelId, { page: memberPage.value, size: memberPageSize })
    if (sequence !== memberRequestSequence || detailId.value !== modelId) return
    members.value = data?.items || []
    memberTotal.value = data?.total || 0
  } catch {
    if (sequence !== memberRequestSequence) return
    members.value = []
    membersError.value = true
  } finally {
    if (sequence === memberRequestSequence) membersLoading.value = false
  }
}

async function loadFamily(modelId) {
  const sequence = ++familyRequestSequence
  family.value = null
  members.value = []
  memberTotal.value = 0
  memberPage.value = 1
  familyLoading.value = true
  familyError.value = ''
  try {
    const loader = isRecommendation.value ? getFamilyRecommendation : getFamilyDetail
    const data = await loader(modelId)
    if (sequence !== familyRequestSequence || detailId.value !== modelId) return
    family.value = data
    void loadMembers(modelId)
  } catch (error) {
    if (sequence === familyRequestSequence) {
      familyError.value = error?.message === '家族不存在' ? '家族不存在' : '家族详情加载失败'
    }
  } finally {
    if (sequence === familyRequestSequence) familyLoading.value = false
  }
}

function handlePageChange(pager) {
  memberPage.value = pager.current || 1
  void loadMembers(detailId.value)
}

function openTask(taskId) {
  void router.push(`/tasks/${taskId}`)
}

async function handleDownload(taskId, type) {
  const task = members.value.find((item) => item.id === taskId)
  const fetcher = {
    apk: getTaskApkDownload,
    report: getTaskReportDownload,
    pcap: getTaskPcapDownload,
  }[type]
  if (!fetcher || task?.[`can_download_${type}`] !== true) return
  const data = await fetcher(taskId)
  if (data?.download_url) window.open(data.download_url, '_blank', 'noopener')
}

watch(
  () => [route.meta.familySource, route.params.familyId],
  ([, modelId]) => { void loadFamily(modelId) },
  { immediate: true },
)
</script>

<template>
  <div class="family-page">
    <a-breadcrumb class="family-breadcrumb">
      <a-breadcrumb-item>
        <router-link :to="isRecommendation ? '/families/new' : '/families'">
          {{ isRecommendation ? '新增家族' : '家族列表' }}
        </router-link>
      </a-breadcrumb-item>
      <a-breadcrumb-item>{{ family?.name || (isRecommendation ? '自动推荐详情' : '家族详情') }}</a-breadcrumb-item>
    </a-breadcrumb>

    <a-spin v-if="familyLoading" :spinning="true" class="family-loading" />
    <a-result v-else-if="familyError" status="error" :title="familyError">
      <template #extra>
        <a-button v-if="familyError === '家族不存在'" @click="router.push(isRecommendation ? '/families/new' : '/families')">
          {{ isRecommendation ? '返回新增家族' : '返回家族列表' }}
        </a-button>
        <a-button v-else @click="loadFamily(detailId)">重试</a-button>
      </template>
    </a-result>

    <template v-else-if="family">
      <div class="family-page-header detail-header">
        <div>
          <h1>{{ family.name }}</h1>
          <p class="family-subtitle">{{ family.description || '暂无家族简介' }}</p>
        </div>
        <a-tag color="blue" class="detail-type">{{ family.type || '待确认' }}</a-tag>
      </div>

      <div class="family-overview">
        <div><span>关联数量</span><strong>{{ family.count ?? 0 }}</strong></div>
        <div><span>最近关联任务时间</span><strong>{{ formatDateTime(family.latestTaskAt) }}</strong></div>
        <div><span>关联来源</span><strong>{{ isRecommendation ? '自动推荐' : '模型关联' }}</strong></div>
      </div>

      <section class="family-detail-section">
        <div class="family-section-heading"><h2>关联模型</h2></div>
        <div class="rule-summary">
          {{ family.name }}（{{ isRecommendation ? `候选编号：${family.id}` : `模型编号：${family.modelId}` }}）
        </div>
        <div v-if="isRecommendation" class="candidate-detail-meta">
          <span>框架：{{ family.frameworkName || '未知' }}</span>
          <span>聚类阶段：{{ family.clusterStage || '未知' }}</span>
          <span v-if="family.minPairSimilarity != null">家族内最小相似度：{{ Number(family.minPairSimilarity).toFixed(4) }}</span>
          <span v-if="family.status">状态：{{ family.status }}</span>
        </div>
        <a-alert v-if="isRecommendation && family.failureReason" type="warning" show-icon :message="family.failureReason" class="family-notice" />
      </section>

      <section class="family-detail-section">
        <div class="family-section-heading">
          <h2>关联任务</h2>
          <span class="result-count">共 {{ memberTotal }} 条任务</span>
        </div>
        <a-spin :spinning="membersLoading">
          <a-result v-if="membersError" status="error" title="关联任务加载失败">
            <template #extra><a-button @click="loadMembers(detailId)">重试</a-button></template>
          </a-result>
          <a-empty v-else-if="!membersLoading && members.length === 0" description="暂无可查看的关联任务" />
          <TaskRecordsTable
            v-else
            :tasks="members"
            :pagination="memberPagination"
            show-md5
            compact
            @change="handlePageChange"
            @view="openTask"
            @download="handleDownload"
          />
        </a-spin>
      </section>
    </template>
  </div>
</template>

<style src="./family.css"></style>
<style scoped>
.candidate-detail-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 20px;
  margin-top: 12px;
  color: var(--text-secondary);
}
</style>
