<script setup>
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { message, Modal } from 'ant-design-vue'
import { useRouter } from 'vue-router'

import {
  approveFamilyRecommendation,
  generateFamilyRecommendations,
  getFamilyRecommendation,
  getFamilyRecommendationJob,
  getFamilyRecommendations,
  getFamilyRecommendationTypes,
  getFamilyTypes,
  rejectFamilyRecommendation,
} from '../api/families'
import FamilyCard from '../components/FamilyCard.vue'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const authStore = useAuthStore()
const activeTab = ref('auto')
const typeOptions = ref([])
const recommendationTypeOptions = ref([])
const manualForm = reactive({ name: '', description: '', type: undefined })
const reviewForm = reactive({ name: '', description: '', type_code: undefined })
const candidates = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = 9
const loading = ref(false)
const loadError = ref(false)
const jobId = ref(localStorage.getItem('familyRecommendationJobId') || '')
const jobStatus = ref('')
const jobProgress = ref(null)
const jobError = ref('')
const selected = ref(null)
const ruleOpen = ref(false)
const reviewOpen = ref(false)
const saving = ref(false)
let pollTimer = null
let polling = false

async function loadCandidates() {
  loading.value = true
  loadError.value = false
  try {
    const data = await getFamilyRecommendations({ page: page.value, size: pageSize })
    candidates.value = data?.items || []
    total.value = data?.total || 0
  } catch {
    candidates.value = []
    total.value = 0
    loadError.value = true
  } finally {
    loading.value = false
  }
}

async function pollJob() {
  if (!jobId.value || polling) return
  polling = true
  try {
    const job = await getFamilyRecommendationJob(jobId.value)
    jobStatus.value = job?.status || ''
    const previousProcessed = jobProgress.value?.processedFamilies
    jobProgress.value = job?.progress || null
    if (jobStatus.value === 'PROGRESS' && jobProgress.value?.processedFamilies !== previousProcessed) void loadCandidates()
    if (jobStatus.value === 'SUCCESS' || jobStatus.value === 'FAILURE' || jobStatus.value === 'REVOKED') {
      if (jobStatus.value === 'SUCCESS') {
        const count = job?.result?.savedCandidates ?? 0
        message.success(`推荐生成完成，保存 ${count} 个候选家族`)
        page.value = 1
        await loadCandidates()
      } else {
        jobError.value = job?.error || '推荐生成失败'
      }
      localStorage.removeItem('familyRecommendationJobId')
      jobId.value = ''
      clearInterval(pollTimer)
      pollTimer = null
    }
  } catch (error) {
    jobError.value = error?.message || '无法获取生成进度'
    clearInterval(pollTimer)
    pollTimer = null
  } finally {
    polling = false
  }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer)
  void pollJob()
  pollTimer = setInterval(() => { void pollJob() }, 3000)
}

async function generate() {
  jobError.value = ''
  try {
    const data = await generateFamilyRecommendations()
    jobId.value = data.jobId
    jobStatus.value = 'PENDING'
    localStorage.setItem('familyRecommendationJobId', jobId.value)
    startPolling()
  } catch (error) {
    jobError.value = error?.message || '无法启动推荐任务'
  }
}

async function openCandidate(candidate, mode) {
  if (mode === 'detail') {
    await router.push(`/families/recommendations/${encodeURIComponent(candidate.id)}`)
    return
  }
  try {
    selected.value = await getFamilyRecommendation(candidate.id)
    if (mode === 'rule') {
      ruleOpen.value = true
    } else {
      reviewForm.name = selected.value.name || ''
      reviewForm.description = selected.value.description || ''
      reviewForm.type_code = selected.value.typeCode || undefined
      reviewOpen.value = true
    }
  } catch {
    message.error('候选家族加载失败')
  }
}

async function approve() {
  if (!selected.value || !reviewForm.name.trim() || !reviewForm.type_code) {
    message.warning('请填写模型名称并选择诈骗类型')
    return
  }
  saving.value = true
  try {
    const data = await approveFamilyRecommendation(selected.value.id, {
      name: reviewForm.name.trim(),
      description: reviewForm.description.trim(),
      type_code: reviewForm.type_code,
    })
    reviewOpen.value = false
    message.success('模型已入库，关联 APP 已更新')
    await router.push(`/families/${encodeURIComponent(data.modelId)}`)
  } catch {
    await loadCandidates()
  } finally {
    saving.value = false
  }
}

function reject() {
  if (!selected.value) return
  const id = selected.value.id
  Modal.confirm({
    title: '拒绝这个候选家族？',
    content: '拒绝后，该候选将从待审核列表移除。',
    okText: '拒绝',
    okType: 'danger',
    cancelText: '取消',
    onOk: async () => {
      await rejectFamilyRecommendation(id)
      reviewOpen.value = false
      message.success('已拒绝候选家族')
      await loadCandidates()
    },
  })
}

onMounted(async () => {
  try {
    const data = await getFamilyTypes()
    typeOptions.value = (data?.items || []).map((type) => ({ label: type, value: type }))
  } catch {
    typeOptions.value = []
  }
  void loadCandidates()
  if (authStore.isAdmin) {
    try {
      const data = await getFamilyRecommendationTypes()
      recommendationTypeOptions.value = (data?.items || []).map((item) => ({ label: item.name, value: item.code }))
    } catch {
      recommendationTypeOptions.value = []
    }
    if (jobId.value) startPolling()
  }
})

onBeforeUnmount(() => { if (pollTimer) clearInterval(pollTimer) })
</script>

<template>
  <div class="family-page">
    <a-tabs v-model:activeKey="activeTab" class="family-tabs">
      <a-tab-pane key="auto" :tab="`自动推荐 (${total})`">
        <div class="family-toolbar">
            <a-button v-if="authStore.isAdmin" type="primary" :loading="Boolean(jobId)" :disabled="Boolean(jobId)" @click="generate">生成推荐</a-button>
            <a-button @click="loadCandidates">刷新</a-button>
            <span class="result-count">共 {{ total }} 个待审核候选</span>
          </div>
          <a-alert
            v-if="jobId && authStore.isAdmin"
            type="info"
            show-icon
            :message="jobProgress ? `推荐任务正在运行：${jobProgress.processedFamilies}/${jobProgress.totalFamilies} 个家族已处理` : `推荐任务正在运行（${jobStatus || 'PENDING'}）`"
            class="family-notice"
          />
          <a-alert v-if="jobError && authStore.isAdmin" type="error" show-icon :message="jobError" class="family-notice" />
          <a-spin :spinning="loading">
            <a-result v-if="loadError" status="error" title="自动推荐加载失败">
              <template #extra><a-button @click="loadCandidates">重试</a-button></template>
            </a-result>
            <a-empty v-else-if="!loading && candidates.length === 0" description="暂无待审核候选" />
            <template v-else>
              <div class="family-grid">
                <FamilyCard
                  v-for="candidate in candidates"
                  :key="candidate.id"
                  :family="candidate"
                  :candidate="authStore.isAdmin"
                  :review-disabled="candidate.status !== 'pending'"
                  @view="openCandidate(candidate, 'detail')"
                  @rule="openCandidate(candidate, 'rule')"
                  @review="openCandidate(candidate, 'review')"
                />
              </div>
              <a-pagination
                v-if="total > pageSize"
                v-model:current="page"
                class="family-pagination"
                :total="total"
                :page-size="pageSize"
                :show-size-changer="false"
                @change="loadCandidates"
              />
            </template>
          </a-spin>
      </a-tab-pane>

      <a-tab-pane key="manual" tab="手动添加">
        <div class="manual-section">
          <a-alert type="info" show-icon message="手动新增家族尚未开放" class="family-notice" />
          <div class="family-section-heading"><h2>填写家族信息</h2></div>
          <a-form :model="manualForm" layout="vertical" class="family-form">
            <a-form-item label="家族名称" name="name" required>
              <a-input v-model:value="manualForm.name" :maxlength="255" show-count placeholder="请输入家族名称" />
            </a-form-item>
            <a-form-item label="家族简介" name="description">
              <a-textarea v-model:value="manualForm.description" :rows="4" :maxlength="500" show-count placeholder="简要说明该家族的共同特征" />
            </a-form-item>
            <a-form-item label="诈骗类型" name="type" required>
              <a-select v-model:value="manualForm.type" placeholder="请选择诈骗类型" :options="typeOptions" />
            </a-form-item>
            <a-button type="primary" disabled>创建家族</a-button>
          </a-form>
        </div>
      </a-tab-pane>
    </a-tabs>

    <a-modal v-model:open="ruleOpen" title="推荐模型规则" width="min(800px, calc(100vw - 32px))" :footer="null">
      <div v-if="selected" class="rule-detail">
        <div><span>候选家族</span><p>{{ selected.name || selected.familyKey }}</p></div>
        <div><span>规则表达式</span><pre class="candidate-rule">{{ selected.rule }}</pre></div>
      </div>
    </a-modal>

    <a-modal v-model:open="reviewOpen" title="审核推荐模型" :confirm-loading="saving" ok-text="入库" @ok="approve">
      <a-form :model="reviewForm" layout="vertical" class="family-form">
        <a-form-item label="模型名称" required>
          <a-input v-model:value="reviewForm.name" :maxlength="255" show-count />
        </a-form-item>
        <a-form-item label="家族简介">
          <a-textarea v-model:value="reviewForm.description" :rows="3" :maxlength="500" show-count />
        </a-form-item>
        <a-form-item label="诈骗类型" required>
          <a-select v-model:value="reviewForm.type_code" :options="recommendationTypeOptions" placeholder="请选择诈骗类型" />
        </a-form-item>
      </a-form>
      <a-button danger @click="reject">拒绝候选</a-button>
    </a-modal>
  </div>
</template>

<style src="./family.css"></style>
<style scoped>
.family-notice { margin-bottom: 16px; }
.candidate-rule { max-height: 440px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; color: var(--text-primary); }
</style>
