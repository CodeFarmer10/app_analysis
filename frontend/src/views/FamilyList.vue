<script setup>
import { onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'

import FamilyCard from '../components/FamilyCard.vue'
import { getFamilyList, getFamilyTypes } from '../api/families'

const router = useRouter()
const keyword = ref('')
const selectedType = ref(undefined)
const currentPage = ref(1)
const pageSize = 9
const families = ref([])
const total = ref(0)
const typeOptions = ref([])
const loading = ref(false)
const loadError = ref(false)
let requestSequence = 0

async function loadFamilies() {
  const sequence = ++requestSequence
  loading.value = true
  loadError.value = false
  try {
    const data = await getFamilyList({
      keyword: keyword.value.trim() || undefined,
      type: selectedType.value,
      page: currentPage.value,
      size: pageSize,
    })
    if (sequence !== requestSequence) return
    families.value = data?.items || []
    total.value = data?.total || 0
  } catch {
    if (sequence !== requestSequence) return
    families.value = []
    total.value = 0
    loadError.value = true
  } finally {
    if (sequence === requestSequence) loading.value = false
  }
}

watch([keyword, selectedType], () => {
  if (currentPage.value !== 1) currentPage.value = 1
  else void loadFamilies()
})
watch(currentPage, () => { void loadFamilies() })

onMounted(async () => {
  void loadFamilies()
  try {
    const data = await getFamilyTypes()
    typeOptions.value = (data?.items || []).map((type) => ({ label: type, value: type }))
  } catch {
    typeOptions.value = []
  }
})

function openFamily(family) {
  void router.push(`/families/${encodeURIComponent(family.id)}`)
}
</script>

<template>
  <div class="family-page">
    <div class="family-toolbar">
      <a-input v-model:value="keyword" allow-clear placeholder="搜索家族名称或简介" class="family-search" />
      <a-select
        v-model:value="selectedType"
        allow-clear
        placeholder="全部诈骗类型"
        :options="typeOptions"
        class="family-type-filter"
      />
      <span class="result-count">共 {{ total }} 个家族</span>
    </div>

    <a-spin :spinning="loading">
      <a-result v-if="loadError" status="error" title="家族列表加载失败">
        <template #extra><a-button @click="loadFamilies">重试</a-button></template>
      </a-result>
      <a-empty v-else-if="!loading && families.length === 0" description="暂无符合条件的家族" />
      <template v-else>
        <div class="family-grid">
          <FamilyCard v-for="family in families" :key="family.id" :family="family" @view="openFamily" />
        </div>
        <a-pagination
          v-model:current="currentPage"
          class="family-pagination"
          :total="total"
          :page-size="pageSize"
          :show-size-changer="false"
        />
      </template>
    </a-spin>
  </div>
</template>

<style src="./family.css"></style>
