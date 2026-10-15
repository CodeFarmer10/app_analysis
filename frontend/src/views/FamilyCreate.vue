<script setup>
import { onMounted, reactive, ref } from 'vue'

import { getFamilyTypes } from '../api/families'

const activeTab = ref('auto')
const typeOptions = ref([])
const manualForm = reactive({ name: '', description: '', type: undefined })

onMounted(async () => {
  try {
    const data = await getFamilyTypes()
    typeOptions.value = (data?.items || []).map((type) => ({ label: type, value: type }))
  } catch {
    typeOptions.value = []
  }
})
</script>

<template>
  <div class="family-page">
    <a-alert
      type="info"
      show-icon
      message="新增家族与自动推荐审核尚未接入后端，当前不能入库。"
    />
    <a-tabs v-model:activeKey="activeTab" class="family-tabs">
      <a-tab-pane key="auto" tab="自动推荐 (0)">
        <a-empty description="暂无待审核候选" />
      </a-tab-pane>

      <a-tab-pane key="manual" tab="手动添加">
        <div class="manual-section">
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
  </div>
</template>

<style src="./family.css"></style>
