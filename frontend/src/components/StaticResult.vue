<script setup>
import { computed } from 'vue'

import { formatFileSize } from '../utils/format'

const props = defineProps({
  task: {
    type: Object,
    default: () => ({}),
  },
  result: {
    type: Object,
    default: () => null,
  },
  loading: {
    type: Boolean,
    default: false,
  },
})

const permissionList = computed(() => {
  const source = Array.isArray(props.result?.permissions) ? props.result.permissions : []
  return source
    .map((item) => {
      if (typeof item === 'string') {
        return { name: item, is_dangerous: false }
      }
      return {
        name: item?.name || '',
        is_dangerous: Boolean(item?.is_dangerous),
      }
    })
    .filter((item) => item.name)
})

const activityList = computed(() => {
  const source = Array.isArray(props.result?.activities) ? props.result.activities : []
  return source
    .map((item) => {
      if (typeof item === 'string') {
        return { name: item, is_launcher: false }
      }
      return {
        name: item?.name || '',
        is_launcher: Boolean(item?.is_launcher),
      }
    })
    .filter((item) => item.name)
})

const serviceList = computed(() => {
  const source = Array.isArray(props.result?.services) ? props.result.services : []
  return source
    .map((item) => (typeof item === 'string' ? item : item?.name || ''))
    .filter(Boolean)
})

const providerList = computed(() => {
  const source = Array.isArray(props.result?.providers) ? props.result.providers : []
  return source
    .map((item) => (typeof item === 'string' ? item : item?.name || ''))
    .filter(Boolean)
})

const soFileList = computed(() => {
  const source = Array.isArray(props.result?.so_files) ? props.result.so_files : []
  return source
    .map((item) => (typeof item === 'string' ? item : item?.name || ''))
    .filter(Boolean)
})

function getComponentCountText(count) {
  return `(${count} 项)`
}
</script>

<template>
  <a-spin :spinning="loading">
    <a-empty v-if="!result" description="静态分析结果暂未生成" />
    <div v-else class="static-result">
      <a-card :bordered="false" class="section-card">
        <a-row :gutter="24" align="middle">
          <a-col :xs="24" :md="6" :lg="5">
            <div class="icon-wrap">
              <a-image v-if="result.icon_url" :src="result.icon_url" :width="120" />
              <a-avatar v-else shape="square" :size="120">
                {{ result.app_name?.slice(0, 1) || 'APP' }}
              </a-avatar>
            </div>
          </a-col>
          <a-col :xs="24" :md="18" :lg="19">
            <a-descriptions title="基础信息" :column="2" size="small">
              <a-descriptions-item label="APP名称">
                {{ result.app_name || '--' }}
              </a-descriptions-item>
              <a-descriptions-item label="包名">
                {{ result.package_name || '--' }}
              </a-descriptions-item>
              <a-descriptions-item label="版本">
                {{ result.version_name || '--' }} / {{ result.version_code || '--' }}
              </a-descriptions-item>
              <a-descriptions-item label="文件MD5">
                {{ task.file_md5 || '--' }}
              </a-descriptions-item>
              <a-descriptions-item label="文件大小">
                {{ formatFileSize(task.file_size) }}
              </a-descriptions-item>
            </a-descriptions>
          </a-col>
        </a-row>
      </a-card>

      <a-card :bordered="false" class="section-card">
        <a-descriptions title="证书信息" :column="1" size="small">
          <a-descriptions-item label="证书MD5">
            {{ result.cert_md5 || '--' }}
          </a-descriptions-item>
          <a-descriptions-item label="证书SHA1">
            {{ result.cert_sha1 || '--' }}
          </a-descriptions-item>
          <a-descriptions-item label="证书SHA256">
            {{ result.cert_sha256 || '--' }}
          </a-descriptions-item>
        </a-descriptions>
      </a-card>

      <a-card :bordered="false" class="section-card">
        <template #title>权限清单</template>
        <a-empty v-if="permissionList.length === 0" description="无权限数据" />
        <div v-else class="permission-list">
          <a-tag
            v-for="item in permissionList"
            :key="item.name"
            :color="item.is_dangerous ? 'red' : 'default'"
          >
            {{ item.name }}<span v-if="item.is_dangerous">（危险）</span>
          </a-tag>
        </div>
      </a-card>

      <a-card :bordered="false" class="section-card">
        <template #title>组件列表</template>
        <a-collapse>
          <a-collapse-panel key="activities" :header="`Activity ${getComponentCountText(activityList.length)}`">
            <a-empty v-if="activityList.length === 0" description="无 Activity" />
            <div v-else class="component-list">
              <a-tag v-for="item in activityList" :key="item.name" color="blue">
                {{ item.name }}<span v-if="item.is_launcher">（入口）</span>
              </a-tag>
            </div>
          </a-collapse-panel>

          <a-collapse-panel key="services" :header="`Service ${getComponentCountText(serviceList.length)}`">
            <a-empty v-if="serviceList.length === 0" description="无 Service" />
            <div v-else class="component-list">
              <a-tag v-for="item in serviceList" :key="item">{{ item }}</a-tag>
            </div>
          </a-collapse-panel>

          <a-collapse-panel key="providers" :header="`Provider ${getComponentCountText(providerList.length)}`">
            <a-empty v-if="providerList.length === 0" description="无 Provider" />
            <div v-else class="component-list">
              <a-tag v-for="item in providerList" :key="item">{{ item }}</a-tag>
            </div>
          </a-collapse-panel>
        </a-collapse>
      </a-card>

      <a-card :bordered="false" class="section-card">
        <template #title>SO 文件</template>
        <a-empty v-if="soFileList.length === 0" description="无 SO 文件" />
        <div v-else class="component-list">
          <a-tag v-for="item in soFileList" :key="item">{{ item }}</a-tag>
        </div>
      </a-card>
    </div>
  </a-spin>
</template>

<style scoped>
.static-result {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.section-card {
  border-radius: 8px;
}

.icon-wrap {
  display: flex;
  justify-content: center;
  margin-bottom: 12px;
}

.permission-list,
.component-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
</style>
