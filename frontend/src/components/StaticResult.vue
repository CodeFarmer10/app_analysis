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

const soFileGroups = computed(() => {
  const grouped = new Map()
  for (const item of soFileList.value) {
    const matched =
      item.match(/(?:^|\/)(arm64-v8a|armeabi-v7a|armeabi|x86_64|x86|mips64|mips)(?:\/|$)/i)?.[1] ||
      'unknown'
    const key = matched.toLowerCase()
    if (!grouped.has(key)) {
      grouped.set(key, [])
    }
    grouped.get(key).push(item)
  }
  return Array.from(grouped.entries()).map(([arch, files]) => ({ arch, files }))
})

const packerVendorList = computed(() => {
  const source = Array.isArray(props.result?.packer_vendors) ? props.result.packer_vendors : []
  return source
    .map((item) => item?.product || item?.name_cn || item?.name_en || '')
    .filter(Boolean)
})

const obfuscationVendorList = computed(() => {
  const source = Array.isArray(props.result?.obfuscation_vendors) ? props.result.obfuscation_vendors : []
  return source
    .map((item) => item?.product || item?.name_cn || item?.name_en || '')
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
                <span class="mono-text">{{ result.package_name || '--' }}</span>
              </a-descriptions-item>
              <a-descriptions-item label="版本">
                <span class="mono-text">{{ result.version_name || '--' }} / {{ result.version_code || '--' }}</span>
              </a-descriptions-item>
              <a-descriptions-item label="文件MD5">
                <span class="mono-text">{{ task.file_md5 || '--' }}</span>
              </a-descriptions-item>
              <a-descriptions-item label="文件大小">
                {{ formatFileSize(task.file_size) }}
              </a-descriptions-item>
              <a-descriptions-item label="开发框架">
                {{ result.framework_name || '--' }}
              </a-descriptions-item>
              <a-descriptions-item label="是否加固">
                <a-tag :color="result.is_packed ? 'red' : 'green'">{{ result.is_packed ? '是' : '否' }}</a-tag>
              </a-descriptions-item>
              <a-descriptions-item label="加固类型">
                {{ result.packer_vendor || packerVendorList.join('、') || '--' }}
              </a-descriptions-item>
              <a-descriptions-item label="是否混淆">
                <a-tag :color="result.is_obfuscated ? 'orange' : 'green'">
                  {{ result.is_obfuscated ? '是' : '否' }}
                </a-tag>
              </a-descriptions-item>
              <a-descriptions-item label="混淆类型">
                {{ result.obfuscation_vendor || obfuscationVendorList.join('、') || '--' }}
              </a-descriptions-item>
              <a-descriptions-item v-if="result.is_packed" label="脱壳结果">
                <a v-if="result.unpack_archive_path" :href="result.unpack_archive_path" target="_blank" rel="noreferrer">
                  下载脱壳压缩包
                </a>
                <span v-else>--</span>
              </a-descriptions-item>
            </a-descriptions>
          </a-col>
        </a-row>
      </a-card>

      <a-card :bordered="false" class="section-card">
        <a-descriptions title="证书信息" :column="1" size="small">
          <a-descriptions-item label="证书MD5">
            <span class="mono-text">{{ result.cert_md5 || '--' }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="证书SHA1">
            <span class="mono-text">{{ result.cert_sha1 || '--' }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="证书SHA256">
            <span class="mono-text">{{ result.cert_sha256 || '--' }}</span>
          </a-descriptions-item>
        </a-descriptions>
      </a-card>

      <a-card :bordered="false" class="section-card">
        <template #title>权限清单</template>
        <a-empty v-if="permissionList.length === 0" description="无权限数据" />
        <div v-else class="permission-list">
          <div
            v-for="item in permissionList"
            :key="item.name"
            class="permission-tag"
            :class="{ dangerous: item.is_dangerous }"
          >
            <span v-if="item.is_dangerous" class="shield-mini" aria-hidden="true" />
            <span class="mono-text">{{ item.name }}</span>
            <span v-if="item.is_dangerous">（危险）</span>
          </div>
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
        <a-empty v-if="soFileGroups.length === 0" description="无 SO 文件" />
        <div v-else class="so-group-list">
          <div v-for="group in soFileGroups" :key="group.arch" class="so-group">
            <div class="so-group-title mono-text">{{ group.arch }}</div>
            <div class="component-list">
              <a-tag v-for="item in group.files" :key="item">
                <span class="mono-text">{{ item }}</span>
              </a-tag>
            </div>
          </div>
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

.icon-wrap :deep(.ant-image-img) {
  border-radius: 12px;
  border: 1px solid var(--border-normal);
}

.section-card :deep(.ant-descriptions-title) {
  color: var(--text-primary);
}

.section-card :deep(.ant-descriptions-item-content) {
  color: #d7e3ef;
}

.permission-list,
.component-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.component-list :deep(.ant-tag) {
  border: 1px solid rgba(148, 163, 184, 0.4);
  background: rgba(148, 163, 184, 0.14);
  color: #e2ebf5;
}

.component-list :deep(.ant-tag-blue) {
  border-color: rgba(59, 130, 246, 0.45);
  background: rgba(59, 130, 246, 0.18);
  color: #bfdbfe;
}

.permission-tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-height: 28px;
  padding: 2px 10px;
  border-radius: 6px;
  border: 1px solid var(--border-subtle);
  background: rgba(148, 163, 184, 0.14);
  color: #d7e3ef;
  font-size: 12px;
}

.permission-tag.dangerous {
  border-color: rgba(239, 68, 68, 0.44);
  background: rgba(239, 68, 68, 0.14);
  color: #fecaca;
}

.shield-mini {
  width: 12px;
  height: 12px;
  border: 1px solid currentColor;
  border-radius: 4px;
  position: relative;
}

.shield-mini::after {
  content: '';
  position: absolute;
  left: 3px;
  top: 2px;
  width: 4px;
  height: 6px;
  border: 1px solid currentColor;
  clip-path: polygon(50% 0%, 100% 18%, 100% 64%, 50% 100%, 0 64%, 0 18%);
}

.so-group-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.so-group {
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 10px;
  background: rgba(255, 255, 255, 0.02);
}

.so-group-title {
  color: #c4d6ea;
  margin-bottom: 8px;
  font-size: 12px;
  font-weight: 600;
}
</style>
