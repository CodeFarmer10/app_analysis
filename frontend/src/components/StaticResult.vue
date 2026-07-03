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

const receiverList = computed(() => {
  const source = Array.isArray(props.result?.receivers) ? props.result.receivers : []
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

const sourceIocGroups = computed(() => {
  return [
    {
      key: 'phone',
      label: '手机号',
      items: Array.isArray(props.result?.source_phones) ? props.result.source_phones : [],
    },
    {
      key: 'email',
      label: '邮箱',
      items: Array.isArray(props.result?.source_emails) ? props.result.source_emails : [],
    },
    {
      key: 'url',
      label: 'URL',
      items: Array.isArray(props.result?.source_urls) ? props.result.source_urls : [],
    },
  ]
})

const hasSourceIocs = computed(() => sourceIocGroups.value.some((group) => group.items.length > 0))

const sourceIocStatusText = computed(() => {
  if (props.result?.is_packed) {
    return '应用已加固，静态阶段暂不定位原始 Java 代码'
  }
  return '未发现手机号、邮箱或 URL'
})

function getComponentCountText(count) {
  return `(${count} 项)`
}

const certInfo = computed(() => {
  const info = props.result?.cert_info
  return info && typeof info === 'object' ? info : null
})

const certList = computed(() => {
  const certs = certInfo.value?.certificates
  return Array.isArray(certs) ? certs : []
})

const signatureSchemes = ['v1', 'v2', 'v3', 'v4']

const iocColumns = [
  { title: '序号', key: 'index', width: 72 },
  { title: '内容', key: 'value' },
  { title: '来源', key: 'sources' },
]

function formatPublicKey(cert) {
  if (!cert?.public_key_algorithm) {
    return '--'
  }
  return cert.public_key_bits
    ? `${cert.public_key_algorithm} (${cert.public_key_bits} bits)`
    : cert.public_key_algorithm
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
        <template #title>签名证书</template>

        <template v-if="certInfo">
          <div class="cert-badges">
            <a-tag :color="certInfo.is_signed ? 'green' : 'red'">
              {{ certInfo.is_signed ? 'APK已签名' : 'APK未签名' }}
            </a-tag>
            <a-tag
              v-for="scheme in signatureSchemes"
              :key="scheme"
              :color="certInfo.schemes && certInfo.schemes[scheme] ? 'red' : 'default'"
              :class="{ 'scheme-off': !(certInfo.schemes && certInfo.schemes[scheme]) }"
            >
              {{ scheme }}: {{ certInfo.schemes && certInfo.schemes[scheme] ? '是' : '否' }}
            </a-tag>
            <span class="cert-count">共 {{ certInfo.cert_count }} 个证书</span>
          </div>

          <div v-for="(cert, index) in certList" :key="index" class="cert-block">
            <a-descriptions :column="1" size="small">
              <a-descriptions-item label="主题">{{ cert.subject || '--' }}</a-descriptions-item>
              <a-descriptions-item label="发行人">{{ cert.issuer || '--' }}</a-descriptions-item>
              <a-descriptions-item label="签名算法">{{ cert.signature_algorithm || '--' }}</a-descriptions-item>
              <a-descriptions-item label="哈希算法">{{ cert.hash_algorithm || '--' }}</a-descriptions-item>
              <a-descriptions-item label="序列号">
                <span class="mono-text">{{ cert.serial_number || '--' }}</span>
              </a-descriptions-item>
              <a-descriptions-item label="有效期">
                {{ cert.not_before || '--' }} 至 {{ cert.not_after || '--' }}
              </a-descriptions-item>
              <a-descriptions-item label="证书MD5">
                <span class="mono-text">{{ cert.md5 || '--' }}</span>
              </a-descriptions-item>
              <a-descriptions-item label="证书SHA1">
                <span class="mono-text">{{ cert.sha1 || '--' }}</span>
              </a-descriptions-item>
              <a-descriptions-item label="证书SHA256">
                <span class="mono-text">{{ cert.sha256 || '--' }}</span>
              </a-descriptions-item>
              <a-descriptions-item label="公钥算法">{{ formatPublicKey(cert) }}</a-descriptions-item>
              <a-descriptions-item label="公钥指纹">
                <span class="mono-text">{{ cert.public_key_fingerprint || '--' }}</span>
              </a-descriptions-item>
            </a-descriptions>
          </div>
        </template>

        <a-descriptions v-else title="证书信息" :column="1" size="small">
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
        <template #title>源码线索</template>
        <a-empty v-if="!hasSourceIocs" :description="sourceIocStatusText" />
        <a-collapse v-else>
          <a-collapse-panel
            v-for="group in sourceIocGroups"
            :key="group.key"
            :header="`${group.label} ${getComponentCountText(group.items.length)}`"
          >
            <a-empty v-if="group.items.length === 0" :description="`未发现${group.label}`" />
            <a-table
              v-else
              :data-source="group.items"
              :columns="iocColumns"
              :pagination="false"
              size="small"
              :row-key="(record) => record.value"
            >
              <template #bodyCell="{ column, record, index }">
                <template v-if="column.key === 'index'">{{ index + 1 }}</template>
                <template v-else-if="column.key === 'value'">
                  <span class="mono-text ioc-value">{{ record.value }}</span>
                </template>
                <template v-else-if="column.key === 'sources'">
                  <span class="mono-text ioc-value">{{ record.sources?.length ? record.sources.join('、') : '--' }}</span>
                </template>
              </template>
            </a-table>
          </a-collapse-panel>
        </a-collapse>
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

          <a-collapse-panel key="receivers" :header="`Receiver ${getComponentCountText(receiverList.length)}`">
            <a-empty v-if="receiverList.length === 0" description="无 Receiver" />
            <div v-else class="component-list">
              <a-tag v-for="item in receiverList" :key="item">{{ item }}</a-tag>
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

.cert-badges {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-bottom: 16px;
}

.cert-count {
  color: #94a3b8;
  font-size: 13px;
}

.cert-block {
  margin-top: 16px;
}

/* "否" 的签名版本徽标：固定浅底深字，避免暗色主题下黑字看不清 */
.cert-badges .scheme-off {
  background: #f0f0f0 !important;
  border-color: #d9d9d9 !important;
  color: #595959 !important;
}

.ioc-value {
  word-break: break-all;
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
  word-break: break-all;
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
