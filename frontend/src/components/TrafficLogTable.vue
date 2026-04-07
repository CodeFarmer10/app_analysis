<script setup>
import { computed } from 'vue'
import { message } from 'ant-design-vue'

const props = defineProps({
  items: {
    type: Array,
    default: () => [],
  },
  total: {
    type: Number,
    default: 0,
  },
  page: {
    type: Number,
    default: 1,
  },
  size: {
    type: Number,
    default: 20,
  },
  loading: {
    type: Boolean,
    default: false,
  },
})

const emit = defineEmits(['change'])

const protocolFilters = computed(() => {
  const values = Array.from(
    new Set(
      (props.items || [])
        .map((item) => item?.protocol)
        .filter(Boolean)
    )
  )
  return values.map((item) => ({ text: item, value: item }))
})

const columns = computed(() => [
  { title: '序号', dataIndex: 'seq', key: 'seq', width: 80 },
  { title: '源IP', dataIndex: 'src_ip', key: 'src_ip', width: 140 },
  { title: '目的IP', dataIndex: 'dst_ip', key: 'dst_ip', width: 140 },
  { title: '源端口', dataIndex: 'src_port', key: 'src_port', width: 100 },
  {
    title: '目的端口',
    dataIndex: 'dst_port',
    key: 'dst_port',
    width: 100,
    customHeaderCell: () => ({ class: 'nowrap-header-cell' }),
  },
  {
    title: '协议',
    dataIndex: 'protocol',
    key: 'protocol',
    width: 120,
    filters: protocolFilters.value,
    onFilter: (value, record) => (record?.protocol || '') === value,
  },
  { title: '域名', dataIndex: 'domain', key: 'domain', width: 180 },
  { title: 'URL', dataIndex: 'url', key: 'url', width: 300 },
  {
    title: '解析IP',
    dataIndex: 'resolved_ip',
    key: 'resolved_ip',
    width: 160,
    customHeaderCell: () => ({ class: 'nowrap-header-cell' }),
  },
])

const pagination = computed(() => ({
  current: props.page,
  pageSize: props.size,
  total: props.total,
  showSizeChanger: true,
  showTotal: (total) => `共 ${total} 条`,
}))

function copyText(value) {
  if (!value) {
    return
  }

  if (navigator?.clipboard?.writeText) {
    navigator.clipboard
      .writeText(value)
      .then(() => {
        message.success('URL 已复制')
      })
      .catch(() => {
        message.error('复制失败，请手动复制')
      })
    return
  }

  try {
    const input = document.createElement('textarea')
    input.value = value
    document.body.appendChild(input)
    input.select()
    document.execCommand('copy')
    document.body.removeChild(input)
    message.success('URL 已复制')
  } catch (_error) {
    message.error('复制失败，请手动复制')
  }
}

function handleTableChange(pager) {
  emit('change', {
    page: pager.current || 1,
    size: pager.pageSize || props.size,
  })
}
</script>

<template>
  <a-table
    row-key="id"
    :columns="columns"
    :data-source="items"
    :loading="loading"
    :pagination="pagination"
    :scroll="{ x: 1400 }"
    @change="handleTableChange"
  >
    <template #bodyCell="{ column, text }">
      <template v-if="column.key === 'protocol'">
        <span class="protocol-badge" :class="`protocol-${String(text || '').toLowerCase()}`">
          {{ text || '--' }}
        </span>
      </template>
      <template v-else-if="column.key === 'url' || column.key === 'domain'">
        <div class="url-cell">
          <a-typography-text class="url-text" :ellipsis="{ tooltip: text || '--' }">
            {{ text || '--' }}
          </a-typography-text>
          <a-button v-if="column.key === 'url' && text" type="link" size="small" @click="copyText(text)">
            复制
          </a-button>
        </div>
      </template>
      <template v-else-if="column.key === 'resolved_ip'">
        <span class="mono-text resolved-ip-text">{{ text || '--' }}</span>
      </template>
      <template v-else>
        <span class="mono-text">{{ text || '--' }}</span>
      </template>
    </template>
  </a-table>
</template>

<style scoped>
.nowrap-header-cell {
  white-space: nowrap;
}

.url-cell {
  display: flex;
  align-items: center;
  gap: 6px;
}

.url-text {
  max-width: 220px;
  color: #f8fafc !important;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 4px;
  border: 1px solid rgba(96, 165, 250, 0.42);
  background: rgba(59, 130, 246, 0.14);
}

.url-text:hover {
  border-color: rgba(191, 219, 254, 0.88);
  background: rgba(59, 130, 246, 0.24);
}

.url-cell :deep(.ant-btn-link) {
  color: #93c5fd;
  font-weight: 600;
}

.url-cell :deep(.ant-btn-link:hover) {
  color: #dbeafe;
}

.resolved-ip-text {
  color: #67e8f9;
  font-weight: 700;
}

.protocol-badge {
  display: inline-block;
  min-width: 56px;
  text-align: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  border: 1px solid rgba(148, 163, 184, 0.4);
  background: rgba(148, 163, 184, 0.15);
  color: #d1d9e4;
}

.protocol-http,
.protocol-https {
  border-color: rgba(59, 130, 246, 0.45);
  background: rgba(59, 130, 246, 0.16);
  color: #bfdbfe;
}

.protocol-tcp {
  border-color: rgba(139, 92, 246, 0.45);
  background: rgba(139, 92, 246, 0.16);
  color: #ddd6fe;
}

.protocol-udp {
  border-color: rgba(245, 158, 11, 0.46);
  background: rgba(245, 158, 11, 0.16);
  color: #fcd34d;
}

.protocol-dns {
  border-color: rgba(16, 185, 129, 0.5);
  background: rgba(16, 185, 129, 0.16);
  color: #a7f3d0;
}
</style>
