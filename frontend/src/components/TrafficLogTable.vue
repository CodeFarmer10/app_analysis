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
  { title: '目的端口', dataIndex: 'dst_port', key: 'dst_port', width: 100 },
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
  { title: '解析IP', dataIndex: 'resolved_ip', key: 'resolved_ip', width: 160 },
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
      <template v-if="column.key === 'url'">
        <div class="url-cell">
          <a-typography-text class="url-text" :ellipsis="{ tooltip: text || '--' }">
            {{ text || '--' }}
          </a-typography-text>
          <a-button v-if="text" type="link" size="small" @click="copyText(text)">复制</a-button>
        </div>
      </template>
      <template v-else>
        {{ text || '--' }}
      </template>
    </template>
  </a-table>
</template>

<style scoped>
.url-cell {
  display: flex;
  align-items: center;
  gap: 6px;
}

.url-text {
  max-width: 220px;
}
</style>
