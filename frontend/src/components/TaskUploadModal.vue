<script setup>
import { computed, ref } from 'vue'
import { message } from 'ant-design-vue'

import { submitTaskUrls, uploadTaskFiles } from '../api/tasks'

const props = defineProps({
  open: {
    type: Boolean,
    default: false,
  },
})

const emit = defineEmits(['update:open', 'success'])

const activeTab = ref('apk')
const fileList = ref([])
const urlText = ref('')
const submitting = ref(false)

const canSubmit = computed(() => {
  if (activeTab.value === 'apk') {
    return fileList.value.length > 0
  }

  const urls = urlText.value
    .split('\n')
    .map((item) => item.trim())
    .filter(Boolean)
  return urls.length > 0
})

function closeModal() {
  emit('update:open', false)
}

function resetFormState() {
  activeTab.value = 'apk'
  fileList.value = []
  urlText.value = ''
  submitting.value = false
}

function handleCancel() {
  closeModal()
  resetFormState()
}

function handleBeforeUpload(file) {
  fileList.value = [...fileList.value, file]
  return false
}

function handleFileRemove(targetFile) {
  fileList.value = fileList.value.filter((file) => file.uid !== targetFile.uid)
}

async function submitApkBatch() {
  const files = fileList.value
    .map((file) => file.originFileObj || file)
    .filter(Boolean)

  const result = await uploadTaskFiles(files)
  const successCount = result.items?.filter((item) => item.success).length || 0
  message.success(`已提交 ${successCount} 个 APK 任务`)
}

async function submitUrlBatch() {
  const urls = urlText.value
    .split('\n')
    .map((item) => item.trim())
    .filter(Boolean)

  const result = await submitTaskUrls(urls)
  const successCount = result.items?.filter((item) => item.success).length || 0
  message.success(`已提交 ${successCount} 条 URL 任务`)
}

async function handleSubmit() {
  if (!canSubmit.value) {
    return
  }

  submitting.value = true
  try {
    if (activeTab.value === 'apk') {
      await submitApkBatch()
    } else {
      await submitUrlBatch()
    }
    emit('success')
    handleCancel()
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <a-modal
    :open="props.open"
    title="上传/提交分析任务"
    width="680px"
    :confirm-loading="submitting"
    :ok-button-props="{ disabled: !canSubmit }"
    ok-text="提交"
    cancel-text="取消"
    @ok="handleSubmit"
    @cancel="handleCancel"
  >
    <a-tabs v-model:activeKey="activeTab">
      <a-tab-pane key="apk" tab="APK 批量上传">
        <a-upload-dragger
          :file-list="fileList"
          accept=".apk"
          multiple
          :before-upload="handleBeforeUpload"
          @remove="handleFileRemove"
        >
          <p class="upload-tip">点击或拖拽 APK 文件到此区域上传</p>
          <p class="upload-desc">支持批量上传，单文件建议不超过 500MB</p>
        </a-upload-dragger>
      </a-tab-pane>

      <a-tab-pane key="url" tab="URL 批量提交">
        <a-textarea
          v-model:value="urlText"
          :auto-size="{ minRows: 8, maxRows: 12 }"
          placeholder="每行输入一个 HTTP/HTTPS 下载地址"
        />
      </a-tab-pane>
    </a-tabs>
  </a-modal>
</template>

<style scoped>
.upload-tip {
  margin-bottom: 8px;
  color: #1f2d3d;
}

.upload-desc {
  margin: 0;
  color: #7a869a;
}
</style>
