import request from './request'

function normalizeTaskPriority(priority) {
  const parsed = Number.parseInt(priority, 10)
  if (!Number.isFinite(parsed) || parsed < 1) {
    return 1
  }
  return parsed
}

export function uploadTaskFiles(files, taskDescription = '', priority = 1) {
  const formData = new FormData()
  files.forEach((file) => {
    const rawFile = file?.originFileObj || file
    if (!(rawFile instanceof Blob)) {
      return
    }
    const filename = rawFile.name || file?.name || 'upload.apk'
    formData.append('files', rawFile, filename)
  })
  formData.append('task_description', String(taskDescription || '').trim())
  formData.append('priority', String(normalizeTaskPriority(priority)))
  return request.post('/tasks/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
}

export function submitTaskUrls(urls, taskDescription = '', priority = 1) {
  return request.post('/tasks/url', {
    urls,
    task_description: String(taskDescription || '').trim(),
    priority: normalizeTaskPriority(priority),
  })
}

export function getTaskList(params) {
  return request.get('/tasks', { params })
}

export function getTaskDetail(taskId) {
  return request.get(`/tasks/${taskId}`)
}

export function getTaskStatus(taskId) {
  return request.get(`/tasks/${taskId}/status`)
}

export function getTaskStaticResult(taskId) {
  return request.get(`/tasks/${taskId}/static`)
}

export function getTaskDynamicResult(taskId, params) {
  return request.get(`/tasks/${taskId}/dynamic`, { params })
}

export function getTaskScreenshot(taskId, seq) {
  return request.get(`/tasks/${taskId}/screenshots/${seq}`)
}

export function getTaskApkDownload(taskId) {
  return request.get(`/tasks/${taskId}/apk`)
}

export function getTaskReportDownload(taskId) {
  return request.get(`/tasks/${taskId}/report`)
}

export function getTaskPcapDownload(taskId) {
  return request.get(`/tasks/${taskId}/pcap`)
}
