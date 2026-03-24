import request from './request'

export function uploadTaskFiles(files) {
  const formData = new FormData()
  files.forEach((file) => {
    formData.append('files', file)
  })
  return request.post('/tasks/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
}

export function submitTaskUrls(urls) {
  return request.post('/tasks/url', { urls })
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
