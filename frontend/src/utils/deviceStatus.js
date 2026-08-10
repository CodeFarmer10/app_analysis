export function getUnavailableSummary(record) {
  if (record?.status === 'error') {
    return record.recovery_error || '设备恢复失败，请手动重试'
  }
  if (record?.status === 'quarantined') {
    return record.quarantine_reason || '设备健康检查失败'
  }
  if (record?.status === 'recovering') {
    return '设备正在自动恢复'
  }
  return '设备当前离线'
}

export function getUnavailableDetail(record) {
  const summary = getUnavailableSummary(record)
  if (record?.status !== 'error' || !record.quarantine_reason) {
    return summary
  }
  return `${summary}\n原隔离原因：${record.quarantine_reason}`
}
