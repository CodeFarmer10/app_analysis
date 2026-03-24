function normalizeByteSize(input) {
  const size = Number(input)
  if (!Number.isFinite(size) || size < 0) {
    return 0
  }
  return size
}

export function formatFileSize(bytes) {
  const size = normalizeByteSize(bytes)
  const units = ['B', 'KB', 'MB', 'GB', 'TB']

  if (size === 0) {
    return '0 B'
  }

  const exponent = Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1)
  const value = size / 1024 ** exponent
  const fixed = value >= 10 || exponent === 0 ? 0 : 2

  return `${value.toFixed(fixed)} ${units[exponent]}`
}

export function formatDateTime(isoString) {
  if (!isoString) {
    return '--'
  }

  const date = new Date(isoString)
  if (Number.isNaN(date.getTime())) {
    return '--'
  }

  const pad = (value) => String(value).padStart(2, '0')
  const year = date.getFullYear()
  const month = pad(date.getMonth() + 1)
  const day = pad(date.getDate())
  const hours = pad(date.getHours())
  const minutes = pad(date.getMinutes())
  const seconds = pad(date.getSeconds())

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`
}
