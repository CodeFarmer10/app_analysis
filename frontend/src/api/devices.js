import request from './request'

export function getDeviceList() {
  return request.get('/devices')
}

export function getDeviceDetail(deviceId) {
  return request.get(`/devices/${deviceId}`)
}

export function createDevice(data) {
  return request.post('/devices', data)
}

export function updateDevice(deviceId, data) {
  return request.put(`/devices/${deviceId}`, data)
}

export function deleteDevice(deviceId) {
  return request.delete(`/devices/${deviceId}`)
}
