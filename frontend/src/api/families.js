import request from './request'

export function getFamilyList(params) {
  return request.get('/families', { params })
}

export function getFamilyTypes() {
  return request.get('/families/types')
}

export function getFamilyDetail(modelId) {
  return request.get(`/families/${encodeURIComponent(modelId)}`)
}

export function getFamilyMembers(modelId, params) {
  return request.get(`/families/${encodeURIComponent(modelId)}/members`, { params })
}
