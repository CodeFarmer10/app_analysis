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

export function getFamilyRecommendations(params) {
  return request.get('/families/recommendations', { params })
}

export function getFamilyRecommendationTypes() {
  return request.get('/families/recommendations/types')
}

export function getFamilyRecommendation(id) {
  return request.get(`/families/recommendations/${encodeURIComponent(id)}`)
}

export function getFamilyRecommendationMembers(id, params) {
  return request.get(`/families/recommendations/${encodeURIComponent(id)}/members`, { params })
}

export function generateFamilyRecommendations() {
  return request.post('/families/recommendations/generate')
}

export function getFamilyRecommendationJob(jobId) {
  return request.get(`/families/recommendations/jobs/${encodeURIComponent(jobId)}`)
}

export function approveFamilyRecommendation(id, draft) {
  return request.post(`/families/recommendations/${encodeURIComponent(id)}/approve`, draft)
}

export function rejectFamilyRecommendation(id) {
  return request.post(`/families/recommendations/${encodeURIComponent(id)}/reject`)
}
