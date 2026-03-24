import request from './request'

export function getDashboardStats() {
  return request.get('/dashboard/stats')
}

export function getDashboardTrend(days = 7) {
  return request.get('/dashboard/trend', {
    params: { days },
  })
}
