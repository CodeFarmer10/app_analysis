import request from './request'

export function getUserList() {
  return request.get('/users')
}

export function createUser(data) {
  return request.post('/users', data)
}

export function deleteUser(userId) {
  return request.delete(`/users/${userId}`)
}
