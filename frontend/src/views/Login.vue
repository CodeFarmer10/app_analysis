<script setup>
import { reactive, ref } from 'vue'
import { useRoute } from 'vue-router'

import { useAuthStore } from '../stores/auth'

const route = useRoute()
const authStore = useAuthStore()

const loading = ref(false)
const errorText = ref('')
const formState = reactive({
  username: '',
  password: '',
})

const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

async function handleSubmit(values) {
  loading.value = true
  errorText.value = ''

  try {
    await authStore.login(values, route.query.redirect)
  } catch (error) {
    const backendMessage = error?.response?.data?.message
    errorText.value = backendMessage || '登录失败，请检查用户名和密码'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login-page">
    <a-card class="login-card" :bordered="false">
      <h2 class="title">诈骗APP分析系统</h2>
      <p class="subtitle">请输入账号密码登录系统</p>

      <a-alert
        v-if="errorText"
        class="error-alert"
        type="error"
        :message="errorText"
        show-icon
      />

      <a-form :model="formState" :rules="rules" layout="vertical" @finish="handleSubmit">
        <a-form-item label="用户名" name="username">
          <a-input v-model:value="formState.username" placeholder="请输入用户名" size="large" />
        </a-form-item>
        <a-form-item label="密码" name="password">
          <a-input-password
            v-model:value="formState.password"
            placeholder="请输入密码"
            size="large"
          />
        </a-form-item>
        <a-form-item>
          <a-button type="primary" html-type="submit" size="large" block :loading="loading">
            登录
          </a-button>
        </a-form-item>
      </a-form>
    </a-card>
  </div>
</template>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background:
    radial-gradient(circle at 20% 20%, rgba(111, 145, 255, 0.14) 0%, rgba(111, 145, 255, 0) 45%),
    radial-gradient(circle at 80% 80%, rgba(76, 175, 255, 0.12) 0%, rgba(76, 175, 255, 0) 42%),
    linear-gradient(135deg, #eef3ff 0%, #f6f9ff 50%, #f8fafc 100%);
}

.login-card {
  width: 420px;
  border-radius: 12px;
  border: 1px solid #e6ecf7;
  background: rgba(255, 255, 255, 0.95);
  box-shadow: 0 14px 36px rgba(31, 45, 61, 0.1);
}

.title {
  margin: 0 0 8px;
  text-align: center;
  color: #1f2d3d;
}

.subtitle {
  margin: 0 0 20px;
  text-align: center;
  color: #6b7785;
}

.error-alert {
  margin-bottom: 16px;
}
</style>
