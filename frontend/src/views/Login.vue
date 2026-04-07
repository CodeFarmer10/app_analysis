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
      <h2 class="title">系统登录</h2>
      <p class="subtitle">请输入账号密码</p>

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
  padding: 28px;
  background:
    radial-gradient(circle at 18% 24%, rgba(31, 110, 143, 0.2) 0%, rgba(31, 110, 143, 0) 44%),
    radial-gradient(circle at 84% 82%, rgba(33, 133, 129, 0.14) 0%, rgba(33, 133, 129, 0) 45%),
    linear-gradient(135deg, #e7f0f6 0%, #edf4f8 50%, #f3f8fb 100%);
}

.login-card {
  width: min(440px, 100%);
  border-radius: 12px;
  border: 1px solid #cfe0ec;
  background: #ffffff;
  box-shadow: 0 16px 34px rgba(15, 58, 85, 0.1);
  animation: panel-in 260ms ease-out;
}

.title {
  margin: 0 0 6px;
  color: #17435e;
}

.subtitle {
  margin: 0 0 20px;
  color: #5a7489;
}

.error-alert {
  margin-bottom: 16px;
}

@keyframes panel-in {
  from {
    opacity: 0;
    transform: translateY(8px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@media (max-width: 960px) {
  .login-page {
    padding: 18px;
  }
}
</style>
