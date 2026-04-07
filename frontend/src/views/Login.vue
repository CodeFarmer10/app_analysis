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
    <section class="brand-panel">
      <div class="brand-wrap">
        <h1 class="system-name title-text">诈骗APP分析系统</h1>
        <div class="tech-line" />
        <p class="system-desc">面向实战的恶意应用研判平台，聚焦快速发现、关联溯源与可追踪输出。</p>
        <ul class="ability-list">
          <li>
            <span class="ability-dot ability-blue" />
            <div>
              <h3>静态分析</h3>
              <p>提取权限、组件、签名与 SO 结构，快速构建应用画像。</p>
            </div>
          </li>
          <li>
            <span class="ability-dot ability-green" />
            <div>
              <h3>动态溯源</h3>
              <p>记录操作过程与网络行为，形成完整可回溯证据链。</p>
            </div>
          </li>
          <li>
            <span class="ability-dot ability-purple" />
            <div>
              <h3>报告生成</h3>
              <p>自动汇总分析结论，输出结构化结果与标准化报告。</p>
            </div>
          </li>
        </ul>
      </div>
    </section>

    <section class="form-panel">
      <a-card class="login-card" :bordered="false">
        <div class="shield-icon" aria-hidden="true" />
        <h2 class="title title-text">系统登录</h2>
        <p class="subtitle">请输入账号信息进入控制台</p>

        <a-alert
          v-if="errorText"
          class="error-alert"
          type="error"
          :message="errorText"
          show-icon
        />

        <a-form :model="formState" :rules="rules" layout="vertical" @finish="handleSubmit">
          <a-form-item name="username" class="floating-item">
            <div class="field-wrap">
              <a-input v-model:value="formState.username" placeholder=" " allow-clear />
              <span class="floating-label">用户名</span>
            </div>
          </a-form-item>
          <a-form-item name="password" class="floating-item">
            <div class="field-wrap">
              <a-input-password v-model:value="formState.password" placeholder=" " />
              <span class="floating-label">密码</span>
            </div>
          </a-form-item>
          <a-form-item>
            <a-button type="primary" html-type="submit" block :loading="loading" class="submit-btn">
              登录系统
            </a-button>
          </a-form-item>
        </a-form>
      </a-card>
    </section>
  </div>
</template>

<style scoped>
.login-page {
  min-height: 100vh;
  display: grid;
  grid-template-columns: minmax(0, 60%) minmax(380px, 40%);
  background:
    radial-gradient(circle at 78% 8%, rgba(59, 130, 246, 0.14), rgba(59, 130, 246, 0) 42%),
    radial-gradient(circle at 12% 74%, rgba(6, 182, 212, 0.1), rgba(6, 182, 212, 0) 45%),
    repeating-linear-gradient(
      90deg,
      rgba(255, 255, 255, 0.03) 0,
      rgba(255, 255, 255, 0.03) 1px,
      transparent 1px,
      transparent 26px
    ),
    #0a0e1a;
}

.brand-panel {
  display: flex;
  align-items: center;
  padding: 48px 5vw;
}

.brand-wrap {
  max-width: 640px;
}

.system-name {
  margin: 0;
  font-size: 44px;
  font-weight: 700;
  color: #f8fbff;
  line-height: 1.15;
}

.tech-line {
  width: 88px;
  height: 4px;
  margin: 20px 0 18px;
  border-radius: 99px;
  background: linear-gradient(90deg, #3b82f6, #06b6d4);
}

.system-desc {
  max-width: 560px;
  margin: 0 0 28px;
  color: #98aac2;
  font-size: 15px;
  line-height: 1.8;
}

.ability-list {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.ability-list li {
  display: flex;
  gap: 12px;
  align-items: flex-start;
}

.ability-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  margin-top: 7px;
  flex-shrink: 0;
}

.ability-blue {
  background: #3b82f6;
  box-shadow: 0 0 0 6px rgba(59, 130, 246, 0.16);
}

.ability-green {
  background: #10b981;
  box-shadow: 0 0 0 6px rgba(16, 185, 129, 0.16);
}

.ability-purple {
  background: #8b5cf6;
  box-shadow: 0 0 0 6px rgba(139, 92, 246, 0.16);
}

.ability-list h3 {
  margin: 0 0 6px;
  font-size: 17px;
  color: #e2ebf7;
}

.ability-list p {
  margin: 0;
  color: #7f93ac;
  font-size: 14px;
  line-height: 1.7;
}

.form-panel {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px;
  border-left: 1px solid rgba(255, 255, 255, 0.06);
  background:
    linear-gradient(180deg, rgba(28, 35, 51, 0.38), rgba(28, 35, 51, 0.22)),
    rgba(10, 14, 26, 0.45);
}

.login-card {
  width: min(430px, 100%);
  padding-top: 6px;
  border-radius: 12px;
  border: 1px solid var(--border-normal);
  background: #1c2333;
  box-shadow: 0 18px 48px rgba(5, 10, 19, 0.46);
  animation: card-enter 400ms ease-out;
}

.shield-icon {
  width: 42px;
  height: 42px;
  border: 1px solid rgba(59, 130, 246, 0.5);
  background:
    radial-gradient(circle at 50% 35%, rgba(59, 130, 246, 0.45), rgba(59, 130, 246, 0.06)),
    #1f2a3f;
  border-radius: 11px;
  margin-bottom: 12px;
  position: relative;
}

.shield-icon::after {
  content: '';
  position: absolute;
  left: 50%;
  top: 9px;
  width: 14px;
  height: 18px;
  transform: translateX(-50%);
  border: 2px solid #dbeafe;
  border-radius: 6px 6px 9px 9px;
  clip-path: polygon(50% 0%, 100% 14%, 100% 64%, 50% 100%, 0% 64%, 0% 14%);
}

.title {
  margin: 0 0 6px;
  color: #f1f5f9;
  font-size: 24px;
  font-weight: 700;
}

.subtitle {
  margin: 0 0 20px;
  color: #8ca0b8;
  font-size: 14px;
}

.error-alert {
  margin-bottom: 18px;
  border: 1px solid rgba(248, 113, 113, 0.58) !important;
  background: rgba(127, 29, 29, 0.48) !important;
}

.error-alert :deep(.ant-alert-message) {
  color: #fecaca !important;
  font-weight: 600;
  font-size: 14px;
}

.error-alert :deep(.ant-alert-icon) {
  color: #f87171 !important;
}

.floating-item {
  margin-bottom: 18px;
}

.floating-item :deep(.ant-form-item-control-input) {
  min-height: 48px;
}

.floating-item :deep(.ant-form-item-explain),
.floating-item :deep(.ant-form-item-extra) {
  min-height: 18px;
  margin-top: 6px;
}

.floating-item :deep(.ant-form-item-explain-error) {
  color: #fda4af;
  font-size: 13px;
  font-weight: 500;
}

.field-wrap {
  position: relative;
  padding-top: 8px;
  isolation: isolate;
}

.field-wrap::after {
  content: '';
  position: absolute;
  left: 0;
  right: 0;
  top: 8px;
  bottom: 0;
  border-radius: 6px;
  box-shadow: 0 0 0 0 rgba(59, 130, 246, 0);
  pointer-events: none;
  transition: box-shadow var(--dur-hover) ease;
}

.field-wrap:focus-within::after {
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.18);
}

.floating-label {
  position: absolute;
  top: 0;
  left: 11px;
  padding: 0 4px;
  font-size: 14px;
  font-weight: 500;
  color: #8aa5c8;
  background: #1c2333;
  pointer-events: none;
  line-height: 1;
  border-radius: 4px;
  z-index: 5;
}

.field-wrap :deep(.ant-input),
.field-wrap :deep(.ant-input-affix-wrapper) {
  height: 40px;
  position: relative;
  z-index: 1;
  background: var(--bg-input) !important;
  font-size: 16px;
}

.field-wrap :deep(.ant-input-password input) {
  font-size: 16px;
}

.field-wrap :deep(.ant-input),
.field-wrap :deep(.ant-input-affix-wrapper),
.field-wrap :deep(.ant-input:focus),
.field-wrap :deep(.ant-input-affix-wrapper-focused) {
  box-shadow: none !important;
}

.field-wrap :deep(.ant-input-affix-wrapper) {
  overflow: hidden;
}

.field-wrap :deep(.ant-input-password-icon),
.field-wrap :deep(.ant-input-password-icon:focus),
.field-wrap :deep(.ant-input-password-icon:focus-visible) {
  outline: none !important;
  box-shadow: none !important;
  border: none !important;
}

.field-wrap :deep(.ant-input-affix-wrapper-focused) {
  outline: none !important;
  border-color: var(--accent-blue) !important;
}

.field-wrap:focus-within :deep(.ant-input),
.field-wrap:focus-within :deep(.ant-input-affix-wrapper) {
  border-color: var(--accent-blue) !important;
}

.submit-btn {
  height: 36px;
  font-weight: 600;
  border: none;
  background: linear-gradient(135deg, #4d8ef7 0%, #3b82f6 65%, #2f73dd 100%);
}

.submit-btn:hover {
  background: linear-gradient(135deg, #6aa2ff 0%, #4f90f9 60%, #3a7de7 100%) !important;
}

@keyframes card-enter {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@media (max-width: 1100px) {
  .login-page {
    grid-template-columns: 1fr;
  }

  .brand-panel {
    display: none;
  }

  .form-panel {
    min-height: 100vh;
    border-left: none;
    padding: 18px;
  }
}
</style>
