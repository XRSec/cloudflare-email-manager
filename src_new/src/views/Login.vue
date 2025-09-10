<template>
  <div class="login-container">
    <div class="container">
      <!-- 页面标题 -->
      <div class="header text-center">
        <h1>临时邮箱管理系统</h1>
        <p>基于 Cloudflare 的安全、快速、便捷的临时邮箱解决方案</p>
      </div>

      <!-- 登录表单卡片 -->
      <div class="login-card card">
        <!-- 标签切换 -->
        <div class="tabs">
          <button
            :class="['tab', { active: activeTab === 'login' }]"
            @click="activeTab = 'login'"
          >
            登录
          </button>
          <button
            v-if="systemStore.allowRegistration"
            :class="['tab', { active: activeTab === 'register' }]"
            @click="activeTab = 'register'"
          >
            注册
          </button>
        </div>

        <!-- 登录表单 -->
        <div v-if="activeTab === 'login'" class="tab-content active">
          <form @submit.prevent="handleLogin">
            <div class="form-group">
              <label for="loginPrefix" class="form-label">邮箱前缀</label>
              <input
                id="loginPrefix"
                v-model="loginForm.email_prefix"
                type="text"
                class="form-control"
                placeholder="请输入您的邮箱前缀"
                required
                :disabled="authStore.loading"
              >
            </div>

            <div class="form-group">
              <label for="loginPassword" class="form-label">密码</label>
              <input
                id="loginPassword"
                v-model="loginForm.email_password"
                type="password"
                class="form-control"
                placeholder="请输入您的密码"
                required
                :disabled="authStore.loading"
              >
            </div>

            <button
              type="submit"
              class="btn btn-primary btn-block"
              :disabled="authStore.loading || !isLoginFormValid"
            >
              <span v-if="authStore.loading">登录中...</span>
              <span v-else>登录</span>
            </button>
          </form>
        </div>

        <!-- 注册表单 -->
        <div v-if="activeTab === 'register'" class="tab-content active">
          <form @submit.prevent="handleRegister">
            <div class="form-group">
              <label for="registerPassword" class="form-label">设置密码</label>
              <input
                id="registerPassword"
                v-model="registerForm.email_password"
                type="password"
                class="form-control"
                placeholder="请设置您的密码（至少6位）"
                required
                minlength="6"
                :disabled="authStore.loading"
              >
              <small class="text-muted">
                注册成功后系统将自动为您生成唯一的邮箱前缀
              </small>
            </div>

            <button
              type="submit"
              class="btn btn-primary btn-block"
              :disabled="authStore.loading || !isRegisterFormValid"
            >
              <span v-if="authStore.loading">注册中...</span>
              <span v-else>注册</span>
            </button>
          </form>
        </div>

        <!-- 错误信息 -->
        <div v-if="authStore.error" class="mt-4">
          <div class="alert alert-danger">
            {{ authStore.error }}
          </div>
        </div>
      </div>

      <!-- 系统信息 -->
      <div class="system-info text-center">
        <p class="text-muted">
          <small>
            支持的域名: {{ systemStore.domains.join(', ') || '加载中...' }}
          </small>
        </p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useSystemStore } from '@/stores/system'
import type { LoginForm, RegisterForm } from '@/types'

// Composables
const router = useRouter()
const authStore = useAuthStore()
const systemStore = useSystemStore()

// State
const activeTab = ref<'login' | 'register'>('login')
const loginForm = ref<LoginForm>({
  email_prefix: '',
  email_password: ''
})
const registerForm = ref<RegisterForm>({
  email_password: ''
})

// Computed
const isLoginFormValid = computed(() => {
  return loginForm.value.email_prefix.trim() && 
         loginForm.value.email_password.trim()
})

const isRegisterFormValid = computed(() => {
  return registerForm.value.email_password.length >= 6
})

// Methods
const handleLogin = async () => {
  authStore.clearError()
  
  const success = await authStore.login(loginForm.value)
  
  if (success) {
    // 登录成功，跳转到仪表盘
    router.push('/dashboard')
  }
}

const handleRegister = async () => {
  authStore.clearError()
  
  const result = await authStore.register(registerForm.value)
  
  if (result.success && result.email_prefix) {
    // 注册成功，自动填入登录表单
    loginForm.value.email_prefix = result.email_prefix
    loginForm.value.email_password = registerForm.value.email_password
    
    // 切换到登录标签
    activeTab.value = 'login'
    
    // 清空注册表单
    registerForm.value.email_password = ''
    
    // 显示成功消息
    showMessage(`注册成功！您的邮箱前缀是：${result.email_prefix}`, 'success')
  }
}

const showMessage = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
  // 这里可以使用全局消息组件或者简单的 alert
  // 暂时使用简单的实现
  console.log(`[${type.toUpperCase()}] ${message}`)
}

// Lifecycle
onMounted(async () => {
  // 如果已经登录，直接跳转到仪表盘
  if (authStore.isAuthenticated) {
    router.push('/dashboard')
    return
  }
  
  // 加载系统配置
  await systemStore.loadConfig()
})
</script>

<style scoped>
.login-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  padding: var(--spacing-4) 0;
}

.header {
  color: var(--white);
  margin-bottom: var(--spacing-10);
}

.header h1 {
  font-size: var(--font-size-3xl);
  margin-bottom: var(--spacing-3);
  font-weight: 300;
  text-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
}

.header p {
  font-size: var(--font-size-lg);
  opacity: 0.9;
}

.login-card {
  max-width: 500px;
  margin: 0 auto;
  position: relative;
}

.tabs {
  display: flex;
  margin-bottom: var(--spacing-8);
  border-bottom: 2px solid var(--gray-200);
  background: var(--gray-100);
  border-radius: var(--border-radius-lg) var(--border-radius-lg) 0 0;
  overflow: hidden;
  margin: calc(var(--spacing-8) * -1) calc(var(--spacing-8) * -1) var(--spacing-8) calc(var(--spacing-8) * -1);
}

.tab {
  flex: 1;
  padding: var(--spacing-4) var(--spacing-5);
  background: none;
  border: none;
  font-size: var(--font-size-base);
  cursor: pointer;
  color: var(--gray-600);
  transition: var(--transition);
  font-weight: 500;
}

.tab.active {
  color: var(--primary-color);
  background: var(--white);
  font-weight: 600;
}

.tab:hover:not(.active) {
  background: var(--gray-200);
}

.tab-content {
  display: none;
}

.tab-content.active {
  display: block;
}

.form-group small {
  display: block;
  margin-top: var(--spacing-2);
  font-size: var(--font-size-sm);
}

.alert {
  padding: var(--spacing-4);
  border-radius: var(--border-radius);
  margin: 0;
}

.alert-danger {
  background: linear-gradient(135deg, var(--danger-color) 0%, var(--danger-light) 100%);
  color: var(--white);
  border: none;
}

.system-info {
  margin-top: var(--spacing-8);
  color: var(--white);
}

.system-info .text-muted {
  color: rgba(255, 255, 255, 0.7) !important;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .header h1 {
    font-size: var(--font-size-2xl);
  }
  
  .header p {
    font-size: var(--font-size-base);
  }
  
  .login-card {
    margin: 0 var(--spacing-4);
  }
}
</style>