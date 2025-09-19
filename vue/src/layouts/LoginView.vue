<template>
  <div class="login-page">
    <div id="loginSection" class="card">
      <div class="header">
        <h1>CEM 邮箱管理系统</h1>
        <p>现代化的邮件管理解决方案</p>
      </div>

      <div class="tabs">
        <button class="tab" :class="{ active: activeTab === 'login' }" @click="switchTab('login')">
          登录
        </button>
        <button v-if="allowRegistration" class="tab" :class="{ active: activeTab === 'register' }"
          @click="switchTab('register')">
          注册
        </button>
      </div>

      <!-- 登录表单 -->
      <div v-if="activeTab === 'login'" class="tab-content active">
        <!-- 错误消息显示 -->
        <div v-if="errorMessage" class="alert alert-error">
          {{ errorMessage }}
        </div>

        <form @submit.prevent="handleLogin">
          <div class="form-group">
            <label class="form-label">用户名</label>
            <input v-model="loginForm.username" type="text" class="form-control" placeholder="请输入用户名" required>
          </div>
          <div class="form-group">
            <label class="form-label">密码</label>
            <input v-model="loginForm.password" type="password" class="form-control" placeholder="请输入密码" required>
          </div>
          <button type="submit" class="btn btn-primary" :disabled="loading">
            {{ loading ? '登录中...' : '登录' }}
          </button>
        </form>
      </div>

      <!-- 注册表单 -->
      <div v-if="activeTab === 'register'" class="tab-content active">
        <form @submit.prevent="handleRegister">
          <div class="form-group">
            <label class="form-label">用户名</label>
            <input v-model="registerForm.username" type="text" class="form-control"
              placeholder="请输入用户名（只允许英文、数字、下划线、连字符）" pattern="^[a-zA-Z0-9_-]+$" required>
          </div>
          <div class="form-group">
            <label class="form-label">邮箱</label>
            <input v-model="registerForm.email" type="email" class="form-control" placeholder="请输入邮箱地址" required>
          </div>
          <div class="form-group">
            <label class="form-label">设置密码</label>
            <input v-model="registerForm.password" type="password" class="form-control" placeholder="设置密码（至少6位）"
              minlength="6" required>
          </div>
          <button type="submit" class="btn btn-primary" :disabled="loading">
            {{ loading ? '注册中...' : '注册' }}
          </button>
          <p class="help-text">
            请填写您想要的用户名，系统将验证其唯一性
          </p>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useAuthStore } from '@/composables/stores'
import { systemApiService } from '@/composables/api'

const authStore = useAuthStore()

onMounted(async () => {
  if (authStore.isAuthenticated) {
    // 如果已登录，触发登录成功事件
    await handleLoginSuccess()
  }
})

// 定义事件
const emit = defineEmits<{
  'login-success': []
}>()

const handleLoginSuccess = () => {
  // 触发登录成功事件，让 App.vue 处理预加载
  emit('login-success')
}

// 声明全局类型
declare global {
  interface Window {
    CEM_CONFIG?: {
      allow_registration: boolean
      debug_mode: boolean
      supported_domains: string[]
      max_attachment_size: number
      api_base_url: string
      version: string
      build_time: string
    }
    ConfigManager?: {
      isRegistrationAllowed(): boolean
      isDebugMode(): boolean
      getSupportedDomains(): string[]
      getMaxAttachmentSize(): number
    }
  }
}

const activeTab = ref<'login' | 'register'>('login')
const loading = ref(false)
const errorMessage = ref('')

// 登录表单
const loginForm = ref({
  username: '',
  password: ''
})

// 注册表单
const registerForm = ref({
  username: '',
  email: '',
  password: ''
})

// 是否允许注册
const allowRegistration = ref(false)

// 获取注册状态
const loadRegistrationStatus = async () => {
  try {
    // 优先使用注入的配置
    if (window.CEM_CONFIG && window.ConfigManager) {
      allowRegistration.value = window.ConfigManager.isRegistrationAllowed()
      return
    }

    // 使用系统健康状态接口
    const health = await systemApiService.getSystemHealth()
    if (health.success && health.data) {
      allowRegistration.value = health.data.config?.allow_registration === 1
      return
    }

    // 降级到注册状态接口
    const registration = await systemApiService.getRegistrationStatus()
    if (registration.success && registration.data) {
      allowRegistration.value = registration.data.allow_registration
    }
  } catch (error) {
    console.error('获取注册状态失败:', error)
    // 默认不允许注册
    allowRegistration.value = false
  }
}

// 组件挂载时加载配置
onMounted(async () => {
  await loadRegistrationStatus()
})

const switchTab = (tab: 'login' | 'register') => {
  activeTab.value = tab
}

const handleLogin = async () => {
  loading.value = true
  errorMessage.value = '' // 清空之前的错误消息

  try {
    // 获取重定向URL参数
    const urlParams = new URLSearchParams(window.location.search)
    const redirectUrl = urlParams.get('redirect')

    const result = await authStore.login(
      loginForm.value.username,
      loginForm.value.password
    )

    if (result.success) {
      // 登录成功后处理重定向
      if (redirectUrl) {
        window.location.href = decodeURIComponent(redirectUrl)
      } else {
        await handleLoginSuccess()
      }
    } else {
      // 显示错误消息
      errorMessage.value = result.error || '登录失败'
    }
  } catch (error) {
    console.error('登录错误:', error)
    errorMessage.value = '登录时发生错误，请重试'
  } finally {
    loading.value = false
  }
}

const handleRegister = async () => {
  loading.value = true
  try {
    const result = await authStore.register(
      registerForm.value.username,
      registerForm.value.email,
      registerForm.value.password
    )
    if (result.success) {
      alert(result.message || '注册成功，请登录')
      switchTab('login')
      // 清空注册表单
      registerForm.value = {
        username: '',
        email: '',
        password: ''
      }
    } else {
      alert(result.error || '注册失败')
    }
  } catch (error) {
    console.error('注册错误:', error)
    alert('注册时发生错误')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  display: flex;
  padding: 20px;
  z-index: 1000;
}

.card {
  width: 400px;
  min-width: 400px;
  padding: 30px;
  border: 2px solid #e0e0e0;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, .16);
  overflow: hidden;
  position: relative;
  display: flex;
  flex-direction: column;
}

.header {
  text-align: center;
  margin-bottom: 30px;
}

.header h1 {
  margin-bottom: 10px;
  color: #2c3e50;
  font-size: 24px;
}

.header p {
  color: #7f8c8d;
  font-size: 14px;
}

.tabs {
  display: flex;
  border-bottom: 2px solid #ecf0f1;
  margin-bottom: 20px;
}

.tab {
  flex: 1;
  padding: 10px 20px;
  cursor: pointer;
  background: none;
  border: none;
  color: #7f8c8d;
  font-size: 16px;
  transition: all 0.3s;
}

.tab.active {
  color: #3498db;
  border-bottom: 2px solid #3498db;
}

.tab-content {
  display: none;
}

.tab-content.active {
  display: block;
}

.form-group {
  margin-bottom: 20px;
}

.form-label {
  display: block;
  margin-bottom: 5px;
  font-weight: 500;
  color: #555;
}

.form-control {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
  font-size: 14px;
  transition: border-color 0.3s;
}

.form-control:focus {
  outline: none;
  border-color: #3498db;
  box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
}

.btn {
  width: 100%;
  padding: 12px;
  border: none;
  border-radius: 5px;
  font-size: 16px;
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #2980b9;
  transform: translateY(-2px);
  box-shadow: 0 5px 15px rgba(52, 152, 219, 0.3);
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.help-text {
  margin-top: 15px;
  color: #6c757d;
  font-size: 0.9rem;
  text-align: center;
}

.alert {
  padding: 12px 16px;
  margin-bottom: 20px;
  border-radius: 5px;
  font-size: 14px;
  font-weight: 500;
}

.alert-error {
  background-color: #fee;
  color: #c33;
  border: 1px solid #fcc;
}

.alert-success {
  background-color: #efe;
  color: #363;
  border: 1px solid #cfc;
}


/* ===== 响应式 ===== */
@media (max-width: 768px) {
  .card {
    padding: 20px;
  }

  .header h1 {
    font-size: 20px;
  }

  .header p {
    font-size: 13px;
  }

  .tab {
    padding: 12px 16px;
    font-size: 15px;
  }

  .form-label {
    font-size: 14px;
    margin-bottom: 8px;
  }

  .form-control {
    padding: 12px 16px;
    font-size: 16px;
  }

  .btn {
    padding: 12px 24px;
    font-size: 16px;
  }
}

@media (max-width: 480px) {
  .card {
    width: 100%;
    padding: 15px;
    border-top: 1px solid #e0e0e0;
    min-width: 300px;
  }

  .header {
    margin-bottom: 20px;
  }

  .header h1 {
    font-size: 18px;
  }

  .tabs {
    margin-bottom: 15px;
  }

  .tab {
    padding: 10px 12px;
    font-size: 14px;
  }

  .form-group {
    margin-bottom: 15px;
  }

  .form-control {
    padding: 10px 12px;
  }

  .btn {
    padding: 10px 20px;
    font-size: 15px;
  }
}
</style>