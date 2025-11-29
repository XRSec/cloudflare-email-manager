<template>
  <div class="login-page">
    <div id="loginSection" class="card">
      <div class="header">
        <h1>CEM 邮箱管理系统</h1>
        <p>现代化的邮件管理解决方案</p>
      </div>

      <div class="status-banner" :class="{ open: allowRegistration, closed: !allowRegistration }">
        <span>
          {{ allowRegistration ? '注册配置为开放（前端禁用，未来可能启用）' : '注册已关闭，仅管理员可登录' }}
        </span>
      </div>

      <!-- 登录表单 -->
      <div class="tab-content active">
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
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, nextTick } from 'vue'
import { useAuthStore } from '@/composables/stores'
import { systemApiService } from '@/composables/api'

const authStore = useAuthStore()

// 定义事件
const emit = defineEmits<{
  'login-success': []
}>()

const handleLoginSuccess = async () => {
  // 触发登录成功事件，让 App.vue 处理预加载
  console.log('🚀 触发登录成功事件')

  // 使用 nextTick 确保在下一个 tick 中触发事件
  await nextTick()
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

const loading = ref(false)
const errorMessage = ref('')

// 登录表单
const loginForm = ref({
  username: 'admin',
  password: '123456'
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

const handleLogin = async () => {
  loading.value = true
  errorMessage.value = '' // 清空之前的错误消息

  try {
    const result = await authStore.login(
      loginForm.value.username,
      loginForm.value.password
    )

    if (result.success) {
      // 登录成功，立即隐藏登录页面
      console.log('✅ 登录成功，准备触发登录成功事件')

      // 立即隐藏登录页面，不等待 Vue 响应式更新
      const loginPage = document.querySelector('.login-page') as HTMLElement
      if (loginPage) {
        loginPage.style.display = 'none'
        console.log('🚫 登录页面已隐藏')
      }

      // 触发登录成功事件
      await handleLoginSuccess()
    } else {
      // 显示错误消息
      console.log('❌ 登录失败:', result.error)
      errorMessage.value = result.error || '登录失败'
    }
  } catch (error) {
    console.error('登录错误:', error)
    errorMessage.value = '登录时发生错误，请重试'
  } finally {
    loading.value = false
  }
  // 注意：登录成功时不重置 loading 状态，让页面切换时自然隐藏
}

</script>

<style scoped>
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  /* min-height: 100vh; */
  background: #f8f9fa;
  padding: 20px;
  z-index: 1000;
}

.card {
  width: 400px;
  min-width: 400px;
  padding: 30px;
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
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

.status-banner {
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
  margin-bottom: 20px;
  font-weight: 500;
}

.status-banner.open {
  background: #e8f5e9;
  color: #2e7d32;
  border: 1px solid #a5d6a7;
}

.status-banner.closed {
  background: #fff3e0;
  color: #ef6c00;
  border: 1px solid #ffcc80;
}

/* 表单样式 - 登录页面专用，因为登录时MainLayoutView还没加载 */
.form-group {
  margin-bottom: 20px;
}

.form-label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
  color: #2c3e50;
  font-size: 14px;
}

.form-control {
  width: 100%;
  padding: 12px 16px;
  border: 1px solid #ddd;
  border-radius: 6px;
  font-size: 14px;
  transition: border-color 0.3s ease;
  box-sizing: border-box;
  background: white;
}

.form-control:focus {
  outline: none;
  border-color: #007bff;
  box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
}

/* 只有在用户交互后才显示验证状态 */
.form-control:invalid:not(:placeholder-shown) {
  border-color: #e74c3c;
}

.form-control:valid:not(:placeholder-shown) {
  border-color: #27ae60;
}

/* 按钮样式 - 登录页面专用 */
.btn {
  width: 100%;
  padding: 12px 24px;
  border: none;
  border-radius: 6px;
  font-size: 16px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s ease;
  display: inline-block;
  text-decoration: none;
  text-align: center;
}

.btn-primary {
  background: #007bff;
  color: white;
  border-radius: 6px;
  font-weight: 500;
  font-size: 16px;
}

.btn-primary:hover:not(:disabled) {
  background: #0056b3;
  transform: translateY(-1px);
  box-shadow: 0 4px 8px rgba(0, 123, 255, 0.3);
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none;
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