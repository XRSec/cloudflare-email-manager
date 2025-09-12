<template>
  <div id="loginSection" class="card">
    <div class="header">
      <h1>临时邮箱管理系统</h1>
      <p>现代化的邮件管理解决方案</p>
    </div>

    <div class="tabs">
      <button 
        class="tab" 
        :class="{ active: activeTab === 'login' }" 
        @click="switchTab('login')"
      >
        登录
      </button>
      <button 
        v-if="allowRegistration"
        class="tab" 
        :class="{ active: activeTab === 'register' }" 
        @click="switchTab('register')"
      >
        注册
      </button>
    </div>

    <!-- 登录表单 -->
    <div v-if="activeTab === 'login'" class="tab-content active">
      <form @submit.prevent="handleLogin">
        <div class="form-group">
          <label class="form-label">用户名</label>
          <input 
            v-model="loginForm.username"
            type="text" 
            class="form-control" 
            placeholder="请输入用户名"
            required
          >
        </div>
        <div class="form-group">
          <label class="form-label">密码</label>
          <input 
            v-model="loginForm.password"
            type="password" 
            class="form-control" 
            placeholder="请输入密码"
            required
          >
        </div>
        <button 
          type="submit" 
          class="btn btn-primary" 
          :disabled="loading"
        >
          {{ loading ? '登录中...' : '登录' }}
        </button>
      </form>
    </div>

    <!-- 注册表单 -->
    <div v-if="activeTab === 'register'" class="tab-content">
      <form @submit.prevent="handleRegister">
        <div class="form-group">
          <label class="form-label">用户名</label>
          <input 
            v-model="registerForm.username"
            type="text" 
            class="form-control" 
            placeholder="请输入用户名（只允许英文、数字、下划线、连字符）"
            pattern="^[a-zA-Z0-9_-]+$"
            required
          >
        </div>
        <div class="form-group">
          <label class="form-label">邮箱</label>
          <input 
            v-model="registerForm.email"
            type="email" 
            class="form-control" 
            placeholder="请输入邮箱地址"
            required
          >
        </div>
        <div class="form-group">
          <label class="form-label">设置密码</label>
          <input 
            v-model="registerForm.password"
            type="password" 
            class="form-control" 
            placeholder="设置密码（至少6位）"
            minlength="6"
            required
          >
        </div>
        <button 
          type="submit" 
          class="btn btn-primary" 
          :disabled="loading"
        >
          {{ loading ? '注册中...' : '注册' }}
        </button>
        <p class="help-text">
          请填写您想要的用户名，系统将验证其唯一性
        </p>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

interface Emits {
  (e: 'login-success'): void
}

const emit = defineEmits<Emits>()
const router = useRouter()
const authStore = useAuthStore()

const activeTab = ref<'login' | 'register'>('login')
const loading = ref(false)

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

// 是否允许注册（这里可以从系统配置获取）
const allowRegistration = computed(() => {
  // 这里可以根据系统配置来判断
  return true
})

const switchTab = (tab: 'login' | 'register') => {
  activeTab.value = tab
}

const handleLogin = async () => {
  loading.value = true
  try {
    const result = await authStore.login(loginForm.value.username, loginForm.value.password)
    if (result.success) {
      emit('login-success')
      router.push('/')
    } else {
      // 显示错误消息
      alert(result.error || '登录失败')
    }
  } catch (error) {
    console.error('登录错误:', error)
    alert('登录时发生错误')
  } finally {
    loading.value = false
  }
}

const handleRegister = async () => {
  loading.value = true
  try {
    const result = await authStore.register(
      registerForm.value.username, 
      registerForm.value.password, 
      registerForm.value.email
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
.card {
  max-width: 400px;
  margin: 50px auto;
  padding: 30px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
}

.header {
  text-align: center;
  margin-bottom: 30px;
}

.header h1 {
  margin: 0 0 10px 0;
  color: #2c3e50;
  font-size: 24px;
}

.header p {
  margin: 0;
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
</style>
