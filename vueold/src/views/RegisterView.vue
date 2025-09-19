<template>
  <div class="register-container">
    <n-card class="register-card" :bordered="false">
      <template #header>
        <div class="register-header">
          <h1>临时邮箱管理系统</h1>
          <p>创建您的账户</p>
        </div>
      </template>
      
      <n-form
        ref="formRef"
        :model="formData"
        :rules="rules"
        label-placement="left"
        label-width="auto"
        require-mark-placement="right-hanging"
        size="large"
      >
        <n-form-item label="用户名" path="username">
          <n-input
            v-model:value="formData.username"
            placeholder="请输入用户名"
            :disabled="loading"
          />
        </n-form-item>
        
        <n-form-item label="密码" path="password">
          <n-input
            v-model:value="formData.password"
            type="password"
            placeholder="请输入密码"
            :disabled="loading"
          />
        </n-form-item>
        
        <n-form-item label="确认密码" path="confirmPassword">
          <n-input
            v-model:value="formData.confirmPassword"
            type="password"
            placeholder="请再次输入密码"
            :disabled="loading"
            @keyup.enter="handleRegister"
          />
        </n-form-item>
      </n-form>
      
      <template #action>
        <div class="register-actions">
          <n-button
            type="primary"
            size="large"
            :loading="loading"
            @click="handleRegister"
            block
          >
            注册
          </n-button>
          
          <div class="register-links">
            <n-button
              text
              type="primary"
              @click="$router.push('/login')"
            >
              已有账户？立即登录
            </n-button>
          </div>
        </div>
      </template>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { useMessage } // 移除 naive-ui 导入
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const message = useMessage()
const authStore = useAuthStore()

const formRef = ref()
const loading = ref(false)

const formData = reactive({
  username: '',
  password: '',
  confirmPassword: ''
})

const rules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { 
      pattern: /^[a-zA-Z0-9_-]+$/, 
      message: '用户名只能包含英文字母、数字、下划线和连字符', 
      trigger: 'blur' 
    }
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, message: '密码长度不能少于6位', trigger: 'blur' }
  ],
  confirmPassword: [
    { required: true, message: '请确认密码', trigger: 'blur' },
    {
      validator: (rule: any, value: string) => {
        return value === formData.password
      },
      message: '两次输入的密码不一致',
      trigger: 'blur'
    }
  ]
}

const handleRegister = async () => {
  try {
    await formRef.value?.validate()
    loading.value = true
    
    const result = await authStore.register(formData.username, formData.password)
    
    if (result.success) {
      message.success('注册成功')
      router.push('/')
    } else {
      message.error(result.error || '注册失败')
    }
  } catch (error) {
    console.error('注册失败:', error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.register-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #f5f5dc 0%, #f0e68c 100%);
  padding: 20px;
}

.register-card {
  width: 100%;
  max-width: 400px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
  border-radius: 12px;
}

.register-header {
  text-align: center;
  margin-bottom: 20px;
}

.register-header h1 {
  margin: 0 0 8px 0;
  color: #333;
  font-size: 24px;
  font-weight: 600;
}

.register-header p {
  margin: 0;
  color: #666;
  font-size: 14px;
}

.register-actions {
  width: 100%;
}

.register-links {
  text-align: center;
  margin-top: 16px;
}
</style>
