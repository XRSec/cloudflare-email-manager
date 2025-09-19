<template>
  <div class="debug-page">
    <div class="page-header">
      <h1>🐛 调试模式</h1>
      <span class="debug-badge">仅调试模式可用</span>
    </div>
    
    <div class="debug-content">
      <div class="debug-section">
        <h2>系统信息</h2>
        <div class="info-grid">
          <div class="info-item">
            <label>用户信息:</label>
            <span>{{ userInfo }}</span>
          </div>
          <div class="info-item">
            <label>认证状态:</label>
            <span>{{ authStatus }}</span>
          </div>
          <div class="info-item">
            <label>API 基础 URL:</label>
            <span>/api</span>
          </div>
        </div>
      </div>
      
      <div class="debug-section">
        <h2>测试邮件发送</h2>
        <form @submit.prevent="sendTestEmail">
          <div class="form-group">
            <label class="form-label">收件人</label>
            <input 
              v-model="testEmail.to"
              type="email" 
              class="form-control" 
              placeholder="test@example.com"
              required
            >
          </div>
          <div class="form-group">
            <label class="form-label">主题</label>
            <input 
              v-model="testEmail.subject"
              type="text" 
              class="form-control" 
              placeholder="测试邮件主题"
              required
            >
          </div>
          <div class="form-group">
            <label class="form-label">内容</label>
            <textarea 
              v-model="testEmail.content"
              class="form-control" 
              rows="4"
              placeholder="测试邮件内容"
              required
            ></textarea>
          </div>
          <button type="submit" class="btn btn-primary" :disabled="sending">
            {{ sending ? '发送中...' : '发送测试邮件' }}
          </button>
        </form>
      </div>
      
      <div class="debug-section">
        <h2>API 测试</h2>
        <div class="api-tests">
          <button class="btn btn-secondary" @click="testSystemHealth">
            测试系统健康状态
          </button>
          <button class="btn btn-secondary" @click="testSystemConfig">
            获取系统配置
          </button>
          <button class="btn btn-secondary" @click="testUserInfo">
            获取用户信息
          </button>
        </div>
        <div v-if="testResult" class="test-result">
          <h3>测试结果:</h3>
          <pre>{{ testResult }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { apiService } from '@/api'

const authStore = useAuthStore()
const sending = ref(false)
const testResult = ref('')

const testEmail = ref({
  to: '',
  subject: '测试邮件',
  content: '这是一封测试邮件，用于验证邮件发送功能。'
})

const userInfo = computed(() => {
  if (authStore.user) {
    return `${authStore.user.username} (${authStore.user.user_type})`
  }
  return '未登录'
})

const authStatus = computed(() => {
  return authStore.isAuthenticated ? '已认证' : '未认证'
})

const sendTestEmail = async () => {
  sending.value = true
  try {
    const response = await apiService.sendEmail(
      testEmail.value.to,
      testEmail.value.subject,
      testEmail.value.content
    )
    
    if (response.success) {
      alert('测试邮件发送成功')
    } else {
      alert(response.message || '测试邮件发送失败')
    }
  } catch (error) {
    console.error('发送测试邮件失败:', error)
    alert('发送测试邮件失败')
  } finally {
    sending.value = false
  }
}

const testSystemHealth = async () => {
  try {
    const response = await apiService.getSystemHealth()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}

const testSystemConfig = async () => {
  try {
    const response = await apiService.getSystemConfig()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}

const testUserInfo = async () => {
  try {
    const response = await apiService.getCurrentUser()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}

onMounted(() => {
  // 初始化测试邮件收件人
  if (authStore.user?.email) {
    testEmail.value.to = authStore.user.email
  }
})
</script>

<style scoped>
.debug-page {
  padding: 20px;
  background: #f8f9fa;
  min-height: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
}

.page-header h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
}

.debug-badge {
  background: #dc3545;
  color: white;
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.debug-content {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.debug-section {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.debug-section h2 {
  margin: 0 0 20px 0;
  color: #2c3e50;
  font-size: 18px;
  font-weight: 600;
  padding-bottom: 10px;
  border-bottom: 1px solid #e9ecef;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 15px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.info-item label {
  font-weight: 500;
  color: #555;
  font-size: 14px;
}

.info-item span {
  color: #2c3e50;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 13px;
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
  font-family: inherit;
}

.form-control:focus {
  outline: none;
  border-color: #3498db;
  box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
}

.api-tests {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 5px;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
  display: inline-block;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #2980b9;
}

.btn-secondary {
  background: #6c757d;
  color: white;
}

.btn-secondary:hover {
  background: #5a6268;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.test-result {
  background: #f8f9fa;
  border-radius: 5px;
  padding: 15px;
  border: 1px solid #e9ecef;
}

.test-result h3 {
  margin: 0 0 10px 0;
  color: #2c3e50;
  font-size: 14px;
}

.test-result pre {
  margin: 0;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 12px;
  color: #2c3e50;
  white-space: pre-wrap;
  word-break: break-all;
}

@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
    gap: 10px;
    align-items: flex-start;
  }
  
  .info-grid {
    grid-template-columns: 1fr;
  }
  
  .api-tests {
    flex-direction: column;
  }
}
</style>
