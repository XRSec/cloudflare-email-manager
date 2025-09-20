<template>
  <div class="debug-page">
    <div class="page-header">
      <h1>{{ pageIcon }} {{ pageTitle }}</h1>
      <span class="debug-badge">仅调试模式可用</span>
    </div>

    <div class="debug-content">
      <!-- 系统信息 -->
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
            <label>用户类型:</label>
            <span>{{ userType }}</span>
          </div>
          <div class="info-item">
            <label>API 基础 URL:</label>
            <span>{{ apiBaseUrl }}</span>
          </div>
          <div class="info-item">
            <label>环境模式:</label>
            <span>{{ environment }}</span>
          </div>
          <div class="info-item">
            <label>调试模式:</label>
            <span>{{ debugMode ? '已启用' : '已禁用' }}</span>
          </div>
        </div>
      </div>

      <!-- 模拟邮件接收 -->
      <div class="debug-section">
        <h2>模拟邮件接收</h2>
        <p class="debug-note">此功能模拟邮件接收，邮件会被系统处理并存储到数据库中</p>
        <form @submit.prevent="sendTestEmail">
          <div class="form-group">
            <label class="form-label">发件人</label>
            <input v-model="testEmail.from" type="email" class="form-control" placeholder="sender@example.com" required>
          </div>
          <div class="form-group">
            <label class="form-label">收件人</label>
            <input v-model="testEmail.to" type="email" class="form-control" placeholder="user@example.com" required>
          </div>
          <div class="form-group">
            <label class="form-label">主题</label>
            <input v-model="testEmail.subject" type="text" class="form-control" placeholder="测试邮件主题" required>
          </div>
          <div class="form-group">
            <label class="form-label">内容</label>
            <textarea v-model="testEmail.content" class="form-control" rows="4" placeholder="测试邮件内容"
              required></textarea>
          </div>
          <button type="submit" class="btn btn-primary" :disabled="sending">
            {{ sending ? '模拟中...' : '模拟邮件接收' }}
          </button>
        </form>
      </div>

      <!-- API 测试 -->
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
          <button class="btn btn-secondary" @click="testForwardRules">
            测试转发规则
          </button>
          <button class="btn btn-secondary" @click="testMailboxes">
            测试邮箱列表
          </button>
        </div>
        <div v-if="testResult" class="test-result">
          <h3>测试结果:</h3>
          <pre>{{ testResult }}</pre>
        </div>
      </div>

      <!-- 缓存管理 -->
      <div class="debug-section">
        <h2>缓存管理</h2>
        <div class="cache-actions">
          <button class="btn btn-warning" @click="clearAllCache">
            清空所有缓存
          </button>
          <button class="btn btn-info" @click="showCacheInfo">
            显示缓存信息
          </button>
        </div>
        <div v-if="cacheInfo" class="cache-info">
          <h3>缓存信息:</h3>
          <pre>{{ cacheInfo }}</pre>
        </div>
      </div>

      <!-- 数据库测试 -->
      <div class="debug-section">
        <h2>数据库测试</h2>
        <div class="db-tests">
          <button class="btn btn-secondary" @click="testDatabaseConnection">
            测试数据库连接
          </button>
          <button class="btn btn-secondary" @click="testDatabaseStats">
            获取数据库统计
          </button>
        </div>
        <div v-if="dbResult" class="test-result">
          <h3>数据库测试结果:</h3>
          <pre>{{ dbResult }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAuthStore } from '@/composables/stores'
import { systemApiService, userApiService, mailboxApiService } from '@/composables/api'
import { cacheService } from '@/composables/cache'

const authStore = useAuthStore()
const sending = ref(false)
const testResult = ref('')
const cacheInfo = ref('')
const dbResult = ref('')

const testEmail = ref({
  from: 'sender@example.com',
  to: 'user@example.com',
  subject: '测试邮件',
  content: '这是一封测试邮件，用于验证邮件发送功能。'
})

// 计算属性
const userInfo = computed(() => {
  if (authStore.user) {
    return `${authStore.user.username} (${authStore.user.email})`
  }
  return '未登录'
})

const authStatus = computed(() => {
  return authStore.isAuthenticated ? '已认证' : '未认证'
})

const userType = computed(() => {
  return authStore.user?.user_type || '未知'
})

const apiBaseUrl = computed(() => {
  return import.meta.env.VITE_API_BASE_URL || '/api'
})

const environment = computed(() => {
  return import.meta.env.MODE || 'development'
})

const debugMode = computed(() => {
  return import.meta.env.DEV || import.meta.env.VITE_DEBUG === 'true'
})

// 页面标题和图标
const pageTitle = computed(() => '调试模式')
const pageIcon = computed(() => '🐛')

// 发送测试邮件（使用调试模式模拟邮件接口）
const sendTestEmail = async () => {
  sending.value = true
  try {
    // 使用调试模式的模拟邮件接口
    const response = await fetch('/api/debug/simulate-email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify({
        from: testEmail.value.from,
        to: testEmail.value.to,
        subject: testEmail.value.subject,
        content: testEmail.value.content,
        content_type: 'markdown'
      })
    })

    const result = await response.json()

    if (result.success) {
      alert('测试邮件模拟成功')
    } else {
      alert(result.error || '测试邮件模拟失败')
    }
  } catch (error) {
    console.error('发送测试邮件失败:', error)
    alert('发送测试邮件失败')
  } finally {
    sending.value = false
  }
}

// API 测试方法
const testSystemHealth = async () => {
  try {
    const response = await systemApiService.getSystemHealth()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}

const testSystemConfig = async () => {
  try {
    const response = await systemApiService.getSystemConfig()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}

const testUserInfo = async () => {
  try {
    const response = await userApiService.getUserProfile()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}

const testForwardRules = async () => {
  try {
    const response = await userApiService.getForwardRules()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}

const testMailboxes = async () => {
  try {
    const response = await mailboxApiService.getMailboxes()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}

// 缓存管理
const clearAllCache = () => {
  cacheService.clear()
  alert('所有缓存已清空')
}

const showCacheInfo = () => {
  const info = {
    cacheSize: cacheService.size(),
    cacheKeys: cacheService.keys(),
    memoryUsage: (performance as any).memory ? {
      used: Math.round((performance as any).memory.usedJSHeapSize / 1024 / 1024) + ' MB',
      total: Math.round((performance as any).memory.totalJSHeapSize / 1024 / 1024) + ' MB',
      limit: Math.round((performance as any).memory.jsHeapSizeLimit / 1024 / 1024) + ' MB'
    } : '不支持'
  }
  cacheInfo.value = JSON.stringify(info, null, 2)
}

// 数据库测试
const testDatabaseConnection = async () => {
  try {
    const response = await systemApiService.getSystemHealth()
    dbResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    dbResult.value = `错误: ${error}`
  }
}

const testDatabaseStats = async () => {
  try {
    // 这里可以添加获取数据库统计的API调用
    dbResult.value = '数据库统计功能暂未实现'
  } catch (error) {
    dbResult.value = `错误: ${error}`
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

.debug-note {
  background: #e3f2fd;
  border: 1px solid #bbdefb;
  border-radius: 5px;
  padding: 10px;
  margin-bottom: 20px;
  color: #1565c0;
  font-size: 14px;
  line-height: 1.4;
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

.api-tests,
.cache-actions,
.db-tests {
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

.btn-warning {
  background: #ffc107;
  color: #212529;
}

.btn-warning:hover {
  background: #e0a800;
}

.btn-info {
  background: #17a2b8;
  color: white;
}

.btn-info:hover {
  background: #138496;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.test-result,
.cache-info {
  background: #f8f9fa;
  border-radius: 5px;
  padding: 15px;
  border: 1px solid #e9ecef;
}

.test-result h3,
.cache-info h3 {
  margin: 0 0 10px 0;
  color: #2c3e50;
  font-size: 14px;
}

.test-result pre,
.cache-info pre {
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

  .api-tests,
  .cache-actions,
  .db-tests {
    flex-direction: column;
  }
}
</style>
