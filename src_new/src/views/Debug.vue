<template>
  <div class="debug-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <div class="header-content">
        <h2 class="page-title">🐛 调试工具</h2>
        <p class="page-description">
          开发和测试工具，仅在调试模式下可用
        </p>
      </div>
      <div class="header-actions">
        <button
          class="btn btn-outline-primary"
          @click="refreshDebugInfo"
          :disabled="refreshing"
        >
          <span v-if="refreshing">刷新中...</span>
          <span v-else>🔄 刷新信息</span>
        </button>
      </div>
    </div>

    <!-- 系统状态 -->
    <div class="debug-status-card card">
      <div class="card-header">
        <h3 class="card-title">系统状态</h3>
      </div>
      <div class="status-grid">
        <div class="status-item">
          <div class="status-label">调试模式</div>
          <div :class="['status-value', debugMode ? 'status-success' : 'status-danger']">
            {{ debugMode ? '✅ 已启用' : '❌ 已禁用' }}
          </div>
        </div>
        <div class="status-item">
          <div class="status-label">当前用户</div>
          <div class="status-value status-info">
            {{ authStore.currentUser?.email_prefix }} ({{ authStore.currentUser?.user_type }})
          </div>
        </div>
        <div class="status-item">
          <div class="status-label">系统配置</div>
          <div class="status-value status-info">
            注册: {{ systemStore.allowRegistration ? '开启' : '关闭' }}, 
            清理: {{ systemStore.config?.cleanup_days }}天
          </div>
        </div>
        <div class="status-item">
          <div class="status-label">支持域名</div>
          <div class="status-value status-info">
            {{ systemStore.domains.join(', ') || '未配置' }}
          </div>
        </div>
      </div>
    </div>

    <!-- 模拟邮件接收 -->
    <div class="simulate-email-card card">
      <div class="card-header">
        <h3 class="card-title">📧 模拟邮件接收</h3>
        <p class="text-muted">发送模拟邮件用于测试系统功能</p>
      </div>

      <form @submit.prevent="handleSimulateEmail">
        <div class="form-row">
          <div class="form-col">
            <div class="form-group">
              <label for="simFromEmail" class="form-label">发件人邮箱 *</label>
              <input
                id="simFromEmail"
                v-model="simulateForm.from"
                type="email"
                class="form-control"
                placeholder="sender@example.com"
                required
                :disabled="simulating"
              >
            </div>
          </div>
          <div class="form-col">
            <div class="form-group">
              <label for="simToEmail" class="form-label">收件人邮箱 *</label>
              <input
                id="simToEmail"
                v-model="simulateForm.to"
                type="email"
                class="form-control"
                :placeholder="defaultToEmail"
                required
                :disabled="simulating"
              >
            </div>
          </div>
        </div>

        <div class="form-group">
          <label for="simSubject" class="form-label">邮件主题 *</label>
          <input
            id="simSubject"
            v-model="simulateForm.subject"
            type="text"
            class="form-control"
            placeholder="测试邮件主题"
            required
            :disabled="simulating"
          >
        </div>

        <div class="form-group">
          <label for="simTextContent" class="form-label">邮件内容</label>
          <textarea
            id="simTextContent"
            v-model="simulateForm.text"
            class="form-control"
            rows="4"
            placeholder="这是一封测试邮件的内容..."
            :disabled="simulating"
          ></textarea>
        </div>

        <div class="form-group">
          <label for="simHtmlContent" class="form-label">HTML 内容 (可选)</label>
          <textarea
            id="simHtmlContent"
            v-model="simulateForm.html"
            class="form-control"
            rows="3"
            placeholder="<p>HTML 格式的邮件内容</p>"
            :disabled="simulating"
          ></textarea>
        </div>

        <div class="form-actions">
          <button
            type="submit"
            class="btn btn-primary"
            :disabled="simulating || !isSimulateFormValid"
          >
            <span v-if="simulating">发送中...</span>
            <span v-else>📤 发送模拟邮件</span>
          </button>
          <button
            type="button"
            class="btn btn-light"
            @click="clearSimulateForm"
            :disabled="simulating"
          >
            🗑️ 清空表单
          </button>
        </div>
      </form>
    </div>

    <!-- 最近操作 -->
    <div class="recent-actions-card card">
      <div class="card-header">
        <h3 class="card-title">📝 最近操作</h3>
      </div>
      <div class="actions-list">
        <div
          v-for="action in recentActions"
          :key="action.id"
          :class="['action-item', `action-${action.type}`]"
        >
          <div class="action-time">{{ formatTime(action.timestamp) }}</div>
          <div class="action-content">{{ action.message }}</div>
        </div>
        <div v-if="recentActions.length === 0" class="no-actions">
          <p>暂无操作记录</p>
        </div>
      </div>
      <div class="actions-footer">
        <button
          class="btn btn-sm btn-outline-danger"
          @click="clearActionLogs"
        >
          清空日志
        </button>
      </div>
    </div>

    <!-- API 测试 -->
    <div class="api-test-card card">
      <div class="card-header">
        <h3 class="card-title">🔧 API 测试</h3>
      </div>
      <div class="api-test-content">
        <div class="test-buttons">
          <button
            class="btn btn-outline-primary"
            @click="testSystemConfig"
            :disabled="testing"
          >
            测试系统配置
          </button>
          <button
            class="btn btn-outline-primary"
            @click="testUserInfo"
            :disabled="testing"
          >
            测试用户信息
          </button>
          <button
            class="btn btn-outline-primary"
            @click="testEmailList"
            :disabled="testing"
          >
            测试邮件列表
          </button>
        </div>
        
        <div v-if="apiTestResult" class="test-result">
          <h4>测试结果</h4>
          <pre>{{ JSON.stringify(apiTestResult, null, 2) }}</pre>
        </div>
      </div>
    </div>

    <!-- 错误信息 -->
    <div v-if="error" class="alert alert-danger">
      {{ error }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useSystemStore } from '@/stores/system'
import { useEmailStore } from '@/stores/emails'
import { apiService } from '@/services/api'
import type { SimulateEmailForm } from '@/types'

// Composables
const authStore = useAuthStore()
const systemStore = useSystemStore()
const emailStore = useEmailStore()

// State
const refreshing = ref(false)
const simulating = ref(false)
const testing = ref(false)
const error = ref<string | null>(null)
const apiTestResult = ref<any>(null)

const simulateForm = ref<SimulateEmailForm>({
  from: '',
  to: '',
  subject: '',
  text: '',
  html: ''
})

interface DebugAction {
  id: string
  type: 'success' | 'error' | 'info'
  message: string
  timestamp: Date
}

const recentActions = ref<DebugAction[]>([])

// Computed
const debugMode = computed(() => systemStore.debugMode)

const defaultToEmail = computed(() => {
  if (authStore.currentUser && systemStore.primaryDomain) {
    return `${authStore.currentUser.email_prefix}@${systemStore.primaryDomain}`
  }
  return 'user@example.com'
})

const isSimulateFormValid = computed(() => {
  return simulateForm.value.from &&
         simulateForm.value.to &&
         simulateForm.value.subject
})

// Methods
const addAction = (type: 'success' | 'error' | 'info', message: string) => {
  const action: DebugAction = {
    id: Date.now().toString(),
    type,
    message,
    timestamp: new Date()
  }
  recentActions.value.unshift(action)
  
  // 只保留最近 20 条记录
  if (recentActions.value.length > 20) {
    recentActions.value = recentActions.value.slice(0, 20)
  }
}

const refreshDebugInfo = async () => {
  refreshing.value = true
  error.value = null
  
  try {
    await systemStore.loadConfig()
    await authStore.refreshUser()
    addAction('success', '调试信息刷新成功')
  } catch (err: any) {
    error.value = err.message || '刷新失败'
    addAction('error', `刷新失败: ${err.message}`)
  } finally {
    refreshing.value = false
  }
}

const handleSimulateEmail = async () => {
  simulating.value = true
  error.value = null
  
  try {
    const response = await apiService.simulateEmail(simulateForm.value)
    
    if (response.success) {
      addAction('success', `模拟邮件发送成功: ${simulateForm.value.subject}`)
      clearSimulateForm()
      
      // 刷新邮件列表
      await emailStore.loadEmails()
    } else {
      throw new Error(response.error || '模拟邮件发送失败')
    }
  } catch (err: any) {
    error.value = err.message || '模拟邮件发送失败'
    addAction('error', `模拟邮件发送失败: ${err.message}`)
  } finally {
    simulating.value = false
  }
}

const clearSimulateForm = () => {
  simulateForm.value = {
    from: '',
    to: defaultToEmail.value,
    subject: '',
    text: '',
    html: ''
  }
  addAction('info', '模拟邮件表单已清空')
}

const clearActionLogs = () => {
  recentActions.value = []
  addAction('info', '调试日志已清空')
}

const testSystemConfig = async () => {
  testing.value = true
  apiTestResult.value = null
  
  try {
    const response = await apiService.getSystemConfig()
    apiTestResult.value = response
    addAction('success', '系统配置 API 测试成功')
  } catch (err: any) {
    apiTestResult.value = { error: err.message }
    addAction('error', `系统配置 API 测试失败: ${err.message}`)
  } finally {
    testing.value = false
  }
}

const testUserInfo = async () => {
  testing.value = true
  apiTestResult.value = null
  
  try {
    const response = await apiService.getCurrentUser()
    apiTestResult.value = response
    addAction('success', '用户信息 API 测试成功')
  } catch (err: any) {
    apiTestResult.value = { error: err.message }
    addAction('error', `用户信息 API 测试失败: ${err.message}`)
  } finally {
    testing.value = false
  }
}

const testEmailList = async () => {
  testing.value = true
  apiTestResult.value = null
  
  try {
    const response = await apiService.getEmails({ page: 1, limit: 5 })
    apiTestResult.value = response
    addAction('success', '邮件列表 API 测试成功')
  } catch (err: any) {
    apiTestResult.value = { error: err.message }
    addAction('error', `邮件列表 API 测试失败: ${err.message}`)
  } finally {
    testing.value = false
  }
}

const formatTime = (date: Date): string => {
  return date.toLocaleTimeString('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

// Lifecycle
onMounted(() => {
  // 初始化模拟邮件表单
  simulateForm.value.to = defaultToEmail.value
  simulateForm.value.subject = '调试测试邮件'
  simulateForm.value.text = '这是一封来自调试工具的测试邮件。'
  
  addAction('info', '调试工具已加载')
})
</script>

<style scoped>
.debug-page {
  max-width: 1000px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-6);
  gap: var(--spacing-4);
}

.header-content {
  flex: 1;
}

.page-title {
  font-size: var(--font-size-2xl);
  font-weight: 600;
  color: var(--gray-800);
  margin-bottom: var(--spacing-2);
}

.page-description {
  color: var(--gray-600);
  font-size: var(--font-size-base);
  margin: 0;
}

.header-actions {
  display: flex;
  gap: var(--spacing-3);
}

.debug-status-card {
  margin-bottom: var(--spacing-6);
}

.status-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--spacing-4);
}

.status-item {
  padding: var(--spacing-4);
  background: var(--gray-100);
  border-radius: var(--border-radius);
}

.status-label {
  font-weight: 600;
  color: var(--gray-700);
  font-size: var(--font-size-sm);
  margin-bottom: var(--spacing-2);
}

.status-value {
  font-weight: 500;
}

.status-success {
  color: var(--success-color);
}

.status-danger {
  color: var(--danger-color);
}

.status-info {
  color: var(--gray-800);
}

.simulate-email-card {
  margin-bottom: var(--spacing-6);
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-4);
  margin-bottom: var(--spacing-4);
}

.form-col {
  display: flex;
  flex-direction: column;
}

.form-actions {
  display: flex;
  gap: var(--spacing-3);
  justify-content: flex-start;
}

.recent-actions-card {
  margin-bottom: var(--spacing-6);
}

.actions-list {
  max-height: 300px;
  overflow-y: auto;
}

.action-item {
  display: flex;
  gap: var(--spacing-3);
  padding: var(--spacing-3);
  border-bottom: 1px solid var(--gray-200);
  align-items: flex-start;
}

.action-item:last-child {
  border-bottom: none;
}

.action-time {
  font-size: var(--font-size-sm);
  color: var(--gray-500);
  white-space: nowrap;
  min-width: 80px;
}

.action-content {
  flex: 1;
  font-size: var(--font-size-sm);
}

.action-success .action-content {
  color: var(--success-color);
}

.action-error .action-content {
  color: var(--danger-color);
}

.action-info .action-content {
  color: var(--gray-700);
}

.no-actions {
  text-align: center;
  padding: var(--spacing-8);
  color: var(--gray-500);
}

.actions-footer {
  padding-top: var(--spacing-4);
  border-top: 1px solid var(--gray-200);
  text-align: right;
}

.api-test-card {
  margin-bottom: var(--spacing-6);
}

.test-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-3);
  margin-bottom: var(--spacing-4);
}

.test-result {
  margin-top: var(--spacing-4);
  padding-top: var(--spacing-4);
  border-top: 1px solid var(--gray-200);
}

.test-result h4 {
  margin-bottom: var(--spacing-3);
  color: var(--gray-800);
}

.test-result pre {
  background: var(--gray-100);
  padding: var(--spacing-4);
  border-radius: var(--border-radius);
  overflow-x: auto;
  font-size: var(--font-size-sm);
  line-height: 1.4;
  max-height: 300px;
  overflow-y: auto;
}

.alert {
  padding: var(--spacing-4);
  border-radius: var(--border-radius);
  margin-bottom: var(--spacing-4);
}

.alert-danger {
  background: linear-gradient(135deg, var(--danger-color) 0%, var(--danger-light) 100%);
  color: var(--white);
  border: none;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
    align-items: stretch;
  }
  
  .form-row {
    grid-template-columns: 1fr;
  }
  
  .status-grid {
    grid-template-columns: 1fr;
  }
  
  .test-buttons {
    flex-direction: column;
  }
  
  .form-actions {
    flex-direction: column;
  }
  
  .action-item {
    flex-direction: column;
    gap: var(--spacing-1);
  }
  
  .action-time {
    min-width: auto;
    font-size: var(--font-size-sm);
  }
}
</style>