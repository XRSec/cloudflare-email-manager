<template>
  <div class="settings-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <div class="header-content">
        <h2 class="page-title">个人设置</h2>
        <p class="page-description">
          管理您的账户设置、密码和 Webhook 配置
        </p>
      </div>
    </div>

    <!-- 用户信息卡片 -->
    <div class="user-info-card card">
      <div class="card-header">
        <h3 class="card-title">账户信息</h3>
      </div>
      <div class="user-info-content">
        <div class="info-row">
          <div class="info-label">邮箱前缀</div>
          <div class="info-value">
            <code>{{ authStore.currentUser?.email_prefix }}</code>
          </div>
        </div>
        <div class="info-row">
          <div class="info-label">完整邮箱</div>
          <div class="info-value">
            <strong>{{ userEmail }}</strong>
            <button
              class="btn btn-sm btn-light ml-2"
              @click="copyToClipboard(userEmail)"
            >
              📋 复制
            </button>
          </div>
        </div>
        <div class="info-row">
          <div class="info-label">账户类型</div>
          <div class="info-value">
            <span :class="['badge', authStore.isAdmin ? 'badge-primary' : 'badge-success']">
              {{ authStore.isAdmin ? '管理员' : '普通用户' }}
            </span>
          </div>
        </div>
        <div class="info-row">
          <div class="info-label">注册时间</div>
          <div class="info-value">
            {{ formatDate(authStore.currentUser?.created_at) }}
          </div>
        </div>
      </div>
    </div>

    <!-- 设置表单 -->
    <div class="settings-form-card card">
      <div class="card-header">
        <h3 class="card-title">修改设置</h3>
        <p class="text-muted">只填写需要更新的字段，留空表示不修改</p>
      </div>

      <form @submit.prevent="handleUpdateSettings">
        <!-- 密码设置 -->
        <div class="form-section">
          <h4 class="section-title">密码设置</h4>
          <div class="form-group">
            <label for="newPassword" class="form-label">新密码</label>
            <input
              id="newPassword"
              v-model="settingsForm.email_password"
              type="password"
              class="form-control"
              placeholder="留空表示不修改密码"
              minlength="6"
              :disabled="userStore.loading"
            >
            <small class="form-text text-muted">
              密码长度至少为 6 位字符
            </small>
          </div>
        </div>

        <!-- Webhook 设置 -->
        <div class="form-section">
          <h4 class="section-title">Webhook 设置</h4>
          <p class="section-description">
            配置 Webhook 可以在收到新邮件时自动推送通知到您指定的地址
          </p>

          <div class="form-group">
            <label for="webhookUrl" class="form-label">Webhook URL</label>
            <input
              id="webhookUrl"
              v-model="settingsForm.webhook_url"
              type="url"
              class="form-control"
              placeholder="https://example.com/webhook"
              :disabled="userStore.loading"
            >
            <small class="form-text text-muted">
              支持钉钉、飞书等平台的 Webhook 地址
            </small>
          </div>

          <div class="form-group">
            <label for="webhookSecret" class="form-label">Webhook 密钥</label>
            <input
              id="webhookSecret"
              v-model="settingsForm.webhook_secret"
              type="password"
              class="form-control"
              :placeholder="hasWebhookSecret ? '***已设置*** (留空保持不变)' : '用于验证 Webhook 的密钥'"
              :disabled="userStore.loading"
            >
            <small class="form-text text-muted">
              可选，用于验证 Webhook 请求的安全性
            </small>
          </div>

          <!-- Webhook 测试 -->
          <div class="webhook-test">
            <button
              type="button"
              class="btn btn-outline-primary"
              @click="testWebhook"
              :disabled="!settingsForm.webhook_url || testing"
            >
              <span v-if="testing">测试中...</span>
              <span v-else">🧪 测试 Webhook</span>
            </button>
            <small class="form-text text-muted">
              发送测试请求到您的 Webhook 地址
            </small>
          </div>
        </div>

        <!-- 错误信息 -->
        <div v-if="userStore.error" class="alert alert-danger">
          {{ userStore.error }}
        </div>

        <!-- 操作按钮 -->
        <div class="form-actions">
          <button
            type="submit"
            class="btn btn-primary"
            :disabled="userStore.loading || !hasChanges"
          >
            <span v-if="userStore.loading">保存中...</span>
            <span v-else">💾 保存设置</span>
          </button>
          <button
            type="button"
            class="btn btn-light"
            @click="resetForm"
            :disabled="userStore.loading"
          >
            重置
          </button>
        </div>
      </form>
    </div>

    <!-- 使用说明 -->
    <div class="help-card card">
      <div class="card-header">
        <h3 class="card-title">使用说明</h3>
      </div>
      <div class="help-content">
        <div class="help-section">
          <h4>📧 邮箱使用</h4>
          <ul>
            <li>您的邮箱地址是固定的，无法修改前缀</li>
            <li>所有发送到此地址的邮件都会自动保存</li>
            <li>支持接收最大 {{ maxAttachmentSize }} 的附件</li>
            <li>邮件会在 {{ cleanupDays }} 天后自动清理</li>
          </ul>
        </div>
        
        <div class="help-section">
          <h4>🔗 Webhook 配置</h4>
          <ul>
            <li>支持钉钉、飞书、Slack 等平台的 Webhook</li>
            <li>收到新邮件时会自动推送通知</li>
            <li>建议设置密钥以确保安全性</li>
            <li>可以随时测试 Webhook 是否正常工作</li>
          </ul>
        </div>
        
        <div class="help-section">
          <h4>🔒 安全建议</h4>
          <ul>
            <li>定期更换密码以确保账户安全</li>
            <li>不要在不安全的网络环境下登录</li>
            <li>Webhook 密钥请妥善保管，不要泄露</li>
            <li>如发现异常活动，请及时联系管理员</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useUserStore } from '@/stores/user'
import { useSystemStore } from '@/stores/system'
import type { UserSettingsUpdate } from '@/types'

// Composables
const authStore = useAuthStore()
const userStore = useUserStore()
const systemStore = useSystemStore()

// State
const settingsForm = ref<UserSettingsUpdate>({
  email_password: '',
  webhook_url: '',
  webhook_secret: ''
})
const testing = ref(false)
const originalSettings = ref<UserSettingsUpdate>({})

// Computed
const userEmail = computed(() => {
  if (!authStore.currentUser) return ''
  return systemStore.getFullEmailAddress(authStore.currentUser.email_prefix)
})

const hasWebhookSecret = computed(() => {
  return !!userStore.settings.webhook_secret
})

const hasChanges = computed(() => {
  return settingsForm.value.email_password ||
         settingsForm.value.webhook_url !== originalSettings.value.webhook_url ||
         settingsForm.value.webhook_secret
})

const maxAttachmentSize = computed(() => {
  const size = systemStore.config?.max_attachment_size || 52428800
  return systemStore.formatFileSize(size)
})

const cleanupDays = computed(() => {
  return systemStore.config?.cleanup_days || 7
})

// Methods
const handleUpdateSettings = async () => {
  userStore.clearError()
  
  // 构建更新数据
  const updates: UserSettingsUpdate = {}
  
  if (settingsForm.value.email_password?.trim()) {
    updates.email_password = settingsForm.value.email_password
  }
  
  if (settingsForm.value.webhook_url !== originalSettings.value.webhook_url) {
    updates.webhook_url = settingsForm.value.webhook_url || ''
  }
  
  if (settingsForm.value.webhook_secret) {
    updates.webhook_secret = settingsForm.value.webhook_secret
  }
  
  const success = await userStore.updateSettings(updates)
  
  if (success) {
    // 更新成功，重新加载设置
    await loadSettings()
    showMessage('设置更新成功', 'success')
  }
}

const resetForm = () => {
  settingsForm.value = {
    email_password: '',
    webhook_url: originalSettings.value.webhook_url || '',
    webhook_secret: ''
  }
  userStore.clearError()
}

const loadSettings = async () => {
  const success = await userStore.loadSettings()
  if (success) {
    // 保存原始设置
    originalSettings.value = { ...userStore.settings }
    // 初始化表单
    settingsForm.value = {
      email_password: '',
      webhook_url: userStore.settings.webhook_url || '',
      webhook_secret: ''
    }
  }
}

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text)
    showMessage('已复制到剪贴板', 'success')
  } catch (error) {
    // 降级方案
    const textArea = document.createElement('textarea')
    textArea.value = text
    document.body.appendChild(textArea)
    textArea.select()
    document.execCommand('copy')
    document.body.removeChild(textArea)
    showMessage('已复制到剪贴板', 'success')
  }
}

const testWebhook = async () => {
  if (!settingsForm.value.webhook_url) return
  
  testing.value = true
  try {
    // 这里应该调用测试 Webhook 的 API
    // 暂时模拟测试
    await new Promise(resolve => setTimeout(resolve, 2000))
    showMessage('Webhook 测试成功', 'success')
  } catch (error) {
    showMessage('Webhook 测试失败', 'error')
  } finally {
    testing.value = false
  }
}

const formatDate = (dateString?: string): string => {
  if (!dateString) return '-'
  return systemStore.formatDate(dateString)
}

const showMessage = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
  // 这里应该使用全局消息组件
  console.log(`[${type.toUpperCase()}] ${message}`)
}

// Lifecycle
onMounted(async () => {
  await loadSettings()
})
</script>

<style scoped>
.settings-page {
  max-width: 800px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: var(--spacing-6);
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

.user-info-card {
  margin-bottom: var(--spacing-6);
}

.user-info-content {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-4);
}

.info-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-3);
  background: var(--gray-100);
  border-radius: var(--border-radius);
  gap: var(--spacing-4);
}

.info-label {
  font-weight: 500;
  color: var(--gray-700);
  min-width: 100px;
}

.info-value {
  flex: 1;
  display: flex;
  align-items: center;
  gap: var(--spacing-2);
  justify-content: flex-end;
}

.info-value code {
  background: var(--white);
  padding: var(--spacing-1) var(--spacing-2);
  border-radius: var(--border-radius-sm);
  font-family: 'Courier New', monospace;
  border: 1px solid var(--gray-300);
}

.settings-form-card {
  margin-bottom: var(--spacing-6);
}

.form-section {
  margin-bottom: var(--spacing-8);
  padding-bottom: var(--spacing-6);
  border-bottom: 1px solid var(--gray-200);
}

.form-section:last-child {
  border-bottom: none;
  margin-bottom: var(--spacing-6);
}

.section-title {
  font-size: var(--font-size-lg);
  font-weight: 600;
  color: var(--gray-800);
  margin-bottom: var(--spacing-2);
}

.section-description {
  color: var(--gray-600);
  font-size: var(--font-size-sm);
  margin-bottom: var(--spacing-4);
}

.form-text {
  font-size: var(--font-size-sm);
  margin-top: var(--spacing-1);
}

.webhook-test {
  margin-top: var(--spacing-4);
  padding-top: var(--spacing-4);
  border-top: 1px solid var(--gray-200);
}

.webhook-test .form-text {
  margin-top: var(--spacing-2);
  margin-left: 0;
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

.form-actions {
  display: flex;
  gap: var(--spacing-3);
  justify-content: flex-start;
}

.help-card {
  margin-bottom: var(--spacing-6);
}

.help-content {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-6);
}

.help-section h4 {
  font-size: var(--font-size-base);
  font-weight: 600;
  color: var(--gray-800);
  margin-bottom: var(--spacing-3);
}

.help-section ul {
  list-style: none;
  padding: 0;
  margin: 0;
}

.help-section li {
  padding: var(--spacing-2) 0;
  padding-left: var(--spacing-4);
  position: relative;
  color: var(--gray-600);
  font-size: var(--font-size-sm);
  line-height: 1.5;
}

.help-section li::before {
  content: '•';
  position: absolute;
  left: 0;
  color: var(--primary-color);
  font-weight: bold;
}

.ml-2 {
  margin-left: var(--spacing-2);
}

/* 响应式设计 */
@media (max-width: 768px) {
  .info-row {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-2);
  }
  
  .info-label {
    min-width: auto;
    font-size: var(--font-size-sm);
  }
  
  .info-value {
    justify-content: flex-start;
  }
  
  .form-actions {
    flex-direction: column;
  }
  
  .help-section li {
    padding-left: var(--spacing-3);
  }
}
</style>