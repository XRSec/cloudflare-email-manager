<template>
  <div class="admin-settings-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <div class="header-content">
        <h2 class="page-title">🔧 系统设置</h2>
        <p class="page-description">
          管理系统的全局配置和参数
        </p>
      </div>
      <div class="header-actions">
        <button
          class="btn btn-primary"
          @click="refreshSettings"
          :disabled="adminStore.loading"
        >
          <span v-if="adminStore.loading">刷新中...</span>
          <span v-else>🔄 刷新</span>
        </button>
      </div>
    </div>

    <!-- 系统状态卡片 -->
    <div class="system-status-card card">
      <div class="card-header">
        <h3 class="card-title">系统状态</h3>
      </div>
      <div class="status-grid">
        <div class="status-item">
          <div class="status-label">系统版本</div>
          <div class="status-value">v1.0.0 (Vue 3)</div>
        </div>
        <div class="status-item">
          <div class="status-label">运行环境</div>
          <div class="status-value">Cloudflare Workers</div>
        </div>
        <div class="status-item">
          <div class="status-label">数据库</div>
          <div class="status-value">Cloudflare D1</div>
        </div>
        <div class="status-item">
          <div class="status-label">存储</div>
          <div class="status-value">Cloudflare R2</div>
        </div>
      </div>
    </div>

    <!-- 设置表单 -->
    <div class="settings-form-card card">
      <div class="card-header">
        <h3 class="card-title">系统配置</h3>
      </div>

      <form @submit.prevent="handleSaveSettings">
        <!-- 基础设置 -->
        <div class="form-section">
          <h4 class="section-title">基础设置</h4>
          
          <div class="form-row">
            <div class="form-col">
              <div class="form-group">
                <label for="allowRegistration" class="form-label">允许用户注册</label>
                <select
                  id="allowRegistration"
                  v-model="settingsForm.allow_registration"
                  class="form-control"
                  :disabled="saving"
                >
                  <option :value="true">是</option>
                  <option :value="false">否</option>
                </select>
                <small class="form-text text-muted">
                  控制是否允许新用户自由注册账户
                </small>
              </div>
            </div>
            
            <div class="form-col">
              <div class="form-group">
                <label for="debugMode" class="form-label">调试模式</label>
                <select
                  id="debugMode"
                  v-model="settingsForm.debug_mode"
                  class="form-control"
                  :disabled="saving"
                >
                  <option :value="true">开启</option>
                  <option :value="false">关闭</option>
                </select>
                <small class="form-text text-muted">
                  开启后可使用调试工具和模拟邮件功能
                </small>
              </div>
            </div>
          </div>
        </div>

        <!-- 邮件设置 -->
        <div class="form-section">
          <h4 class="section-title">邮件设置</h4>
          
          <div class="form-row">
            <div class="form-col">
              <div class="form-group">
                <label for="cleanupDays" class="form-label">邮件清理天数</label>
                <input
                  id="cleanupDays"
                  v-model.number="settingsForm.cleanup_days"
                  type="number"
                  class="form-control"
                  min="1"
                  max="365"
                  :disabled="saving"
                >
                <small class="form-text text-muted">
                  邮件保存天数，超过此天数的邮件将被自动清理
                </small>
              </div>
            </div>
            
            <div class="form-col">
              <div class="form-group">
                <label for="maxAttachmentSize" class="form-label">最大附件大小 (MB)</label>
                <input
                  id="maxAttachmentSize"
                  v-model.number="maxAttachmentSizeMB"
                  type="number"
                  class="form-control"
                  min="1"
                  max="100"
                  :disabled="saving"
                >
                <small class="form-text text-muted">
                  单个附件的最大大小限制
                </small>
              </div>
            </div>
          </div>
        </div>

        <!-- 域名设置 -->
        <div class="form-section">
          <h4 class="section-title">域名设置</h4>
          
          <div class="form-group">
            <label for="domains" class="form-label">支持的域名</label>
            <textarea
              id="domains"
              v-model="domainsText"
              class="form-control"
              rows="4"
              placeholder="example.com&#10;mail.example.com&#10;temp.example.com"
              :disabled="saving"
            ></textarea>
            <small class="form-text text-muted">
              每行一个域名，第一个域名将作为主域名
            </small>
          </div>
        </div>

        <!-- 安全设置 -->
        <div class="form-section">
          <h4 class="section-title">安全设置</h4>
          
          <div class="form-row">
            <div class="form-col">
              <div class="form-group">
                <label for="jwtSecret" class="form-label">JWT 密钥</label>
                <input
                  id="jwtSecret"
                  v-model="settingsForm.jwt_secret"
                  type="password"
                  class="form-control"
                  placeholder="留空表示不修改"
                  :disabled="saving"
                >
                <small class="form-text text-muted">
                  用于签名 JWT Token，修改后所有用户需要重新登录
                </small>
              </div>
            </div>
            
            <div class="form-col">
              <div class="form-group">
                <label for="adminEmail" class="form-label">管理员邮箱</label>
                <input
                  id="adminEmail"
                  v-model="settingsForm.admin_email"
                  type="email"
                  class="form-control"
                  placeholder="admin@example.com"
                  :disabled="saving"
                >
                <small class="form-text text-muted">
                  用于接收系统通知和重要信息
                </small>
              </div>
            </div>
          </div>
        </div>

        <!-- Cookie 设置 -->
        <div class="form-section">
          <h4 class="section-title">会话设置</h4>
          
          <div class="form-group">
            <label for="cookieMaxAge" class="form-label">会话过期时间 (秒)</label>
            <input
              id="cookieMaxAge"
              v-model.number="settingsForm.cookie_max_age"
              type="number"
              class="form-control"
              min="3600"
              max="2592000"
              :disabled="saving"
            >
            <small class="form-text text-muted">
              用户登录状态的保持时间，建议设置为 7 天 (604800 秒)
            </small>
          </div>
        </div>

        <!-- 错误信息 -->
        <div v-if="adminStore.error" class="alert alert-danger">
          {{ adminStore.error }}
        </div>

        <!-- 操作按钮 -->
        <div class="form-actions">
          <button
            type="submit"
            class="btn btn-primary"
            :disabled="saving || !hasChanges"
          >
            <span v-if="saving">保存中...</span>
            <span v-else">💾 保存设置</span>
          </button>
          <button
            type="button"
            class="btn btn-light"
            @click="resetForm"
            :disabled="saving"
          >
            重置
          </button>
        </div>
      </form>
    </div>

    <!-- 危险操作 -->
    <div class="danger-zone-card card">
      <div class="card-header">
        <h3 class="card-title text-danger">⚠️ 危险操作</h3>
        <p class="text-muted">以下操作具有风险，请谨慎执行</p>
      </div>
      
      <div class="danger-actions">
        <div class="danger-action">
          <div class="action-info">
            <h4>清理过期邮件</h4>
            <p>立即清理超过保留期限的邮件和附件</p>
          </div>
          <button
            class="btn btn-warning"
            @click="cleanupExpiredEmails"
            :disabled="cleaningUp"
          >
            <span v-if="cleaningUp">清理中...</span>
            <span v-else">🧹 立即清理</span>
          </button>
        </div>
        
        <div class="danger-action">
          <div class="action-info">
            <h4>重置系统配置</h4>
            <p>将所有系统配置恢复为默认值</p>
          </div>
          <button
            class="btn btn-danger"
            @click="resetSystemConfig"
            :disabled="resetting"
          >
            <span v-if="resetting">重置中...</span>
            <span v-else">🔄 重置配置</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useAdminStore } from '@/stores/admin'
import { useSystemStore } from '@/stores/system'
import type { SystemConfig } from '@/types'

// Composables
const adminStore = useAdminStore()
const systemStore = useSystemStore()

// State
const saving = ref(false)
const cleaningUp = ref(false)
const resetting = ref(false)
const domainsText = ref('')

const settingsForm = ref<SystemConfig>({
  allow_registration: false,
  cleanup_days: 7,
  max_attachment_size: 52428800, // 50MB
  debug_mode: false,
  domains: [],
  cookie_max_age: 604800, // 7 days
  jwt_secret: '',
  admin_email: ''
})

const originalSettings = ref<SystemConfig | null>(null)

// Computed
const maxAttachmentSizeMB = computed({
  get: () => Math.round(settingsForm.value.max_attachment_size / 1024 / 1024),
  set: (value: number) => {
    settingsForm.value.max_attachment_size = value * 1024 * 1024
  }
})

const hasChanges = computed(() => {
  if (!originalSettings.value) return false
  
  return JSON.stringify(settingsForm.value) !== JSON.stringify(originalSettings.value) ||
         domainsText.value !== originalSettings.value.domains.join('\n')
})

// Watch domains text changes
watch(domainsText, (newValue) => {
  settingsForm.value.domains = newValue
    .split('\n')
    .map(domain => domain.trim())
    .filter(domain => domain.length > 0)
})

// Methods
const refreshSettings = async () => {
  await adminStore.loadAdminSettings()
  loadFormData()
}

const loadFormData = () => {
  if (adminStore.adminConfig) {
    settingsForm.value = { 
      ...adminStore.adminConfig,
      domains: [...adminStore.adminConfig.domains]
    }
    domainsText.value = adminStore.adminConfig.domains.join('\n')
    originalSettings.value = { 
      ...adminStore.adminConfig,
      domains: [...adminStore.adminConfig.domains]
    }
  }
}

const handleSaveSettings = async () => {
  adminStore.clearError()
  saving.value = true
  
  try {
    const success = await adminStore.updateAdminSettings(settingsForm.value)
    
    if (success) {
      showMessage('系统设置保存成功', 'success')
      originalSettings.value = { ...settingsForm.value }
      
      // 刷新系统配置
      await systemStore.loadConfig()
    }
  } catch (error) {
    console.error('保存系统设置失败:', error)
  } finally {
    saving.value = false
  }
}

const resetForm = () => {
  if (originalSettings.value) {
    settingsForm.value = { ...originalSettings.value }
    domainsText.value = originalSettings.value.domains.join('\n')
  }
  adminStore.clearError()
}

const cleanupExpiredEmails = async () => {
  const confirmText = `确定要立即清理过期邮件吗？\n\n此操作将：\n- 删除超过 ${settingsForm.value.cleanup_days} 天的邮件\n- 删除相关的附件文件\n\n此操作不可恢复！`
  
  if (!confirm(confirmText)) {
    return
  }

  cleaningUp.value = true
  try {
    // 这里应该调用清理邮件的 API
    await new Promise(resolve => setTimeout(resolve, 3000))
    showMessage('过期邮件清理完成', 'success')
  } catch (error) {
    showMessage('清理过期邮件失败', 'error')
  } finally {
    cleaningUp.value = false
  }
}

const resetSystemConfig = async () => {
  const confirmText = `确定要重置所有系统配置吗？\n\n此操作将：\n- 恢复所有配置为默认值\n- 不会影响用户数据和邮件\n- 需要重新配置系统参数\n\n此操作不可恢复！`
  
  if (!confirm(confirmText)) {
    return
  }

  resetting.value = true
  try {
    // 这里应该调用重置配置的 API
    await new Promise(resolve => setTimeout(resolve, 2000))
    showMessage('系统配置已重置', 'success')
    await refreshSettings()
  } catch (error) {
    showMessage('重置系统配置失败', 'error')
  } finally {
    resetting.value = false
  }
}

const showMessage = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
  // 这里应该使用全局消息组件
  console.log(`[${type.toUpperCase()}] ${message}`)
}

// Lifecycle
onMounted(async () => {
  await refreshSettings()
})
</script>

<style scoped>
.admin-settings-page {
  max-width: 900px;
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

.system-status-card {
  margin-bottom: var(--spacing-6);
}

.status-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-4);
}

.status-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-1);
  padding: var(--spacing-3);
  background: var(--gray-100);
  border-radius: var(--border-radius);
}

.status-label {
  font-weight: 500;
  color: var(--gray-700);
  font-size: var(--font-size-sm);
}

.status-value {
  color: var(--gray-800);
  font-weight: 600;
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
  margin-bottom: var(--spacing-4);
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

.form-text {
  font-size: var(--font-size-sm);
  margin-top: var(--spacing-1);
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
  padding-top: var(--spacing-4);
  border-top: 1px solid var(--gray-200);
}

.danger-zone-card {
  border: 2px solid var(--danger-color);
  margin-bottom: var(--spacing-6);
}

.danger-zone-card .card-header {
  background: rgba(220, 53, 69, 0.1);
  border-bottom: 1px solid var(--danger-color);
}

.text-danger {
  color: var(--danger-color) !important;
}

.danger-actions {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-6);
}

.danger-action {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-4);
  border: 1px solid var(--gray-200);
  border-radius: var(--border-radius);
  gap: var(--spacing-4);
}

.action-info {
  flex: 1;
}

.action-info h4 {
  font-size: var(--font-size-base);
  font-weight: 600;
  color: var(--gray-800);
  margin-bottom: var(--spacing-1);
}

.action-info p {
  color: var(--gray-600);
  font-size: var(--font-size-sm);
  margin: 0;
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
    grid-template-columns: repeat(2, 1fr);
  }
  
  .form-actions {
    flex-direction: column;
  }
  
  .danger-action {
    flex-direction: column;
    align-items: stretch;
    text-align: center;
    gap: var(--spacing-3);
  }
}

@media (max-width: 480px) {
  .status-grid {
    grid-template-columns: 1fr;
  }
}
</style>