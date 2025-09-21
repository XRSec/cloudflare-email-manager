<template>
  <div class="admin-page">
    <div class="page-header">
      <h1>{{ pageIcon }} {{ pageTitle }}</h1>
    </div>

    <div class="page-content">
      <LoadingOverlay v-if="loading" :text="loadingText" />

      <!-- 个人设置 -->
      <div v-if="!loading && isPersonalSettings" class="settings-container">
        <!-- 密码设置 -->
        <div class="settings-section">
          <h3>密码设置</h3>
          <div class="form-group">
            <label class="form-label">新密码</label>
            <input v-model="passwordForm.newPassword" type="password" class="form-control" placeholder="输入新密码（至少6位）"
              minlength="6" />
          </div>
          <div class="form-actions">
            <button class="btn btn-primary" @click="updatePassword" :disabled="loading">
              {{ loading ? '更新中...' : '更新密码' }}
            </button>
          </div>
        </div>

        <!-- Webhook 设置 -->
        <div class="settings-section">
          <h3>Webhook 设置</h3>
          <div class="form-group">
            <label class="form-label">Webhook URL</label>
            <input v-model="webhookForm.url" type="url" class="form-control"
              placeholder="https://example.com/webhook" />
            <div class="form-help">当有新邮件时，系统会向此URL发送POST请求</div>
          </div>
          <div class="form-group">
            <label class="form-label">Webhook 密钥</label>
            <input v-model="webhookForm.secret" type="text" class="form-control" placeholder="可选，用于验证请求的安全密钥" />
            <div class="form-help">用于验证webhook请求的HMAC签名</div>
          </div>
          <div class="form-actions">
            <button class="btn btn-primary" @click="updateWebhook" :disabled="loading">
              {{ loading ? '更新中...' : '更新 Webhook' }}
            </button>
            <button v-if="webhookForm.url" class="btn btn-secondary" @click="testWebhook" :disabled="loading">
              测试 Webhook
            </button>
          </div>
        </div>
      </div>

      <!-- 系统设置 -->
      <div v-if="!loading && !isPersonalSettings" class="settings-container">
        <!-- 基本设置 -->
        <div class="settings-section">
          <h3>基本设置</h3>

          <div class="form-group">
            <div class="form-switch">
              <label class="form-label">调试模式</label>
              <label class="switch">
                <input v-model="systemConfig.debug_mode" type="checkbox">
                <span class="slider"></span>
              </label>
            </div>
          </div>

          <div class="form-group">
            <div class="form-switch">
              <label class="form-label">允许注册</label>
              <label class="switch">
                <input v-model="systemConfig.allow_registration" type="checkbox">
                <span class="slider"></span>
              </label>
            </div>
          </div>

          <div class="form-group">
            <div class="form-switch">
              <label class="form-label">自动审核邮箱</label>
              <label class="switch">
                <input v-model="systemConfig.auto_approve_mailbox" type="checkbox">
                <span class="slider"></span>
              </label>
            </div>
          </div>
        </div>

        <!-- 邮箱设置 -->
        <div class="settings-section">
          <h3>邮箱设置</h3>

          <div class="form-group">
            <label class="form-label">支持的域名</label>
            <div class="form-tags">
              <div v-for="(domain, index) in systemConfig.supported_domains" :key="index" class="tag">
                {{ domain }}
                <button type="button" class="tag-remove" @click="removeDomain(index)">×</button>
              </div>
              <input v-model="newDomain" type="text" class="form-control tag-input" placeholder="添加域名..."
                @keyup.enter="addDomain">
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">邮件保留天数</label>
            <input v-model.number="systemConfig.mail_retention_days" type="number" class="form-control" min="1"
              max="365">
          </div>

          <div class="form-group">
            <label class="form-label">附件最大大小 (MB)</label>
            <input v-model.number="systemConfig.attachment_max_size" type="number" class="form-control" min="1"
              max="50">
          </div>
        </div>

        <!-- JWT 和安全设置 -->
        <div class="settings-section">
          <h3>JWT 和安全设置</h3>

          <div class="form-group">
            <label class="form-label">JWT 密钥</label>
            <input v-model="jwtSecretInput" type="text" class="form-control"
              :placeholder="jwtSecretInput ? '当前 JWT 密钥 (点击编辑)' : '输入新的 JWT 密钥 (留空则自动生成新密钥)'"
              :readonly="!jwtSecretModified && !!jwtSecretInput" @input="jwtSecretModified = true"
              @focus="jwtSecretModified = true">
            <small class="form-text">JWT 密钥用于用户认证，显示为掩码格式，留空则自动生成新的密钥</small>
          </div>

          <div class="form-group">
            <label class="form-label">Cookie 最大年龄 (秒)</label>
            <input v-model.number="systemConfig.cookie_max_age" type="number" class="form-control" min="60" max="86400">
          </div>

          <div class="form-group">
            <label class="form-label">管理员邮箱</label>
            <input v-model="systemConfig.admin_email" type="email" class="form-control" placeholder="admin@example.com">
          </div>
        </div>

        <!-- 存储设置 -->
        <div class="settings-section">
          <h3>存储设置</h3>

          <div class="form-group">
            <label class="form-label">存储提供商</label>
            <select v-model="systemConfig.storage_provider" class="form-control">
              <option value="r2">Cloudflare R2</option>
              <option value="s3">Amazon S3</option>
              <option value="local">本地存储</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">每个用户最大邮箱数</label>
            <input v-model.number="systemConfig.max_mailboxes_per_user" type="number" class="form-control" min="1"
              max="100">
          </div>

          <div class="form-group">
            <div class="form-switch">
              <label class="form-label">允许用户发送邮件</label>
              <label class="switch">
                <input v-model="systemConfig.allow_user_send" type="checkbox">
                <span class="slider"></span>
              </label>
            </div>
          </div>
        </div>

        <!-- 操作按钮 -->
        <div class="settings-actions">
          <button class="btn btn-primary" @click="saveSettings" :disabled="loading">
            {{ loading ? '保存中...' : '保存设置' }}
          </button>
          <button class="btn btn-secondary" @click="resetSettings" :disabled="loading">
            重置
          </button>
          <button class="btn btn-warning" @click="clearCache" :disabled="loading">
            清除缓存
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { apiService } from '@/composables/api'
import { useAuthStore, useSystemStore } from '@/composables/stores'
import { cacheService } from '@/composables/cache'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'

const route = useRoute()
const authStore = useAuthStore()
const systemStore = useSystemStore()

// 检测是否为个人设置页面
const isPersonalSettings = computed(() => route.name === 'settings')

// 页面标题和图标
const pageTitle = computed(() =>
  isPersonalSettings.value ? '个人设置' : '系统设置'
)
const pageIcon = computed(() =>
  isPersonalSettings.value ? '⚙️' : '🛠️'
)

// 加载文本
const loadingText = computed(() =>
  isPersonalSettings.value ? '加载个人设置...' : '加载系统配置...'
)

const loading = ref(false)

// 个人设置表单
const passwordForm = ref({
  newPassword: ''
})

const webhookForm = ref({
  url: '',
  secret: ''
})

// JWT 密钥输入
const jwtSecretInput = ref('')
const jwtSecretModified = ref(false) // 跟踪是否修改过 JWT 密钥

// 系统配置
const systemConfig = ref({
  debug_mode: false,
  allow_registration: false,
  auto_approve_mailbox: false,
  supported_domains: [] as string[],
  mail_retention_days: 30,
  attachment_max_size: 50,
  allow_user_send: false,
  max_mailboxes_per_user: 5,
  storage_provider: 'r2',
  cleanup_days: 30,
  max_attachment_size: 52428800, // 50MB in bytes
  cookie_max_age: 86400, // 24 hours
  jwt_secret: '',
  admin_email: '',
  primary_domain: '',
  domains: [] as string[]
})

// 加载系统配置
const loadSystemConfig = async (forceRefresh = false) => {
  loading.value = true
  try {
    const cacheKey = 'system-config'

    // 检查缓存
    if (!forceRefresh) {
      const cached = cacheService.get<typeof systemConfig.value>(cacheKey)
      if (cached) {
        console.log('从缓存加载系统配置')
        systemConfig.value = cached

        // 检查缓存中是否有 JWT 密钥信息
        if (cached.jwt_secret) {
          jwtSecretInput.value = cached.jwt_secret
          console.log('从缓存设置JWT密钥输入框:', jwtSecretInput.value)
        } else {
          console.log('缓存中没有JWT密钥信息，需要从API获取')
          // 如果缓存中没有JWT密钥，强制从API获取
          forceRefresh = true
        }

        if (!forceRefresh) {
          loading.value = false
          return
        }
      }
    }

    // 从API获取
    console.log('从API加载系统配置')
    const response = await apiService.getSystemConfig()
    console.log('API响应:', response)
    if (response.success && response.data) {
      const config = {
        debug_mode: response.data.config.debug_mode === 1 || response.data.config.debug_mode === '1' || response.data.config.debug_mode === true,
        allow_registration: response.data.config.allow_registration === 1 || response.data.config.allow_registration === '1' || response.data.config.allow_registration === true,
        auto_approve_mailbox: response.data.config.auto_approve_mailbox === 1 || response.data.config.auto_approve_mailbox === '1' || response.data.config.auto_approve_mailbox === true,
        supported_domains: response.data.config.supported_domains || [],
        mail_retention_days: response.data.config.mail_retention_days || 30,
        attachment_max_size: response.data.config.attachment_max_size ? Math.round(response.data.config.attachment_max_size / 1024 / 1024) : 50,
        allow_user_send: response.data.config.allow_user_send === 1 || response.data.config.allow_user_send === '1' || response.data.config.allow_user_send === true,
        max_mailboxes_per_user: response.data.config.max_mailboxes_per_user || 5,
        storage_provider: response.data.config.storage_provider || 'r2',
        cleanup_days: response.data.config.cleanup_days || 30,
        max_attachment_size: response.data.config.max_attachment_size || 52428800,
        cookie_max_age: response.data.config.cookie_max_age || 86400,
        jwt_secret: response.data.config.jwt_secret || '',
        admin_email: response.data.config.admin_email || '',
        primary_domain: response.data.config.primary_domain || '',
        domains: response.data.config.domains || []
      }

      systemConfig.value = config

      // 显示当前的 JWT 密钥（掩码格式）
      if (response.data.config.jwt_secret) {
        jwtSecretInput.value = response.data.config.jwt_secret
        // 将 JWT 密钥也存储到配置中，以便缓存
        config.jwt_secret = response.data.config.jwt_secret
      }

      // 存入缓存（5分钟）
      cacheService.set(cacheKey, config, 5 * 60 * 1000)
    }
  } catch (error) {
    console.error('加载系统配置失败:', error)
  } finally {
    loading.value = false
  }
}

// 刷新数据
const refreshData = async () => {
  loading.value = true
  try {
    await loadSystemConfig(true)
    // 同时更新全局 systemStore
    await systemStore.fetchSystemConfig()
  } catch (error) {
    console.error('刷新数据失败:', error)
  } finally {
    loading.value = false
  }
}

// 加载个人设置
const loadPersonalSettings = async () => {
  loading.value = true
  try {
    // 从用户信息中加载webhook设置
    if (authStore.user?.settings) {
      webhookForm.value.url = authStore.user.settings.webhook_url || ''
      webhookForm.value.secret = authStore.user.settings.webhook_secret || ''
    }
  } catch (error) {
    console.error('加载个人设置失败:', error)
  } finally {
    loading.value = false
  }
}

// 更新密码
const updatePassword = async () => {
  if (!passwordForm.value.newPassword) {
    alert('请输入新密码')
    return
  }

  if (passwordForm.value.newPassword.length < 6) {
    alert('密码至少需要6位')
    return
  }

  loading.value = true
  try {
    const response = await apiService.updateUserSettings({
      password: passwordForm.value.newPassword
    })

    if (response.success) {
      alert('密码更新成功')
      passwordForm.value.newPassword = ''
    } else {
      alert(response.message || '密码更新失败')
    }
  } catch (error) {
    console.error('更新密码失败:', error)
    alert('更新密码失败')
  } finally {
    loading.value = false
  }
}

// 更新Webhook设置
const updateWebhook = async () => {
  loading.value = true
  try {
    const response = await apiService.updateUserSettings({
      webhook_url: webhookForm.value.url,
      webhook_secret: webhookForm.value.secret
    })

    if (response.success) {
      alert('Webhook 设置更新成功')
      // 更新用户信息
      await authStore.fetchCurrentUser()
    } else {
      alert(response.message || 'Webhook 设置更新失败')
    }
  } catch (error) {
    console.error('更新 Webhook 设置失败:', error)
    alert('更新 Webhook 设置失败')
  } finally {
    loading.value = false
  }
}

// 测试Webhook (暂时禁用，API 未实现)
const testWebhook = async () => {
  alert('Webhook 测试功能暂未实现')
}

// 全局刷新事件处理
const handleGlobalRefresh = () => {
  console.log('🔄 系统设置页面收到全局刷新事件')
  if (isPersonalSettings.value) {
    loadPersonalSettings()
  } else {
    // 强制刷新系统配置
    loadSystemConfig(true)
  }
}

// 页面加载时获取数据
onMounted(() => {
  if (isPersonalSettings.value) {
    loadPersonalSettings()
  } else {
    // 正常加载，使用缓存机制
    loadSystemConfig()
  }

  // 监听全局刷新事件
  window.addEventListener('global:refresh', handleGlobalRefresh)
})

// 页面卸载时清理事件监听
onUnmounted(() => {
  window.removeEventListener('global:refresh', handleGlobalRefresh)
})

// 新域名输入
const newDomain = ref('')

// 添加域名
const addDomain = () => {
  const domain = newDomain.value.trim()
  if (domain && !systemConfig.value.supported_domains.includes(domain)) {
    systemConfig.value.supported_domains.push(domain)
    newDomain.value = ''
  }
}

// 删除域名
const removeDomain = (index: number) => {
  systemConfig.value.supported_domains.splice(index, 1)
}

// 保存设置
const saveSettings = async () => {
  try {
    // 转换配置为后端格式
    const configToSave: any = {
      debug_mode: systemConfig.value.debug_mode ? 1 : 0,
      allow_registration: systemConfig.value.allow_registration ? 1 : 0,
      auto_approve_mailbox: systemConfig.value.auto_approve_mailbox ? 1 : 0,
      supported_domains: systemConfig.value.supported_domains,
      mail_retention_days: systemConfig.value.mail_retention_days,
      attachment_max_size: systemConfig.value.attachment_max_size * 1024 * 1024,
      allow_user_send: systemConfig.value.allow_user_send ? 1 : 0,
      max_mailboxes_per_user: systemConfig.value.max_mailboxes_per_user,
      storage_provider: systemConfig.value.storage_provider,
      cleanup_days: systemConfig.value.cleanup_days,
      max_attachment_size: systemConfig.value.max_attachment_size,
      cookie_max_age: systemConfig.value.cookie_max_age,
      admin_email: systemConfig.value.admin_email,
      primary_domain: systemConfig.value.primary_domain,
      domains: systemConfig.value.domains
    }

    // JWT 密钥处理：只有在用户实际修改时才携带
    if (jwtSecretModified.value) {
      if (jwtSecretInput.value.trim() !== '') {
        // 有输入则使用输入值
        configToSave.jwt_secret = jwtSecretInput.value.trim()
      } else {
        // 输入框被清空则传递空字符串让后端自动生成
        configToSave.jwt_secret = ''
      }
    }
    // 如果输入框从未被修改过，则不携带 jwt_secret 字段

    const response = await apiService.updateSystemConfig(configToSave)
    if (response.success) {
      alert('设置保存成功')
      // 重置修改标记
      jwtSecretModified.value = false
      // 同时更新全局 systemStore 和本地数据
      await systemStore.fetchSystemConfig()
      await refreshData()
    } else {
      alert('保存失败: ' + (response.message || '未知错误'))
    }
  } catch (error) {
    console.error('保存设置失败:', error)
    alert('保存设置失败')
  }
}

// 重置设置
const resetSettings = async () => {
  if (confirm('确定要重置所有设置吗？')) {
    await refreshData()
  }
}

// 清除缓存
const clearCache = async () => {
  try {
    const response = await apiService.clearSystemCache()
    if (response.success) {
      alert('缓存清除成功')
    } else {
      alert('清除缓存失败: ' + (response.message || '未知错误'))
    }
  } catch (error) {
    console.error('清除缓存失败:', error)
    alert('清除缓存失败')
  }
}
</script>

<style scoped>
.settings-container {
  max-width: 800px;
  margin: 0 auto;
}

.settings-section {
  background: white;
  border-radius: 10px;
  padding: 20px;
  margin-bottom: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.settings-section h3 {
  margin: 0 0 20px 0;
  color: #2c3e50;
  font-size: 1.2rem;
  border-bottom: 2px solid #ecf0f1;
  padding-bottom: 10px;
}

.form-group {
  margin-bottom: 20px;
}

.form-label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
  color: #2c3e50;
}

.form-switch {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 15px;
}

.form-label {
  flex: 1;
}

.switch {
  position: relative;
  display: inline-block;
  width: 50px;
  height: 24px;
  flex-shrink: 0;
}

.switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: #ccc;
  transition: .4s;
  border-radius: 24px;
}

.slider:before {
  position: absolute;
  content: "";
  height: 18px;
  width: 18px;
  left: 3px;
  bottom: 3px;
  background-color: white;
  transition: .4s;
  border-radius: 50%;
}

input:checked+.slider {
  background-color: #3498db;
}

input:checked+.slider:before {
  transform: translateX(26px);
}

.form-control {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
  font-size: 14px;
}

.form-control:focus {
  outline: none;
  border-color: #3498db;
  box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
}

.form-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
  min-height: 40px;
}

.tag {
  display: inline-flex;
  align-items: center;
  background: #3498db;
  color: white;
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  gap: 4px;
}

.tag-remove {
  background: none;
  border: none;
  color: white;
  cursor: pointer;
  font-size: 16px;
  line-height: 1;
  padding: 0;
  margin-left: 4px;
}

.tag-input {
  border: none;
  outline: none;
  flex: 1;
  min-width: 120px;
  padding: 4px;
}

.settings-actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
  margin-top: 20px;
}

/* 按钮样式已移至全局样式，这里只保留SettingsView特有的样式 */
.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.form-help {
  font-size: 12px;
  color: #6c757d;
  margin-top: 5px;
  line-height: 1.4;
}

.form-actions {
  display: flex;
  gap: 10px;
  margin-top: 15px;
}

.form-actions .btn {
  min-width: 120px;
}
</style>
