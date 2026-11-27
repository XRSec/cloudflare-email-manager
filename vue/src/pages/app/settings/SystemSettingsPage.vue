<template>
  <div class="system-settings-view">
    <PageHeader title="⚙️ 系统设置" />

    <PageStates :loading="loading" :error="error" :is-empty="false" loading-text="正在加载系统设置..." @retry="refreshData" />

    <div v-if="data" class="settings-container">
      <form @submit.prevent="saveSettings(formData)">
        <div v-for="section in settingsSections" :key="section.title" class="settings-section">
          <h3>{{ section.title }}</h3>

          <!-- 所有字段使用统一逻辑 -->
          <div v-for="field in section.fields" :key="field.key" :class="{ 'field-wide': field.type === 'tag-list' }">
            <FormField v-if="field.type !== 'checkbox' && field.type !== 'tag-list'"
              v-model="(formData as any)[field.key]" :label="field.label" :type="field.type"
              :placeholder="(field as any).placeholder" :required="(field as any).required"
              :disabled="((field as any).disabled || saving)" :min="(field as any).min" :max="(field as any).max"
              :step="(field as any).step" :rows="(field as any).rows" :error="(field as any).error"
              :help="(field as any).help" />
            <CheckboxField v-else-if="field.type === 'checkbox'" v-model="(formData as any)[field.key]" :label="field.label"
              :disabled="((field as any).disabled || saving)" :error="(field as any).error"
              :help="(field as any).help" />
            <TagListInput v-else-if="field.type === 'tag-list'" v-model="(formData as any)[field.key]" :label="field.label"
              :placeholder="(field as any).placeholder" :disabled="saving" :help="(field as any).help"
              :validate-fn="validateDomainName" />
          </div>
        </div>

        <!-- API Token 管理 -->
        <div class="settings-section">
          <h3>🔑 API Token (访问令牌)</h3>
          <div class="field-wide token-card">
            <div class="token-input-row">
              <div class="token-input-wrap">
                <input
                  :value="tokenVisible ? apiToken : maskedApiToken"
                  type="text"
                  readonly
                  class="form-control token-input"
                  placeholder="未生成 Token"
                />
                <button
                  type="button"
                  class="token-toggle-btn"
                  @click="tokenVisible = !tokenVisible"
                  :disabled="!apiToken"
                >
                  {{ tokenVisible ? '隐藏' : '显示' }}
                </button>
              </div>
              <Button
                type="button"
                variant="secondary"
                @click="copyToken"
                :disabled="!apiToken"
              >
                📋 复制 Token
              </Button>
              <Button
                type="button"
                variant="secondary"
                @click="handleRotateToken"
                :disabled="rotatingToken"
              >
                🔄 {{ rotatingToken ? '更新中...' : '重新生成 Token' }}
              </Button>
            </div>
            <p class="token-help">
              用于外部自动化脚本、第三方客户端或 API 调用的访问令牌。支持在 HTTP 请求头中传入 <code>Authorization: Bearer &lt;token&gt;</code>，或在 URL 查询参数中直接传入 <code>?token=&lt;token&gt;</code> 进行免 Cookie 鉴权。<br>
              <strong>注意：</strong>重新生成后，旧 Token 将立即失效。
            </p>
          </div>
        </div>

        <div class="form-actions">
          <Button variant="secondary" @click="resetForm">重置</Button>
          <Button type="submit" variant="primary" :disabled="saving">
            {{ saving ? '保存中...' : '保存' }}
          </Button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useUnifiedPageData } from '@/composables/useUnifiedPageData'
import { useSystemStore } from '@/composables/system'
import { systemApiService } from '@/composables/api-system'
import { useRouteApiManager } from '@/composables/routeApiManager'
import { PageHeader, PageStates, FormField, CheckboxField, TagListInput, Button } from '@/components'
import { toast } from '@/utils/toast'

const systemStore = useSystemStore()
const { clearCurrentRouteCache } = useRouteApiManager()

// 使用统一页面数据管理
const {
  pageData,
  pageRefresh
} = useUnifiedPageData()

const data = computed(() => pageData.value.data)
const loading = computed(() => pageData.value.loading)
const error = computed(() => pageData.value.error)
const refreshData = pageRefresh

// 表单数据
const saving = ref(false)
const formData = ref({
  systemName: '',
  systemDescription: '',
  maxEmailSize: 10,
  attachmentRetentionDays: 365,
  allowUserRegistration: false,
  requireEmailVerification: false,
  debugMode: false,
  sessionTimeout: 60,
  timezone: 'Asia/Shanghai',
  supportedDomains: [] as string[]
})

// 原始数据备份
const originalData = ref<any>({})

// API Token 状态
const apiToken = ref('')
const tokenVisible = ref(false)
const rotatingToken = ref(false)

const maskedApiToken = computed(() => {
  if (!apiToken.value) return ''
  if (apiToken.value.length <= 14) return '******'
  return `${apiToken.value.slice(0, 8)}************************${apiToken.value.slice(-6)}`
})

const copyToken = async () => {
  if (!apiToken.value) return
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(apiToken.value)
    } else {
      const textarea = document.createElement('textarea')
      textarea.value = apiToken.value
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
    }
    toast.success('Token 已成功复制到剪贴板')
  } catch {
    toast.error('复制失败，请手动选择复制')
  }
}

const handleRotateToken = async () => {
  if (!confirm('重新生成后，旧 Token 将立即失效，所有使用旧 Token 的外部脚本和链接都需要更新。确认重新生成吗？')) {
    return
  }
  rotatingToken.value = true
  try {
    const res = await systemApiService.rotateApiToken()
    if (res.success && res.data?.api_token) {
      apiToken.value = res.data.api_token
      toast.success('API Token 已成功重新生成')
    } else {
      toast.error(res.message || '更新 Token 失败')
    }
  } catch (err: any) {
    toast.error(err.response?.data?.message || err.message || '更新 Token 失败')
  } finally {
    rotatingToken.value = false
  }
}

// 设置表单配置
const settingsSections = computed(() => [
  {
    title: '邮件配置',
    fields: [
      {
        key: 'maxEmailSize',
        label: '最大邮件大小 (MB)',
        type: 'number' as const,
        min: 1,
        max: 50,
        required: true
      },
      {
        key: 'attachmentRetentionDays',
        label: '附件保留天数',
        type: 'number' as const,
        min: 1,
        required: true
      },
      {
        key: 'supportedDomains',
        label: '已支持的邮箱域列表',
        type: 'tag-list' as const,
        placeholder: 'example.com',
        help: '用于记录系统已接收并支持互转的邮箱域名，输入后按回车或逗号添加'
      }
    ]
  },
  {
    title: '用户配置',
    fields: [
      {
        key: 'allowUserRegistration',
        label: '允许新用户注册',
        type: 'checkbox' as const,
        disabled: true,
        help: '当前系统为单管理员模式，不支持用户注册'
      },
      {
        key: 'requireEmailVerification',
        label: '注册时需要邮箱验证',
        type: 'checkbox' as const,
        disabled: true,
        help: '当前系统为单管理员模式，不支持用户注册功能'
      }
    ]
  },
  {
    title: '安全配置',
    fields: [
      {
        key: 'debugMode',
        label: '启用调试模式',
        type: 'checkbox' as const
      },
      {
        key: 'sessionTimeout',
        label: '会话超时时间 (分钟)',
        type: 'number' as const,
        min: 60,  // 1小时
        max: 2880,  // 48小时 = 48 * 60 = 2880 分钟
        required: true,
        help: '范围：60-2880 分钟（1小时-48小时），默认：2880 分钟（48小时）'
      }
    ]
  },
  {
    title: '显示配置',
    fields: [
      {
        key: 'timezone',
        label: '显示时区',
        type: 'text' as const,
        placeholder: 'Asia/Shanghai',
        required: true,
        help: '使用 IANA 时区名称，例如 Asia/Shanghai、UTC、America/New_York'
      }
    ]
  }
])

const normalizeDomainValue = (value: string) => {
  const trimmed = value.trim().toLowerCase().replace(/^@+/, '')
  const domain = trimmed.includes('@') ? trimmed.split('@').pop() || '' : trimmed
  return domain.replace(/^@+/, '')
}

const normalizeDomainList = (domains: string[]) => (
  Array.from(new Set(domains.map(normalizeDomainValue).filter(Boolean)))
)

const parseSupportedDomains = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    return normalizeDomainList(value.filter((item): item is string => typeof item === 'string'))
  }

  if (typeof value !== 'string' || !value.trim()) {
    return []
  }

  try {
    const parsed = JSON.parse(value)
    return Array.isArray(parsed) ? normalizeDomainList(parsed.filter((item): item is string => typeof item === 'string')) : []
  } catch {
    return normalizeDomainList(value.split(','))
  }
}

const parseEnabledFlag = (value: unknown) => value === 1 || value === true || value === '1'

const isValidTimeZone = (value: string) => {
  try {
    new Intl.DateTimeFormat('zh-CN', { timeZone: value })
    return true
  } catch {
    return false
  }
}

const validateDomainName = (value: string) => {
  const domain = normalizeDomainValue(value)
  const domainRegex = /^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/
  return domainRegex.test(domain) || '请输入有效域名，例如 example.com'
}

// 监听数据变化，初始化表单
watch(data, (newData) => {
  if (newData) {
    // 后端返回的数据结构: { success: true, data: { config: {...} } }
    // 或者直接是 API 响应: { data: { config: {...} } }
    const config = newData.data?.config || newData.data || {}

    if (config.api_token) {
      apiToken.value = config.api_token
    }

    formData.value = {
      systemName: config.system_name || '',
      systemDescription: config.system_description || '',
      maxEmailSize: config.attachment_max_size ? Math.floor(config.attachment_max_size / 1024 / 1024) : 10,
      attachmentRetentionDays: config.attachment_retention_days || 365,
      allowUserRegistration: parseEnabledFlag(config.allow_registration) || parseEnabledFlag(config.allow_user_registration),
      requireEmailVerification: parseEnabledFlag(config.require_email_verification),
      debugMode: parseEnabledFlag(config.debug_mode),
      sessionTimeout: config.cookie_max_age ? Math.floor(config.cookie_max_age / 60) : (config.session_timeout || 60),
      timezone: config.timezone || 'Asia/Shanghai',
      supportedDomains: parseSupportedDomains(config.supported_emails)
    }
    originalData.value = { ...formData.value } as any
  }
}, { immediate: true })

// 重置表单
const resetForm = () => {
  formData.value = { ...originalData.value }
}

// 保存设置
const saveSettings = async (settingsData: any) => {
  saving.value = true
  try {
    // 只发送后端支持的字段，并进行字段映射
    const updateData: any = {}

    // 映射前端字段到后端字段
    if (settingsData.allowUserRegistration !== undefined) {
      updateData.allow_registration = settingsData.allowUserRegistration ? 1 : 0
    }

    if (settingsData.debugMode !== undefined) {
      updateData.debug_mode = settingsData.debugMode ? 1 : 0
    }

    if (settingsData.timezone !== undefined) {
      const timezone = String(settingsData.timezone).trim()
      if (!isValidTimeZone(timezone)) {
        toast.error('请输入有效的 IANA 时区，例如 Asia/Shanghai')
        return
      }
      updateData.timezone = timezone
    }

    // 附件保留天数
    if (settingsData.attachmentRetentionDays !== undefined) {
      updateData.attachment_retention_days = settingsData.attachmentRetentionDays
    }

    // 最大邮件大小映射到 attachment_max_size (单位：MB，需要转换为字节)
    if (settingsData.maxEmailSize !== undefined) {
      updateData.attachment_max_size = settingsData.maxEmailSize * 1024 * 1024 // MB 转字节
    }

    // 会话超时时间映射到 cookie_max_age (单位：分钟，需要转换为秒)
    if (settingsData.sessionTimeout !== undefined) {
      updateData.cookie_max_age = settingsData.sessionTimeout * 60 // 分钟转秒
    }

    if (settingsData.supportedDomains !== undefined) {
      updateData.supported_emails = normalizeDomainList(settingsData.supportedDomains)
    }

    // 注意：以下字段后端暂不支持，暂时不发送
    // - systemName (system_name)
    // - systemDescription (system_description)
    // - requireEmailVerification (require_email_verification)

    // 如果没有可更新的字段，提示用户
    if (Object.keys(updateData).length === 0) {
      toast.warning('没有可保存的配置项')
      return
    }

    // 调用更新系统配置API
    const response = await systemApiService.updateSystemConfig(updateData)

    if (response.success) {
      // 清除当前路由的缓存，确保获取最新数据
      clearCurrentRouteCache()

      // 先更新 systemStore，确保调试模式等状态立即更新
      await systemStore.fetchSystemConfig({ forceRefresh: true })

      // 刷新页面数据（这会获取最新的系统配置）
      await refreshData()

      // 从页面数据中获取最新配置并更新 systemStore（双重保险）
      const currentData = data.value
      if (currentData?.data?.config) {
        systemStore.systemConfig = currentData.data.config
      } else if (currentData?.config) {
        // 兼容不同的数据结构
        systemStore.systemConfig = currentData.config
      }

      // 更新原始数据备份（使用最新的表单数据）
      originalData.value = { ...formData.value }

      toast.success(response.message || '系统设置保存成功')
    } else {
      toast.error(response.message || '保存失败')
    }
  } catch (error: any) {
    console.error('保存系统设置失败:', error)
    const errorMessage = error.response?.data?.message || error.message || '保存失败，请稍后重试'
    toast.error(errorMessage)
  } finally {
    saving.value = false
  }
}

// 页面初始化
onMounted(() => {
})
</script>

<style scoped>
.system-settings-view {
  max-width: 1100px;
  margin: 0 auto;
}

.settings-container {
  background: rgba(255, 255, 255, 0.96);
  border-radius: 24px;
  padding: 24px;
  box-shadow: 0 24px 42px -38px rgba(15, 23, 42, 0.8);
  border: 1px solid rgba(15, 23, 42, 0.08);
}

.settings-section {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px 18px;
  margin-bottom: 30px;
  padding-bottom: 20px;
  border-bottom: 1px solid rgba(15, 23, 42, 0.08);
}

.settings-section:last-child {
  border-bottom: none;
  margin-bottom: 0;
}

.settings-section h3 {
  grid-column: 1 / -1;
  margin: 0 0 15px 0;
  color: #17324a;
  font-size: 18px;
  letter-spacing: -0.02em;
}

.settings-section :deep(.form-group) {
  margin-bottom: 0;
}

.field-wide {
  grid-column: 1 / -1;
}

.token-card {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.token-input-row {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
}

.token-input-wrap {
  position: relative;
  flex: 1;
  min-width: 260px;
}

.token-input {
  padding-right: 64px !important;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px !important;
  color: #17324a;
}

.token-toggle-btn {
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  border: none;
  background: transparent;
  color: #3b82f6;
  font-size: 12px;
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 6px;
}

.token-toggle-btn:hover:not(:disabled) {
  background: rgba(59, 130, 246, 0.08);
}

.token-toggle-btn:disabled {
  color: #94a3b8;
  cursor: not-allowed;
}

.token-help {
  color: #64748b;
  font-size: 13px;
  line-height: 1.6;
  margin: 0;
}

.token-help code {
  background: rgba(15, 23, 42, 0.06);
  padding: 2px 6px;
  border-radius: 4px;
  color: #0f172a;
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 12px;
}

.form-actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
  margin-top: 20px;
  padding-top: 20px;
  flex-wrap: wrap;
}

.form-group {
  margin-bottom: 15px;
}

.form-group label {
  display: block;
  margin-bottom: 5px;
  font-weight: bold;
  color: #555;
}

.form-control {
  width: 100%;
  padding: 11px 12px;
  border: 1px solid rgba(52, 84, 117, 0.18);
  border-radius: 14px;
  font-size: 14px;
  transition: border-color 0.2s;
  box-sizing: border-box;
  background: rgba(247, 250, 252, 0.92);
}

.form-control:focus {
  outline: none;
  border-color: #007bff;
  box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
}

.form-control:disabled {
  background-color: #f8f9fa;
  opacity: 0.6;
  cursor: not-allowed;
}

.form-help {
  color: #6c757d;
  font-size: 12px;
  margin-top: 5px;
}

@media (max-width: 840px) {
  .settings-container {
    padding: 18px;
    border-radius: 20px;
  }

  .settings-section {
    grid-template-columns: 1fr;
  }

  .form-actions {
    justify-content: flex-end;
  }

  .form-actions :deep(.btn) {
    width: auto;
  }
}
</style>
