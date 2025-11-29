<template>
  <div class="system-settings-view">
    <PageHeader title="⚙️ 系统设置" />

    <DebugInfo :is-debug-mode="isDebugMode" :route-info="routeInfo" :is-supported="isSupported" :has-access="hasAccess"
      :last-updated="lastUpdated ? lastUpdated.toString() : undefined" />

    <PageStates :loading="loading" :error="error" :is-empty="false" loading-text="正在加载系统设置..." @retry="refreshData" />

    <div v-if="data" class="settings-container">
      <form @submit.prevent="saveSettings(formData)">
        <div v-for="section in settingsSections" :key="section.title" class="settings-section">
          <h3>{{ section.title }}</h3>

          <!-- 所有字段使用统一逻辑 -->
          <div v-for="field in section.fields" :key="field.key">
            <FormField v-if="field.type !== 'checkbox' && field.type !== 'select'"
              v-model="(formData as any)[field.key]" :label="field.label" :type="field.type"
              :placeholder="(field as any).placeholder" :required="(field as any).required"
              :disabled="((field as any).disabled || saving)" :min="(field as any).min" :max="(field as any).max"
              :step="(field as any).step" :rows="(field as any).rows" :error="(field as any).error"
              :help="(field as any).help" />
            <div v-else-if="field.type === 'select'" class="form-group">
              <label v-if="field.label" :for="`field-${field.key}`">{{ field.label }}</label>
              <select :id="`field-${field.key}`" :value="(formData as any)[field.key]"
                :disabled="((field as any).disabled || saving)" class="form-control"
                @change="(formData as any)[field.key] = ($event.target as HTMLSelectElement).value">
                <option v-for="option in (field as any).options" :key="option.value" :value="option.value">
                  {{ option.label }}
                </option>
              </select>
              <div v-if="(field as any).help" class="form-help">{{ (field as any).help }}</div>
            </div>
            <CheckboxField v-else v-model="(formData as any)[field.key]" :label="field.label"
              :disabled="((field as any).disabled || saving)" :error="(field as any).error"
              :help="(field as any).help" />
          </div>
        </div>

        <div class="form-actions">
          <Button variant="secondary" @click="resetForm">重置</Button>
          <Button type="submit" variant="primary" :disabled="saving">
            {{ saving ? '保存中...' : '保存设置' }}
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
import { systemApiService } from '@/composables/api'
import { useRouteApiManager } from '@/composables/routeApiManager'
import { PageHeader, DebugInfo, PageStates, FormField, CheckboxField, Button } from '@/components'
import { toast } from '@/utils'

const systemStore = useSystemStore()
const { clearCurrentRouteCache } = useRouteApiManager()

// 使用统一页面数据管理
const {
  pageData,
  routeInfo,
  isSupported,
  hasAccess,
  pageRefresh
} = useUnifiedPageData()

const data = computed(() => pageData.value.data)
const loading = computed(() => pageData.value.loading)
const error = computed(() => pageData.value.error)
const lastUpdated = computed(() => pageData.value.lastUpdated)
const refreshData = pageRefresh

// 调试模式 - 使用 systemStore 的计算属性
const isDebugMode = computed(() => systemStore.isDebugMode)

// 表单数据
const saving = ref(false)
const formData = ref({
  systemName: '',
  systemDescription: '',
  maxEmailSize: 10,
  emailRetentionDays: 30,
  attachmentRetentionDays: 7,
  allowUserRegistration: false,
  requireEmailVerification: false,
  debugMode: false,
  apiRateLimit: true,
  apiRateLimitMaxRequests: 100,
  sessionTimeout: 60,
  defaultWebhookUrl: '',
  defaultWebhookSecret: '',
  defaultWebhookType: 'dingtalk' as 'dingtalk' | 'feishu' | 'bark'
})

// 原始数据备份
const originalData = ref<any>({})

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
        key: 'emailRetentionDays',
        label: '邮件保留天数',
        type: 'number' as const,
        min: 1,
        required: true
      },
      {
        key: 'attachmentRetentionDays',
        label: '附件保留天数',
        type: 'number' as const,
        min: 1,
        required: true
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
        key: 'apiRateLimit',
        label: '启用API访问频率限制',
        type: 'checkbox' as const
      },
      {
        key: 'apiRateLimitMaxRequests',
        label: '每分钟最大请求数',
        type: 'number' as const,
        min: 10,
        max: 10000,
        required: false,
        help: '范围：10-10000，默认：100。表示每分钟允许的最大请求数'
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
    title: '默认推送渠道',
    fields: [
      {
        key: 'defaultWebhookUrl',
        label: 'Webhook URL',
        type: 'text' as const,
        placeholder: 'https://oapi.dingtalk.com/robot/send?access_token=xxx',
        help: '支持钉钉、飞书、Bark。所有邮件都会发送到此webhook，消息格式：你有一封来自 xxx 的邮件'
      },
      {
        key: 'defaultWebhookSecret',
        label: 'Webhook 密钥（可选）',
        type: 'text' as const,
        placeholder: '用于钉钉加签等',
        help: '钉钉机器人加签密钥（可选）'
      },
      {
        key: 'defaultWebhookType',
        label: 'Webhook 类型',
        type: 'select' as const,
        options: [
          { value: 'dingtalk', label: '钉钉' },
          { value: 'feishu', label: '飞书' },
          { value: 'bark', label: 'Bark' }
        ],
        help: '选择webhook类型'
      }
    ]
  }
])

// 监听数据变化，初始化表单
watch(data, (newData) => {
  if (newData) {
    // 后端返回的数据结构: { success: true, data: { config: {...} } }
    // 或者直接是 API 响应: { data: { config: {...} } }
    const config = newData.data?.config || newData.data || {}
    console.log('📋 系统设置数据更新:', config)

    formData.value = {
      systemName: config.system_name || '',
      systemDescription: config.system_description || '',
      maxEmailSize: config.attachment_max_size ? Math.floor(config.attachment_max_size / 1024 / 1024) : 10,
      emailRetentionDays: config.mail_retention_days || config.email_retention_days || 30,
      attachmentRetentionDays: config.attachment_retention_days || 7,
      allowUserRegistration: config.allow_registration === 1 || config.allow_user_registration === 1 || false,
      requireEmailVerification: config.require_email_verification === 1 || config.require_email_verification === true || false,
      debugMode: config.debug_mode === 1,
      apiRateLimit: config.api_rate_limit === 1 || config.api_rate_limit !== false,
      apiRateLimitMaxRequests: config.api_rate_limit_max_requests || 100,
      sessionTimeout: config.cookie_max_age ? Math.floor(config.cookie_max_age / 60) : (config.session_timeout || 60),
      defaultWebhookUrl: config.default_webhook_url || '',
      defaultWebhookSecret: config.default_webhook_secret || '',
      defaultWebhookType: (config.default_webhook_type || 'dingtalk') as 'dingtalk' | 'feishu' | 'bark'
    }
    originalData.value = { ...formData.value } as any
    console.log('✅ 表单数据已更新，debugMode:', formData.value.debugMode)
  }
}, { immediate: true })

// 重置表单
const resetForm = () => {
  formData.value = { ...originalData.value }
}

// 保存设置
const saveSettings = async (data: any) => {
  saving.value = true
  try {
    // 只发送后端支持的字段，并进行字段映射
    const updateData: any = {}

    // 映射前端字段到后端字段
    if (data.allowUserRegistration !== undefined) {
      updateData.allow_registration = data.allowUserRegistration ? 1 : 0
    }

    if (data.debugMode !== undefined) {
      updateData.debug_mode = data.debugMode ? 1 : 0
    }

    if (data.apiRateLimit !== undefined) {
      updateData.api_rate_limit = data.apiRateLimit ? 1 : 0
    }

    if (data.apiRateLimitMaxRequests !== undefined) {
      updateData.api_rate_limit_max_requests = data.apiRateLimitMaxRequests
    }

    // 邮件保留天数
    if (data.emailRetentionDays !== undefined) {
      updateData.mail_retention_days = data.emailRetentionDays
    }

    // 附件保留天数
    if (data.attachmentRetentionDays !== undefined) {
      updateData.attachment_retention_days = data.attachmentRetentionDays
    }

    // 最大邮件大小映射到 attachment_max_size (单位：MB，需要转换为字节)
    if (data.maxEmailSize !== undefined) {
      updateData.attachment_max_size = data.maxEmailSize * 1024 * 1024 // MB 转字节
    }

    // 会话超时时间映射到 cookie_max_age (单位：分钟，需要转换为秒)
    if (data.sessionTimeout !== undefined) {
      updateData.cookie_max_age = data.sessionTimeout * 60 // 分钟转秒
    }

    // 默认Webhook配置
    if (data.defaultWebhookUrl !== undefined) {
      updateData.default_webhook_url = data.defaultWebhookUrl.trim() || ''
    }
    if (data.defaultWebhookSecret !== undefined) {
      updateData.default_webhook_secret = data.defaultWebhookSecret.trim() || ''
    }
    if (data.defaultWebhookType !== undefined) {
      updateData.default_webhook_type = data.defaultWebhookType.trim() || ''
    }

    // 注意：以下字段后端暂不支持，暂时不发送
    // - systemName (system_name)
    // - systemDescription (system_description)
    // - attachmentRetentionDays (attachment_retention_days)
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
      await systemStore.fetchSystemConfig()

      // 刷新页面数据（这会获取最新的系统配置）
      await refreshData()

      // 从页面数据中获取最新配置并更新 systemStore（双重保险）
      const currentData = data.value
      if (currentData?.data?.config) {
        systemStore.systemConfig = currentData.data.config
        console.log('✅ 已从页面数据更新 systemStore 缓存')
      } else if (currentData?.config) {
        // 兼容不同的数据结构
        systemStore.systemConfig = currentData.config
        console.log('✅ 已从页面数据更新 systemStore 缓存（兼容格式）')
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
  console.log('⚙️ 系统设置页面初始化')
})
</script>

<style scoped>
.system-settings-view {
  padding: 20px;
  max-width: 800px;
  margin: 0 auto;
}

.settings-container {
  background: white;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.settings-section {
  margin-bottom: 30px;
  padding-bottom: 20px;
  border-bottom: 1px solid #e0e0e0;
}

.settings-section:last-child {
  border-bottom: none;
  margin-bottom: 0;
}

.settings-section h3 {
  margin: 0 0 15px 0;
  color: #333;
  font-size: 18px;
}

.form-actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid #e0e0e0;
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
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  transition: border-color 0.2s;
  box-sizing: border-box;
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
</style>
