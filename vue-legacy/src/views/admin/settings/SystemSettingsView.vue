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

          <!-- 特殊处理：安全域名列表使用自定义组件 -->
          <template v-if="section.title === '安全配置'">
            <DomainListInput v-model="formData.emailDomains" label="安全域名列表" placeholder="输入域名后按回车或点击加号添加"
              help="邮件接收时只处理这些域名下的邮件地址" :required="true" :disabled="saving" />
          </template>

          <!-- 其他字段使用原有逻辑 -->
          <template v-else>
            <div v-for="field in section.fields" :key="field.key">
              <FormField v-if="field.type !== 'checkbox'" v-model="(formData as any)[field.key]" :label="field.label"
                :type="field.type" :placeholder="(field as any).placeholder" :required="(field as any).required"
                :disabled="((field as any).disabled || saving)" :min="(field as any).min" :max="(field as any).max"
                :step="(field as any).step" :rows="(field as any).rows" :error="(field as any).error"
                :help="(field as any).help" />
              <CheckboxField v-else v-model="(formData as any)[field.key]" :label="field.label"
                :disabled="((field as any).disabled || saving)" :error="(field as any).error"
                :help="(field as any).help" />
            </div>
          </template>
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
import { useRouteApiCacheMapper } from '@/composables/routeApiCacheMapper'
import { ElMessage } from 'element-plus'
import { PageHeader, DebugInfo, PageStates, FormField, CheckboxField, Button, DomainListInput } from '@/components'

const systemStore = useSystemStore()
const { clearCurrentRouteCache } = useRouteApiCacheMapper()

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

// 调试模式
const isDebugMode = computed(() => systemStore.systemConfig?.debug_mode === 1)

// 表单数据
const saving = ref(false)
const formData = ref({
  systemName: '',
  systemDescription: '',
  defaultDomain: '',
  maxEmailSize: 10,
  emailRetentionDays: 30,
  attachmentRetentionDays: 7,
  maxMailboxesPerUser: 5,
  allowUserRegistration: true,
  requireEmailVerification: false,
  debugMode: false,
  apiRateLimit: true,
  sessionTimeout: 60,
  systemNotifications: true,
  emailNotifications: true,
  adminNotificationEmail: '',
  emailDomains: [] as string[]
})

// 原始数据备份
const originalData = ref<any>({})

// 设置表单配置
const settingsSections = computed(() => [
  {
    title: '系统配置',
    fields: [
      // {
      //   key: 'systemName',
      //   label: '系统名称',
      //   type: 'text' as const,
      //   required: true
      // },
      // {
      //   key: 'systemDescription',
      //   label: '系统描述',
      //   type: 'textarea' as const,
      //   rows: 3
      // },
      // {
      //   key: 'defaultDomain',
      //   label: '默认邮箱域名',
      //   type: 'text' as const,
      //   required: true
      // }
    ]
  },
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
        key: 'maxMailboxesPerUser',
        label: '用户最大邮箱数量',
        type: 'number' as const,
        min: 1,
        required: true
      },
      {
        key: 'allowUserRegistration',
        label: '允许新用户注册',
        type: 'checkbox' as const
      },
      {
        key: 'requireEmailVerification',
        label: '注册时需要邮箱验证',
        type: 'checkbox' as const
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
        key: 'sessionTimeout',
        label: '会话超时时间 (分钟)',
        type: 'number' as const,
        min: 5,
        max: 1440,
        required: true
      }
    ]
  },
  {
    title: '通知配置',
    fields: [
      {
        key: 'systemNotifications',
        label: '启用系统通知',
        type: 'checkbox' as const
      },
      {
        key: 'emailNotifications',
        label: '启用邮件通知',
        type: 'checkbox' as const
      },
      {
        key: 'adminNotificationEmail',
        label: '管理员通知邮箱',
        type: 'email' as const
      }
    ]
  }
])

// 监听数据变化，初始化表单
watch(data, (newData) => {
  if (newData) {
    // 后端返回的数据结构: { success: true, data: { config: {...}, user_role: 'admin' } }
    // 或者直接是 API 响应: { data: { config: {...} } }
    const config = newData.data?.config || newData.data || {}
    console.log('📋 系统设置数据更新:', config)

    formData.value = {
      systemName: config.system_name || '',
      systemDescription: config.system_description || '',
      defaultDomain: config.primary_domain || config.default_domain || '',
      maxEmailSize: config.max_attachment_size ? Math.floor(config.max_attachment_size / 1024 / 1024) : (config.max_email_size || 10),
      emailRetentionDays: config.cleanup_days || config.mail_retention_days || config.email_retention_days || 30,
      attachmentRetentionDays: config.attachment_retention_days || 7,
      maxMailboxesPerUser: config.max_mailboxes_per_user || 5,
      allowUserRegistration: config.allow_registration === 1 || config.allow_user_registration === 1,
      requireEmailVerification: config.require_email_verification === 1 || config.require_email_verification === true,
      debugMode: config.debug_mode === 1,
      apiRateLimit: config.api_rate_limit === 1 || config.api_rate_limit !== false,
      sessionTimeout: config.cookie_max_age ? Math.floor(config.cookie_max_age / 60) : (config.session_timeout || 60),
      systemNotifications: config.system_notifications === 1 || config.system_notifications !== false,
      emailNotifications: config.email_notifications === 1 || config.email_notifications !== false,
      adminNotificationEmail: config.admin_email || config.admin_notification_email || '',
      emailDomains: (config.domains || config.supported_domains || []) as string[]
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

    if (data.defaultDomain !== undefined && data.defaultDomain) {
      updateData.primary_domain = data.defaultDomain
    }

    if (data.adminNotificationEmail !== undefined) {
      updateData.admin_email = data.adminNotificationEmail
    }

    // 邮件保留天数映射到 cleanup_days
    if (data.emailRetentionDays !== undefined) {
      updateData.cleanup_days = data.emailRetentionDays
    }

    // 最大邮件大小映射到 max_attachment_size (单位：MB，需要转换为字节)
    if (data.maxEmailSize !== undefined) {
      updateData.max_attachment_size = data.maxEmailSize * 1024 * 1024 // MB 转字节
    }

    // 会话超时时间映射到 cookie_max_age (单位：分钟，需要转换为秒)
    if (data.sessionTimeout !== undefined) {
      updateData.cookie_max_age = data.sessionTimeout * 60 // 分钟转秒
    }

    // 安全域名列表：直接使用数组
    if (data.emailDomains !== undefined && Array.isArray(data.emailDomains) && data.emailDomains.length > 0) {
      // 过滤空值并转换为小写
      const domains = data.emailDomains
        .map((domain: string) => domain.trim().toLowerCase())
        .filter((domain: string) => domain.length > 0)
      if (domains.length > 0) {
        updateData.domains = domains
      }
    }

    // 注意：以下字段后端暂不支持，暂时不发送
    // - systemName (system_name)
    // - systemDescription (system_description)
    // - attachmentRetentionDays (attachment_retention_days)
    // - maxMailboxesPerUser (max_mailboxes_per_user)
    // - requireEmailVerification (require_email_verification)
    // - apiRateLimit (api_rate_limit)
    // - systemNotifications (system_notifications)
    // - emailNotifications (email_notifications)

    // 如果没有可更新的字段，提示用户
    if (Object.keys(updateData).length === 0) {
      ElMessage.warning('没有可保存的配置项')
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

      ElMessage.success(response.message || '系统设置保存成功')
    } else {
      ElMessage.error(response.message || '保存失败')
    }
  } catch (error: any) {
    console.error('保存系统设置失败:', error)
    const errorMessage = error.response?.data?.message || error.message || '保存失败，请稍后重试'
    ElMessage.error(errorMessage)
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
</style>
