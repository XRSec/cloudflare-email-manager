<template>
  <div class="system-settings-view">
    <PageHeader title="⚙️ 系统设置" :show-refresh="true" :loading="loading" @refresh="refreshData" />

    <DebugInfo :is-debug-mode="isDebugMode" :route-info="routeInfo" :is-supported="isSupported" :has-access="hasAccess"
      :last-updated="lastUpdated ? lastUpdated.toString() : undefined" />

    <PageStates :loading="loading" :error="error" :is-empty="false" loading-text="正在加载系统设置..." @retry="refreshData" />

    <div v-if="data" class="settings-container">
      <SettingsForm :sections="settingsSections" :initial-data="formData" :saving="saving" @submit="saveSettings"
        @reset="resetForm" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useUnifiedPageData } from '@/composables/useUnifiedPageData'
import { useSystemStore } from '@/composables/system'
// import { adminApiService } from '@/composables/api'
import { PageHeader, DebugInfo, PageStates, SettingsForm } from '@/components'

const systemStore = useSystemStore()

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
  adminNotificationEmail: ''
})

// 原始数据备份
const originalData = ref<any>({})

// 设置表单配置
const settingsSections = computed(() => [
  {
    title: '系统配置',
    fields: [
      {
        key: 'systemName',
        label: '系统名称',
        type: 'text' as const,
        required: true
      },
      {
        key: 'systemDescription',
        label: '系统描述',
        type: 'textarea' as const,
        rows: 3
      },
      {
        key: 'defaultDomain',
        label: '默认邮箱域名',
        type: 'text' as const,
        required: true
      }
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
    const config = newData.data || {}
    formData.value = {
      systemName: config.system_name || '',
      systemDescription: config.system_description || '',
      defaultDomain: config.default_domain || '',
      maxEmailSize: config.max_email_size || 10,
      emailRetentionDays: config.email_retention_days || 30,
      attachmentRetentionDays: config.attachment_retention_days || 7,
      maxMailboxesPerUser: config.max_mailboxes_per_user || 5,
      allowUserRegistration: config.allow_user_registration !== false,
      requireEmailVerification: config.require_email_verification === true,
      debugMode: config.debug_mode === 1,
      apiRateLimit: config.api_rate_limit !== false,
      sessionTimeout: config.session_timeout || 60,
      systemNotifications: config.system_notifications !== false,
      emailNotifications: config.email_notifications !== false,
      adminNotificationEmail: config.admin_notification_email || ''
    }
    originalData.value = { ...formData.value } as any
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
    const updateData = {
      system_name: data.systemName,
      system_description: data.systemDescription,
      default_domain: data.defaultDomain,
      max_email_size: data.maxEmailSize,
      email_retention_days: data.emailRetentionDays,
      attachment_retention_days: data.attachmentRetentionDays,
      max_mailboxes_per_user: data.maxMailboxesPerUser,
      allow_user_registration: data.allowUserRegistration ? 1 : 0,
      require_email_verification: data.requireEmailVerification ? 1 : 0,
      debug_mode: data.debugMode ? 1 : 0,
      api_rate_limit: data.apiRateLimit ? 1 : 0,
      session_timeout: data.sessionTimeout,
      system_notifications: data.systemNotifications ? 1 : 0,
      email_notifications: data.emailNotifications ? 1 : 0,
      admin_notification_email: data.adminNotificationEmail
    }

    // TODO: 实现更新系统配置API
    console.log('更新系统配置:', updateData)
    originalData.value = { ...data }

    // 更新系统配置缓存
    // systemStore.updateSystemConfig(updateData)

    alert('系统设置保存成功')
  } catch (error) {
    console.error('保存系统设置失败:', error)
    alert('保存失败')
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
</style>
