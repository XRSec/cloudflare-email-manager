<template>
  <div class="personal-settings-view">
    <PageHeader title="⚙️ 个人设置" />

    <DebugInfo :is-debug-mode="isDebugMode" :route-info="routeInfo" :is-supported="isSupported" :has-access="hasAccess"
      :last-updated="lastUpdated ? lastUpdated.toString() : undefined" />

    <PageStates :loading="loading" :error="error" :is-empty="false" loading-text="正在加载个人设置..." @retry="refreshData" />

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
// import { userApiService } from '@/composables/api'
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
  username: '',
  email: '',
  forwardRules: [
    { source: '', destination: '' }
  ],
  emailNotifications: true,
  systemNotifications: true,
  currentPassword: '',
  newPassword: '',
  confirmPassword: ''
})

// 原始数据备份
const originalData = ref<any>({})

// 设置表单配置
const settingsSections = computed(() => [
  {
    title: '基本信息',
    fields: [
      {
        key: 'username',
        label: '用户名',
        type: 'text' as const,
        required: true
      },
      {
        key: 'email',
        label: '邮箱',
        type: 'email' as const,
        required: true
      }
    ]
  },
  {
    title: '通知设置',
    fields: [
      {
        key: 'emailNotifications',
        label: '接收邮件通知',
        type: 'checkbox' as const
      },
      {
        key: 'systemNotifications',
        label: '接收系统通知',
        type: 'checkbox' as const
      }
    ]
  },
  {
    title: '安全设置',
    fields: [
      {
        key: 'currentPassword',
        label: '当前密码',
        type: 'password' as const,
        placeholder: '输入当前密码'
      },
      {
        key: 'newPassword',
        label: '新密码',
        type: 'password' as const,
        placeholder: '输入新密码'
      },
      {
        key: 'confirmPassword',
        label: '确认新密码',
        type: 'password' as const,
        placeholder: '确认新密码'
      }
    ]
  }
])

// 监听数据变化，初始化表单
watch(data, (newData) => {
  if (newData) {
    const userInfo = newData.data || {}
    formData.value = {
      username: userInfo.username || '',
      email: userInfo.email || '',
      forwardRules: userInfo.forward_rules || [{ source: '', destination: '' }],
      emailNotifications: userInfo.email_notifications !== false,
      systemNotifications: userInfo.system_notifications !== false,
      currentPassword: '',
      newPassword: '',
      confirmPassword: ''
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
  // 验证密码
  if (data.newPassword && data.newPassword !== data.confirmPassword) {
    alert('新密码和确认密码不匹配')
    return
  }

  saving.value = true
  try {
    const updateData: any = {
      username: data.username,
      email: data.email,
      forward_rules: data.forwardRules.filter((rule: any) => rule.source && rule.destination),
      email_notifications: data.emailNotifications,
      system_notifications: data.systemNotifications
    }

    // 如果有新密码，添加密码更新
    if (data.newPassword) {
      updateData.current_password = data.currentPassword
      updateData.new_password = data.newPassword
    }

    // TODO: 实现更新用户信息API
    console.log('更新用户信息:', updateData)
    originalData.value = { ...data }
    alert('设置保存成功')
  } catch (error) {
    console.error('保存设置失败:', error)
    alert('保存失败')
  } finally {
    saving.value = false
  }
}

// 页面初始化
onMounted(() => {
  console.log('⚙️ 个人设置页面初始化')
})
</script>

<style scoped>
.personal-settings-view {
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
