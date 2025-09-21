import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { SystemHealth } from '@/types'
import { systemApiService } from '@/composables/api'
import { useStorage } from '@vueuse/core'

// 调试工具函数
const debugLog = (...args: any[]) => {
  const isDebugMode = import.meta.env.DEV || import.meta.env.VITE_DEBUG === 'true'
  if (isDebugMode) {
    console.log('[SystemStore]', ...args)
  }
}

export const useSystemStore = defineStore('system', () => {
  // 状态
  const systemHealth = ref<SystemHealth | null>(null)
  const registrationStatus = ref<{ allow_registration: number } | null>(null)
  // 使用 localStorage 存储 systemConfig
  const systemConfig = useStorage<{
    debug_mode?: number;
    allow_registration?: number;
    auto_approve_mailbox?: number;
    supported_domains?: string[];
    mail_retention_days?: number;
    attachment_max_size?: number;
    allow_user_send?: number;
    max_mailboxes_per_user?: number;
    storage_provider?: string;
    cleanup_days?: number;
    max_attachment_size?: number;
    cookie_max_age?: number;
    jwt_secret?: string;
    admin_email?: string;
    primary_domain?: string;
    domains?: string[];
  } | null>('systemConfig', null, localStorage, {
    serializer: {
      read: (value: string) => {
        try {
          return value ? JSON.parse(value) : null
        } catch {
          return null
        }
      },
      write: (value: {
        debug_mode?: number;
        allow_registration?: number;
        auto_approve_mailbox?: number;
        supported_domains?: string[];
        mail_retention_days?: number;
        attachment_max_size?: number;
        allow_user_send?: number;
        max_mailboxes_per_user?: number;
        storage_provider?: string;
        cleanup_days?: number;
        max_attachment_size?: number;
        cookie_max_age?: number;
        jwt_secret?: string;
        admin_email?: string;
        primary_domain?: string;
        domains?: string[];
      } | null) => {
        return value ? JSON.stringify(value) : ''
      }
    }
  })
  const loading = ref(false)

  // 获取系统健康状态
  const fetchSystemHealth = async () => {
    loading.value = true
    try {
      const response = await systemApiService.getSystemHealth()
      if (response.success && response.data) {
        systemHealth.value = response

        // 将 health 接口的 config 字段同步到 systemConfig 缓存
        // 注意：只更新特定字段，不覆盖完整配置
        if (response.data.health?.config) {
          const healthConfig = response.data.health.config as { allow_registration: number; debug_mode: number }

          // 使用空值合并赋值操作符，确保 systemConfig 存在并更新字段
          (systemConfig.value ??= {}).allow_registration = healthConfig.allow_registration
          systemConfig.value.debug_mode = healthConfig.debug_mode

          debugLog('系统健康状态配置已同步到 localStorage (部分更新):', systemConfig.value)
        }

        return { success: true }
      } else {
        return { success: false, error: response.message || '获取系统状态失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.message || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 获取注册状态
  const fetchRegistrationStatus = async () => {
    loading.value = true
    try {
      const response = await systemApiService.getRegistrationStatus()
      if (response.success && response.data) {
        registrationStatus.value = response.data
        return { success: true }
      } else {
        return { success: false, error: response.message || '获取注册状态失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.message || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 获取系统配置
  const fetchSystemConfig = async () => {
    loading.value = true
    try {
      const response = await systemApiService.getSystemConfig()
      if (response.success && response.data) {
        // 正确提取 config 字段并保存到 localStorage
        const config = response.data.config || response.data
        systemConfig.value = config
        debugLog('系统配置已保存到 localStorage:', config)
        return { success: true }
      } else {
        return { success: false, error: response.message || '获取系统配置失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.message || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 计算属性
  const isDebugMode = computed(() => {
    // 只从 systemConfig 读取数据库设置，绝对不使用环境变量
    if (systemConfig.value?.debug_mode !== undefined) {
      const result = systemConfig.value.debug_mode === 1
      debugLog('debug_mode:', systemConfig.value.debug_mode, 'type:', typeof systemConfig.value.debug_mode, 'result:', result)
      return result
    }
    // 如果数据库设置不可用，默认返回 false（不使用环境变量）
    debugLog('debug_mode 未定义，默认返回 false')
    return false
  })

  const isRegistrationAllowed = computed(() => {
    // 从 systemConfig 读取（配置修改时会自动更新缓存）
    return systemConfig.value?.allow_registration === 1
  })

  return {
    // 状态
    systemHealth,
    registrationStatus,
    systemConfig,
    loading,

    // 计算属性
    isDebugMode,
    isRegistrationAllowed,

    // 方法
    fetchSystemHealth,
    fetchRegistrationStatus,
    fetchSystemConfig
  }
})
