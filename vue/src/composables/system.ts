import {defineStore} from 'pinia'
import {computed, ref} from 'vue'
import type {SystemConfig, SystemHealth} from '@/types'
import {systemApiService} from '@/composables/api-system'
import {useStorage} from '@vueuse/core'
import {cacheService} from '@/composables/cache'
import {API_CACHE_KEYS, invalidateApiCache, invalidateApiCacheByPrefix} from '@/composables/api-cache'
import {smartCache} from '@/composables/smartCache'

// 调试工具函数
export const useSystemStore = defineStore('system', () => {
  type ChangeSignalKey = 'emails' | 'dashboard' | 'forward_logs' | 'routing_config' | 'system_config'
  type ChangeSignals = Partial<Record<ChangeSignalKey, number>> & { updated_at?: string }

  const CHANGE_SIGNAL_STORAGE_KEY = 'cem_change_signals'

  const readLocalChangeSignals = (): ChangeSignals => {
    try {
      const raw = localStorage.getItem(CHANGE_SIGNAL_STORAGE_KEY)
      return raw ? JSON.parse(raw) : {}
    } catch {
      return {}
    }
  }

  const writeLocalChangeSignals = (signals: ChangeSignals) => {
    localStorage.setItem(CHANGE_SIGNAL_STORAGE_KEY, JSON.stringify(signals))
  }

  const invalidateByPrefixes = (prefixes: string[]) => {
    cacheService.keys().forEach((key) => {
      if (prefixes.some((prefix) => key.startsWith(prefix))) {
        cacheService.delete(key)
      }
    })
    prefixes.forEach((prefix) => smartCache.deleteByPrefix(prefix))
  }

  const invalidateCachesForChanges = (changedKeys: ChangeSignalKey[]) => {
    if (changedKeys.includes('emails')) {
      invalidateByPrefixes(['all_emails', 'dashboard_emails', 'getEmails'])
      cacheService.delete('dashboard:recent_emails')
    }

    if (changedKeys.includes('dashboard')) {
      cacheService.delete('dashboard:stats')
      cacheService.delete('dashboard:recent_emails')
    }

    if (changedKeys.includes('forward_logs')) {
      invalidateApiCacheByPrefix('api:routing:forward_logs')
      invalidateApiCache([API_CACHE_KEYS.ROUTING_STATS])
      cacheService.delete('dashboard:stats')
    }

    if (changedKeys.includes('routing_config')) {
      invalidateApiCache([
        API_CACHE_KEYS.ROUTING_RULES,
        API_CACHE_KEYS.ROUTING_STATS
      ])
      invalidateApiCacheByPrefix('api:routing:forward_logs')
    }

    if (changedKeys.includes('system_config')) {
      invalidateApiCache([API_CACHE_KEYS.SYSTEM_CONFIG])
      invalidateByPrefixes(['system_settings', 'getSystemConfig'])
    }
  }

  const detectChangedSignals = (signals?: ChangeSignals): ChangeSignalKey[] => {
    if (!signals) return []

    const previous = readLocalChangeSignals()
    const keys: ChangeSignalKey[] = ['emails', 'dashboard', 'forward_logs', 'routing_config', 'system_config']
    const hasPrevious = keys.some((key) => typeof previous[key] === 'number')

    writeLocalChangeSignals(signals)
    if (!hasPrevious) return []

    return keys.filter((key) => {
      const currentVersion = signals[key] || 0
      const previousVersion = previous[key] || 0
      return currentVersion > previousVersion
    })
  }

  const applyChangeSignals = (signals?: ChangeSignals): ChangeSignalKey[] => {
    const changedKeys = detectChangedSignals(signals)
    if (changedKeys.length > 0) {
      invalidateCachesForChanges(changedKeys)
    }
    return changedKeys
  }

  // 状态
  const systemHealth = ref<SystemHealth | null>(null)
  const registrationStatus = ref<{ allow_registration: number } | null>(null)
  // 使用 localStorage 存储 systemConfig
  const systemConfig = useStorage<SystemConfig | null>('systemConfig', null, localStorage, {
    serializer: {
      read: (value: string) => {
        try {
          return value ? JSON.parse(value) : null
        } catch {
          return null
        }
      },
      write: (value: SystemConfig | null) => {
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
          const healthConfig = response.data.health.config as { allow_registration: number; debug_mode: number; timezone?: string }

          // 使用空值合并赋值操作符，确保 systemConfig 存在并更新字段
          (systemConfig.value ??= {}).allow_registration = healthConfig.allow_registration
          systemConfig.value.debug_mode = healthConfig.debug_mode
          if (healthConfig.timezone) {
            systemConfig.value.timezone = healthConfig.timezone
          }
        }

        const changedKeys = applyChangeSignals(response.data.health?.changes)

        return { success: true, changedKeys }
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

  // 获取系统变更信号（轻量接口）
  const fetchSystemChanges = async () => {
    try {
      const response = await systemApiService.getSystemChanges()
      if (response.success && response.data) {
        const changedKeys = applyChangeSignals(response.data.changes)
        if (changedKeys.includes('system_config')) {
          await fetchSystemConfig({ forceRefresh: true })
        }
        return { success: true, changedKeys }
      }

      return { success: false, error: response.message || '获取系统变更信号失败' }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.message || '网络错误'
      }
    }
  }


  // 获取系统配置
  const fetchSystemConfig = async (options: { forceRefresh?: boolean } = {}) => {
    loading.value = true
    try {
      const response = await systemApiService.getSystemConfig(options)
      if (response.success && response.data) {
        // 正确提取 config 字段并保存到 localStorage
        systemConfig.value = response.data.config || response.data
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
      return systemConfig.value.debug_mode === 1
    }
    // 如果数据库设置不可用，默认返回 false（不使用环境变量）
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
    fetchSystemChanges,
    fetchSystemConfig
  }
})
