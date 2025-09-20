import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { SystemHealth } from '@/types'
import { systemApiService } from '@/composables/api'

export const useSystemStore = defineStore('system', () => {
  // 状态
  const systemHealth = ref<SystemHealth | null>(null)
  const registrationStatus = ref<{ allow_registration: boolean } | null>(null)
  const systemConfig = ref<{ debug_mode?: boolean } | null>(null)
  const loading = ref(false)

  // 获取系统健康状态
  const fetchSystemHealth = async () => {
    loading.value = true
    try {
      const response = await systemApiService.getSystemHealth()
      if (response.success && response.data) {
        systemHealth.value = response
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
        systemConfig.value = response.data
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
    // 开发环境强制开启
    if (import.meta.env.DEV || import.meta.env.VITE_DEBUG === 'true') {
      return true
    }
    // 生产环境使用数据库配置
    return systemConfig.value?.debug_mode || false
  })

  return {
    // 状态
    systemHealth,
    registrationStatus,
    systemConfig,
    loading,

    // 计算属性
    isDebugMode,

    // 方法
    fetchSystemHealth,
    fetchRegistrationStatus,
    fetchSystemConfig
  }
})
