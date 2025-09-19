import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { SystemHealth } from '@/types'
import { systemApiService } from '@/composables/api'

export const useSystemStore = defineStore('system', () => {
  // 状态
  const systemHealth = ref<SystemHealth | null>(null)
  const registrationStatus = ref<{ allow_registration: boolean } | null>(null)
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
        return { success: false, error: response.error || '获取系统状态失败' }
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
        return { success: false, error: response.error || '获取注册状态失败' }
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

  return {
    // 状态
    systemHealth,
    registrationStatus,
    loading,

    // 方法
    fetchSystemHealth,
    fetchRegistrationStatus
  }
})
