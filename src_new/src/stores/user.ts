/**
 * 用户设置状态管理
 */
import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { UserSettingsUpdate } from '@/types'
import { apiService } from '@/services/api'

export const useUserStore = defineStore('user', () => {
  // 状态
  const settings = ref<UserSettingsUpdate>({})
  const loading = ref(false)
  const error = ref<string | null>(null)

  // 操作
  const setSettings = (newSettings: UserSettingsUpdate) => {
    settings.value = { ...newSettings }
  }

  const setLoading = (isLoading: boolean) => {
    loading.value = isLoading
  }

  const setError = (errorMessage: string | null) => {
    error.value = errorMessage
  }

  const clearError = () => {
    error.value = null
  }

  // 加载用户设置
  const loadSettings = async (): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.getUserSettings()
      
      if (response.success && response.data) {
        setSettings(response.data)
        return true
      }
      
      setError(response.error || '加载设置失败')
      return false
    } catch (err: any) {
      setError(err.message || '加载设置失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 更新用户设置
  const updateSettings = async (updates: UserSettingsUpdate): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      // 过滤空值
      const filteredUpdates: UserSettingsUpdate = {}
      
      if (updates.email_password && updates.email_password.trim()) {
        if (updates.email_password.length < 6) {
          setError('密码长度至少为6位')
          return false
        }
        filteredUpdates.email_password = updates.email_password
      }

      if (updates.webhook_url !== undefined) {
        filteredUpdates.webhook_url = updates.webhook_url.trim() || ''
      }

      if (updates.webhook_secret !== undefined) {
        filteredUpdates.webhook_secret = updates.webhook_secret.trim() || ''
      }

      if (Object.keys(filteredUpdates).length === 0) {
        setError('没有需要更新的内容')
        return false
      }

      const response = await apiService.updateUserSettings(filteredUpdates)
      
      if (response.success) {
        // 重新加载设置
        await loadSettings()
        return true
      }
      
      setError(response.error || '更新设置失败')
      return false
    } catch (err: any) {
      setError(err.message || '更新设置失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 重置状态
  const reset = () => {
    setSettings({})
    setError(null)
  }

  return {
    // 状态
    settings: readonly(settings),
    loading: readonly(loading),
    error: readonly(error),
    
    // 操作
    setSettings,
    setLoading,
    setError,
    clearError,
    loadSettings,
    updateSettings,
    reset
  }
})