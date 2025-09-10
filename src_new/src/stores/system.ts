/**
 * 系统状态管理
 */
import { defineStore } from 'pinia'
import { ref, computed, readonly } from 'vue'
import type { SystemConfig } from '@/types'
import { apiService } from '@/services/api'

export const useSystemStore = defineStore('system', () => {
  // 状态
  const config = ref<SystemConfig | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  // 计算属性
  const allowRegistration = computed(() => config.value?.allow_registration ?? false)
  const debugMode = computed(() => config.value?.debug_mode ?? false)
  const domains = computed(() => config.value?.domains ?? [])
  const primaryDomain = computed(() => domains.value[0] || 'example.com')

  // 操作
  const setConfig = (newConfig: SystemConfig | null) => {
    config.value = newConfig
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

  // 加载系统配置
  const loadConfig = async (): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.getSystemConfig()
      
      if (response.success && response.data) {
        setConfig(response.data.config)
        return true
      }
      
      setError(response.error || '加载系统配置失败')
      return false
    } catch (err: any) {
      setError(err.message || '加载系统配置失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 更新系统配置（管理员）
  const updateConfig = async (updates: Partial<SystemConfig>): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.updateAdminSettings(updates)
      
      if (response.success) {
        // 重新加载配置
        await loadConfig()
        return true
      }
      
      setError(response.error || '更新系统配置失败')
      return false
    } catch (err: any) {
      setError(err.message || '更新系统配置失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 获取完整邮箱地址
  const getFullEmailAddress = (prefix: string): string => {
    return `${prefix}@${primaryDomain.value}`
  }

  // 格式化文件大小
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  // 格式化日期
  const formatDate = (dateString: string): string => {
    const date = new Date(dateString)
    const now = new Date()
    const diffTime = Math.abs(now.getTime() - date.getTime())
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))

    if (diffDays === 1) {
      return '今天 ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
    } else if (diffDays === 2) {
      return '昨天 ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
    } else if (diffDays <= 7) {
      return (diffDays - 1) + '天前'
    } else {
      return date.toLocaleDateString('zh-CN') + ' ' +
             date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
    }
  }

  return {
    // 状态
    config: readonly(config),
    loading: readonly(loading),
    error: readonly(error),
    
    // 计算属性
    allowRegistration,
    debugMode,
    domains,
    primaryDomain,
    
    // 操作
    setConfig,
    setLoading,
    setError,
    clearError,
    loadConfig,
    updateConfig,
    
    // 工具函数
    getFullEmailAddress,
    formatFileSize,
    formatDate
  }
})