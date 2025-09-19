/**
 * 系统状态管理
 */

import { createGlobalState } from '@vueuse/core'
import { ref, computed } from 'vue'
import type { SystemConfig, UserProfile, Mailbox, EmailSummary, ForwardRuleResponse } from '@/api'
import { apiService } from '@/api'
import { configCache } from '@/utils/configCache'

// 声明全局类型
declare global {
  interface Window {
    CEM_CONFIG?: {
      allow_registration: boolean
      debug_mode: boolean
      supported_domains: string[]
      max_attachment_size: number
      api_base_url: string
      version: string
      build_time: string
    }
    ConfigManager?: {
      isRegistrationAllowed(): boolean
      isDebugMode(): boolean
      getSupportedDomains(): string[]
      getMaxAttachmentSize(): number
    }
  }
}

export const useSystemStore = createGlobalState('system', () => {
  // 状态
  const config = ref<SystemConfig | null>(null)
  const users = ref<UserProfile[]>([])
  const allMailboxes = ref<Mailbox[]>([])
  const allEmails = ref<EmailSummary[]>([])
  const forwardRules = ref<ForwardRuleResponse[]>([])
  const webhooks = ref<any[]>([])
  const loading = ref(false)
  const total = ref(0)
  const currentPage = ref(1)
  const pageSize = ref(20)

  // 获取系统配置
  const fetchConfig = async (forceRefresh = false) => {
    loading.value = true
    try {
      // 优先使用注入的配置
      if (window.CEM_CONFIG && window.ConfigManager) {
        config.value = {
          allow_registration: window.ConfigManager.isRegistrationAllowed(),
          debug_mode: window.ConfigManager.isDebugMode(),
          supported_domains: window.ConfigManager.getSupportedDomains(),
          attachment_max_size: window.ConfigManager.getMaxAttachmentSize(),
          auto_approve_mailbox: false, // 默认值
          mail_retention_days: 30, // 默认值
          allow_user_send: false, // 默认值
          max_mailboxes_per_user: 5, // 默认值
          storage_provider: 'r2' as const // 默认值
        }

        // 检查环境变量强制开启debug模式（开发环境）
        if (import.meta.env.DEV || import.meta.env.VITE_DEBUG === 'true') {
          if (config.value) {
            config.value.debug_mode = true
          }
        }

        return { success: true }
      }

      // 降级到缓存获取
      if (!forceRefresh) {
        const cachedConfig = await configCache.getSystemConfig()
        if (cachedConfig) {
          config.value = cachedConfig
          return { success: true }
        }
      }

      // 最后降级到API获取
      const response = await apiService.getSystemConfig()
      if (response.success && response.data) {
        config.value = response.data.config || response.data

        // 检查环境变量强制开启debug模式（开发环境）
        if (import.meta.env.DEV || import.meta.env.VITE_DEBUG === 'true') {
          if (config.value) {
            config.value.debug_mode = true
          }
        }

        // 更新缓存
        if (config.value) {
          configCache.updateConfig('system_config', config.value)
        }

        return { success: true }
      } else {
        return { success: false, error: response.message || '获取系统配置失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 更新系统配置
  const updateConfig = async (newConfig: Partial<SystemConfig>) => {
    loading.value = true
    try {
      const response = await apiService.updateSystemConfig(newConfig)
      if (response.success) {
        // 如果后端返回了新的配置数据，则更新本地状态
        if (response.data) {
          config.value = response.data
        } else {
          // 如果没有返回数据，则合并到现有配置中
          if (config.value) {
            Object.assign(config.value, newConfig)
          }
        }
        return { success: true }
      } else {
        return { success: false, error: response.message || '更新系统配置失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 获取用户列表
  const fetchUsers = async (page = 1, limit = 20, search = '') => {
    loading.value = true
    try {
      const response = await apiService.getUsers(page, limit, search)
      if (response.success && response.data) {
        users.value = response.data.items
        total.value = response.data.total
        currentPage.value = page
        pageSize.value = limit
        return { success: true }
      } else {
        return { success: false, error: response.message || '获取用户列表失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 创建用户
  const createUser = async (username: string, password: string, user_type: 'admin' | 'user' = 'user') => {
    loading.value = true
    try {
      const response = await apiService.createUser(username, password, user_type)
      if (response.success && response.data) {
        users.value.unshift(response.data)
        return { success: true, data: response.data }
      } else {
        return { success: false, error: response.error || '创建用户失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 更新用户（暂时移除，API中不存在此方法）
  const updateUser = async (id: number, data: Partial<UserProfile>) => {
    return { success: false, error: '更新用户功能暂未实现' }
  }

  // 删除用户
  const deleteUser = async (id: number) => {
    loading.value = true
    try {
      const response = await apiService.deleteUser(id)
      if (response.success) {
        const index = users.value.findIndex(u => u.id === id)
        if (index > -1) {
          users.value.splice(index, 1)
        }
        return { success: true }
      } else {
        return { success: false, error: response.message || '删除用户失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 获取所有邮箱
  const fetchAllMailboxes = async (page = 1, limit = 20, search = '', scope?: 'all') => {
    loading.value = true
    try {
      const response = await apiService.getMailboxes(page, limit, scope)
      if (response.success && response.data) {
        allMailboxes.value = response.data.items
        total.value = response.data.total
        currentPage.value = page
        pageSize.value = limit
        return { success: true }
      } else {
        return { success: false, error: response.message || '获取邮箱列表失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 获取所有邮件
  const fetchAllEmails = async (page = 1, limit = 20, search = '') => {
    loading.value = true
    try {
      const response = await apiService.getEmails(page, limit, search)
      if (response.success && response.data) {
        allEmails.value = response.data.emails
        total.value = response.data.total
        currentPage.value = page
        pageSize.value = limit
        return { success: true }
      } else {
        return { success: false, error: response.message || '获取邮件列表失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 获取转发规则
  const fetchForwardRules = async () => {
    loading.value = true
    try {
      const response = await apiService.getForwardRules()
      if (response.success && response.data) {
        forwardRules.value = response.data.items || []
        return { success: true }
      } else {
        return { success: false, error: response.message || '获取转发规则失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 创建转发规则
  const createForwardRule = async (rule: any) => {
    loading.value = true
    try {
      const response = await apiService.createForwardRule(rule)
      if (response.success && response.data) {
        forwardRules.value.unshift(response.data)
        return { success: true, data: response.data }
      } else {
        return { success: false, error: response.message || '创建转发规则失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 更新转发规则
  const updateForwardRule = async (id: number, rule: any) => {
    loading.value = true
    try {
      const response = await apiService.updateForwardRule(id, rule)
      if (response.success && response.data) {
        const index = forwardRules.value.findIndex(r => r.id === id)
        if (index > -1) {
          forwardRules.value[index] = response.data
        }
        return { success: true, data: response.data }
      } else {
        return { success: false, error: response.message || '更新转发规则失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 删除转发规则
  const deleteForwardRule = async (id: number) => {
    loading.value = true
    try {
      const response = await apiService.deleteForwardRule(id)
      if (response.success) {
        const index = forwardRules.value.findIndex(r => r.id === id)
        if (index > -1) {
          forwardRules.value.splice(index, 1)
        }
        return { success: true }
      } else {
        return { success: false, error: response.message || '删除转发规则失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 发送用户信息（暂时移除，API中不存在此方法）
  const sendUserInfo = async (userId: number, subject: string, content: string) => {
    return { success: false, error: '发送用户信息功能暂未实现' }
  }

  // 计算属性
  const isDebugMode = computed(() => {
    // 开发环境强制开启
    if (import.meta.env.DEV || import.meta.env.VITE_DEBUG === 'true') {
      return true
    }
    // 生产环境使用数据库配置
    return config.value?.debug_mode || false
  })

  // 刷新配置缓存
  const refreshConfig = async () => {
    // 清空所有配置缓存
    configCache.clear()

    // 重新获取配置
    const result = await fetchConfig(true)

    if (result.success) {
      console.log('[SystemStore] 配置已刷新')
    }

    return result
  }

  return {
    // 状态
    config,
    users,
    allMailboxes,
    allEmails,
    forwardRules,
    webhooks,
    loading,
    total,
    currentPage,
    pageSize,

    // 计算属性
    isDebugMode,

    // 方法
    fetchConfig,
    updateConfig,
    refreshConfig,
    fetchUsers,
    createUser,
    updateUser,
    deleteUser,
    fetchAllMailboxes,
    fetchAllEmails,
    fetchForwardRules,
    createForwardRule,
    updateForwardRule,
    deleteForwardRule,
    sendUserInfo
  }
})
