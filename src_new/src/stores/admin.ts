/**
 * 管理员状态管理
 */
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { User, Email, ForwardRule, SystemConfig } from '@/types'
import { apiService } from '@/services/api'

export const useAdminStore = defineStore('admin', () => {
  // 状态
  const users = ref<User[]>([])
  const allEmails = ref<Email[]>([])
  const forwardRules = ref<ForwardRule[]>([])
  const adminConfig = ref<SystemConfig | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  // 计算属性
  const totalUsers = computed(() => users.value.length)
  const adminUsers = computed(() => users.value.filter(u => u.user_type === 'admin'))
  const regularUsers = computed(() => users.value.filter(u => u.user_type === 'user'))
  const enabledRules = computed(() => forwardRules.value.filter(r => r.enabled))

  // 操作
  const setUsers = (newUsers: User[]) => {
    users.value = newUsers
  }

  const setAllEmails = (emails: Email[]) => {
    allEmails.value = emails
  }

  const setForwardRules = (rules: ForwardRule[]) => {
    forwardRules.value = rules
  }

  const setAdminConfig = (config: SystemConfig | null) => {
    adminConfig.value = config
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

  // 加载用户列表
  const loadUsers = async (): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.getUsers()
      
      if (response.success && response.data) {
        setUsers(response.data.users)
        return true
      }
      
      setError(response.error || '加载用户列表失败')
      return false
    } catch (err: any) {
      setError(err.message || '加载用户列表失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 删除用户
  const deleteUser = async (id: number): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.deleteUser(id)
      
      if (response.success) {
        // 从列表中移除用户
        users.value = users.value.filter(user => user.id !== id)
        return true
      }
      
      setError(response.error || '删除用户失败')
      return false
    } catch (err: any) {
      setError(err.message || '删除用户失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 发送用户信息
  const sendUserInfo = async (id: number): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.sendUserInfo(id)
      
      if (response.success) {
        return true
      }
      
      setError(response.error || '发送用户信息失败')
      return false
    } catch (err: any) {
      setError(err.message || '发送用户信息失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 加载转发规则
  const loadForwardRules = async (): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.getForwardRules()
      
      if (response.success && response.data) {
        setForwardRules(response.data.rules)
        return true
      }
      
      setError(response.error || '加载转发规则失败')
      return false
    } catch (err: any) {
      setError(err.message || '加载转发规则失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 删除转发规则
  const deleteForwardRule = async (id: number): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.deleteForwardRule(id)
      
      if (response.success) {
        // 从列表中移除规则
        forwardRules.value = forwardRules.value.filter(rule => rule.id !== id)
        return true
      }
      
      setError(response.error || '删除转发规则失败')
      return false
    } catch (err: any) {
      setError(err.message || '删除转发规则失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 加载所有邮件
  const loadAllEmails = async (): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.getAllEmails()
      
      if (response.success && response.data) {
        setAllEmails(response.data.emails)
        return true
      }
      
      setError(response.error || '加载邮件列表失败')
      return false
    } catch (err: any) {
      setError(err.message || '加载邮件列表失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 加载管理员设置
  const loadAdminSettings = async (): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.getAdminSettings()
      
      if (response.success && response.data) {
        setAdminConfig(response.data.config)
        return true
      }
      
      setError(response.error || '加载系统设置失败')
      return false
    } catch (err: any) {
      setError(err.message || '加载系统设置失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 更新管理员设置
  const updateAdminSettings = async (updates: Partial<SystemConfig>): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.updateAdminSettings(updates)
      
      if (response.success) {
        // 重新加载设置
        await loadAdminSettings()
        return true
      }
      
      setError(response.error || '更新系统设置失败')
      return false
    } catch (err: any) {
      setError(err.message || '更新系统设置失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 重置状态
  const reset = () => {
    setUsers([])
    setAllEmails([])
    setForwardRules([])
    setAdminConfig(null)
    setError(null)
  }

  return {
    // 状态
    users: readonly(users),
    allEmails: readonly(allEmails),
    forwardRules: readonly(forwardRules),
    adminConfig: readonly(adminConfig),
    loading: readonly(loading),
    error: readonly(error),
    
    // 计算属性
    totalUsers,
    adminUsers,
    regularUsers,
    enabledRules,
    
    // 操作
    setUsers,
    setAllEmails,
    setForwardRules,
    setAdminConfig,
    setLoading,
    setError,
    clearError,
    loadUsers,
    deleteUser,
    sendUserInfo,
    loadForwardRules,
    deleteForwardRule,
    loadAllEmails,
    loadAdminSettings,
    updateAdminSettings,
    reset
  }
})