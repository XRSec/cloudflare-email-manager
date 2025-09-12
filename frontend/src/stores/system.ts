/**
 * 系统状态管理
 */

import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { SystemConfig, User, Mailbox, Email, ForwardRule, WebhookConfig } from '@/api'
import { apiService } from '@/api'

export const useSystemStore = defineStore('system', () => {
  // 状态
  const config = ref<SystemConfig | null>(null)
  const users = ref<User[]>([])
  const allMailboxes = ref<Mailbox[]>([])
  const allEmails = ref<Email[]>([])
  const forwardRules = ref<ForwardRule[]>([])
  const webhooks = ref<WebhookConfig[]>([])
  const loading = ref(false)
  const total = ref(0)
  const currentPage = ref(1)
  const pageSize = ref(20)

  // 获取系统配置
  const fetchConfig = async () => {
    loading.value = true
    try {
      const response = await apiService.getSystemConfig()
      if (response.success && response.data) {
        config.value = response.data
        return { success: true }
      } else {
        return { success: false, error: response.error || '获取系统配置失败' }
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
      if (response.success && response.data) {
        config.value = response.data
        return { success: true }
      } else {
        return { success: false, error: response.error || '更新系统配置失败' }
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
        users.value = response.data.users
        total.value = response.data.total
        currentPage.value = page
        pageSize.value = limit
        return { success: true }
      } else {
        return { success: false, error: response.error || '获取用户列表失败' }
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
  const createUser = async (username: string, password: string, role: 'admin' | 'user' = 'user') => {
    loading.value = true
    try {
      const response = await apiService.createUser(username, password, role)
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

  // 更新用户
  const updateUser = async (id: number, data: Partial<User>) => {
    loading.value = true
    try {
      const response = await apiService.updateUser(id, data)
      if (response.success && response.data) {
        const index = users.value.findIndex(u => u.id === id)
        if (index > -1) {
          users.value[index] = response.data
        }
        return { success: true, data: response.data }
      } else {
        return { success: false, error: response.error || '更新用户失败' }
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
        return { success: false, error: response.error || '删除用户失败' }
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
  const fetchAllMailboxes = async (page = 1, limit = 20, search = '') => {
    loading.value = true
    try {
      const response = await apiService.getAllMailboxes(page, limit, search)
      if (response.success && response.data) {
        allMailboxes.value = response.data.mailboxes
        total.value = response.data.total
        currentPage.value = page
        pageSize.value = limit
        return { success: true }
      } else {
        return { success: false, error: response.error || '获取邮箱列表失败' }
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
      const response = await apiService.getAllEmails(page, limit, search)
      if (response.success && response.data) {
        allEmails.value = response.data.emails
        total.value = response.data.total
        currentPage.value = page
        pageSize.value = limit
        return { success: true }
      } else {
        return { success: false, error: response.error || '获取邮件列表失败' }
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
        forwardRules.value = response.data
        return { success: true }
      } else {
        return { success: false, error: response.error || '获取转发规则失败' }
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
  const createForwardRule = async (rule: Omit<ForwardRule, 'id' | 'created_at'>) => {
    loading.value = true
    try {
      const response = await apiService.createForwardRule(rule)
      if (response.success && response.data) {
        forwardRules.value.unshift(response.data)
        return { success: true, data: response.data }
      } else {
        return { success: false, error: response.error || '创建转发规则失败' }
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
  const updateForwardRule = async (id: number, rule: Partial<ForwardRule>) => {
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
        return { success: false, error: response.error || '更新转发规则失败' }
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
        return { success: false, error: response.error || '删除转发规则失败' }
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

  // 发送用户信息
  const sendUserInfo = async (userId: number, subject: string, content: string) => {
    loading.value = true
    try {
      const response = await apiService.sendUserInfo(userId, subject, content)
      if (response.success) {
        return { success: true }
      } else {
        return { success: false, error: response.error || '发送用户信息失败' }
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
    
    // 方法
    fetchConfig,
    updateConfig,
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
