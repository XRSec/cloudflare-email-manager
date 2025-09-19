/**
 * 邮箱状态管理
 */

import { createGlobalState } from '@vueuse/core'
import { ref, computed } from 'vue'
import type { Mailbox, Email } from '@/api'
import { apiService } from '@/api'

export const useMailboxStore = createGlobalState('mailbox', () => {
  // 状态
  const mailboxes = ref<Mailbox[]>([])
  const emails = ref<Email[]>([])
  const currentMailbox = ref<Mailbox | null>(null)
  const loading = ref(false)
  const total = ref(0)
  const currentPage = ref(1)
  const pageSize = ref(20)

  // 计算属性
  const activeMailboxes = computed(() => 
    mailboxes.value.filter(mb => mb.status === 'active')
  )

  const pendingMailboxes = computed(() => 
    mailboxes.value.filter(mb => mb.status === 'pending')
  )

  // 获取邮箱列表
  const fetchMailboxes = async () => {
    loading.value = true
    try {
      const response = await apiService.getMailboxes()
      if (response.success && response.data) {
        mailboxes.value = response.data
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

  // 创建邮箱
  const createMailbox = async (email: string) => {
    loading.value = true
    try {
      const response = await apiService.createMailbox(email)
      if (response.success && response.data) {
        mailboxes.value.unshift(response.data)
        return { success: true, data: response.data }
      } else {
        return { success: false, error: response.error || '创建邮箱失败' }
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

  // 删除邮箱
  const deleteMailbox = async (id: number) => {
    loading.value = true
    try {
      const response = await apiService.deleteMailbox(id)
      if (response.success) {
        const index = mailboxes.value.findIndex(mb => mb.id === id)
        if (index > -1) {
          mailboxes.value.splice(index, 1)
        }
        return { success: true }
      } else {
        return { success: false, error: response.error || '删除邮箱失败' }
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

  // 获取邮件列表
  const fetchEmails = async (mailboxId?: number, page = 1, limit = 20) => {
    loading.value = true
    try {
      const response = await apiService.getEmails(mailboxId, page, limit)
      if (response.success && response.data) {
        emails.value = response.data.emails
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

  // 搜索邮件
  const searchEmails = async (keyword: string, mailboxId?: number) => {
    loading.value = true
    try {
      const response = await apiService.searchEmails(keyword, mailboxId)
      if (response.success && response.data) {
        emails.value = response.data
        return { success: true }
      } else {
        return { success: false, error: response.error || '搜索邮件失败' }
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

  // 设置当前邮箱
  const setCurrentMailbox = (mailbox: Mailbox | null) => {
    currentMailbox.value = mailbox
  }

  // 刷新当前页面数据
  const refresh = async () => {
    await fetchMailboxes()
    if (currentMailbox.value) {
      await fetchEmails(currentMailbox.value.id, currentPage.value, pageSize.value)
    } else {
      await fetchEmails(undefined, currentPage.value, pageSize.value)
    }
  }

  return {
    // 状态
    mailboxes,
    emails,
    currentMailbox,
    loading,
    total,
    currentPage,
    pageSize,
    
    // 计算属性
    activeMailboxes,
    pendingMailboxes,
    
    // 方法
    fetchMailboxes,
    createMailbox,
    deleteMailbox,
    fetchEmails,
    searchEmails,
    setCurrentMailbox,
    refresh
  }
})
