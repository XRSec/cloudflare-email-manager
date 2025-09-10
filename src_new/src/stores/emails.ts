/**
 * 邮件状态管理
 */
import { defineStore } from 'pinia'
import { ref, computed, readonly } from 'vue'
import type { Email, EmailQueryParams, Attachment } from '@/types'
import { apiService } from '@/services/api'

export const useEmailStore = defineStore('emails', () => {
  // 状态
  const emails = ref<Email[]>([])
  const currentEmail = ref<Email | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  
  // 分页状态
  const pagination = ref({
    page: 1,
    limit: 20,
    total: 0
  })

  // 计算属性
  const totalPages = computed(() => Math.ceil(pagination.value.total / pagination.value.limit))
  const hasEmails = computed(() => emails.value.length > 0)
  const currentPageEmails = computed(() => emails.value)

  // 操作
  const setEmails = (newEmails: Email[]) => {
    emails.value = newEmails
  }

  const setCurrentEmail = (email: Email | null) => {
    currentEmail.value = email
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

  const setPagination = (page: number, limit: number, total: number) => {
    pagination.value = { page, limit, total }
  }

  // 加载邮件列表
  const loadEmails = async (params?: EmailQueryParams): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const queryParams = {
        page: pagination.value.page,
        limit: pagination.value.limit,
        ...params
      }

      const response = await apiService.getEmails(queryParams)
      
      if (response.success && response.data) {
        setEmails(response.data.emails)
        setPagination(response.data.page, response.data.limit, response.data.total)
        return true
      }
      
      setError(response.error || '加载邮件失败')
      return false
    } catch (err: any) {
      setError(err.message || '加载邮件失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 加载邮件详情
  const loadEmailDetail = async (id: number): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.getEmail(id)
      
      if (response.success && response.data) {
        setCurrentEmail(response.data)
        return true
      }
      
      setError(response.error || '加载邮件详情失败')
      return false
    } catch (err: any) {
      setError(err.message || '加载邮件详情失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 删除邮件
  const deleteEmail = async (id: number): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.deleteEmail(id)
      
      if (response.success) {
        // 从列表中移除邮件
        emails.value = emails.value.filter(email => email.id !== id)
        
        // 如果删除的是当前邮件，清除当前邮件
        if (currentEmail.value?.id === id) {
          setCurrentEmail(null)
        }
        
        // 更新总数
        pagination.value.total = Math.max(0, pagination.value.total - 1)
        
        return true
      }
      
      setError(response.error || '删除邮件失败')
      return false
    } catch (err: any) {
      setError(err.message || '删除邮件失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 下载附件
  const downloadAttachment = async (attachment: Attachment): Promise<boolean> => {
    try {
      const blob = await apiService.downloadAttachment(attachment.id)
      
      // 创建下载链接
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = attachment.filename
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
      
      return true
    } catch (err: any) {
      setError(err.message || '下载附件失败')
      return false
    }
  }

  // 切换页面
  const goToPage = async (page: number): Promise<boolean> => {
    if (page < 1 || page > totalPages.value) {
      return false
    }
    
    pagination.value.page = page
    return await loadEmails()
  }

  // 上一页
  const previousPage = async (): Promise<boolean> => {
    return await goToPage(pagination.value.page - 1)
  }

  // 下一页
  const nextPage = async (): Promise<boolean> => {
    return await goToPage(pagination.value.page + 1)
  }

  // 刷新当前页
  const refresh = async (): Promise<boolean> => {
    return await loadEmails()
  }

  // 重置状态
  const reset = () => {
    setEmails([])
    setCurrentEmail(null)
    setError(null)
    setPagination(1, 20, 0)
  }

  // 搜索邮件
  const searchEmails = async (query: string): Promise<boolean> => {
    pagination.value.page = 1 // 重置到第一页
    return await loadEmails({ search: query })
  }

  // 按发件人过滤
  const filterBySender = async (sender: string): Promise<boolean> => {
    pagination.value.page = 1
    return await loadEmails({ sender })
  }

  // 按主题过滤
  const filterBySubject = async (subject: string): Promise<boolean> => {
    pagination.value.page = 1
    return await loadEmails({ subject })
  }

  // 按日期范围过滤
  const filterByDateRange = async (startDate: string, endDate: string): Promise<boolean> => {
    pagination.value.page = 1
    return await loadEmails({ 
      start_date: startDate, 
      end_date: endDate 
    })
  }

  // 按是否有附件过滤
  const filterByAttachments = async (hasAttachments: boolean): Promise<boolean> => {
    pagination.value.page = 1
    return await loadEmails({ has_attachments: hasAttachments })
  }

  return {
    // 状态
    emails: readonly(emails),
    currentEmail: readonly(currentEmail),
    loading: readonly(loading),
    error: readonly(error),
    pagination: readonly(pagination),
    
    // 计算属性
    totalPages,
    hasEmails,
    currentPageEmails,
    
    // 操作
    setEmails,
    setCurrentEmail,
    setLoading,
    setError,
    clearError,
    setPagination,
    loadEmails,
    loadEmailDetail,
    deleteEmail,
    downloadAttachment,
    goToPage,
    previousPage,
    nextPage,
    refresh,
    reset,
    searchEmails,
    filterBySender,
    filterBySubject,
    filterByDateRange,
    filterByAttachments
  }
})