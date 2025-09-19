import { createGlobalState, useStorage } from '@vueuse/core'
import { computed, ref } from 'vue'

// 邮件接口
interface Email {
  id: string
  subject: string
  from: string
  to: string
  date: string
  content: string
  isRead: boolean
  attachments?: Array<{
    name: string
    size: number
    url: string
  }>
}

// 邮箱状态接口
interface MailboxState {
  emails: Email[]
  selectedEmail: Email | null
  isLoading: boolean
  currentPage: number
  totalPages: number
  filter: {
    search: string
    isRead: boolean | null
  }
}

// 创建全局状态
export const useMailboxStore = createGlobalState(() => {
  // 使用 localStorage 持久化存储
  const emails = useStorage('mailbox_emails', [] as Email[])
  const selectedEmail = ref<Email | null>(null)
  const isLoading = ref(false)
  const currentPage = ref(1)
  const totalPages = ref(1)
  const filter = ref({
    search: '',
    isRead: null as boolean | null,
  })

  // 计算属性
  const filteredEmails = computed(() => {
    let filtered = emails.value

    // 搜索过滤
    if (filter.value.search) {
      const search = filter.value.search.toLowerCase()
      filtered = filtered.filter(email =>
        email.subject.toLowerCase().includes(search) ||
        email.from.toLowerCase().includes(search) ||
        email.content.toLowerCase().includes(search)
      )
    }

    // 已读状态过滤
    if (filter.value.isRead !== null) {
      filtered = filtered.filter(email => email.isRead === filter.value.isRead)
    }

    return filtered
  })

  const unreadCount = computed(() =>
    emails.value.filter(email => !email.isRead).length
  )

  // 获取邮件列表
  const fetchEmails = async (page = 1) => {
    isLoading.value = true
    try {
      const response = await fetch(`/api/emails?page=${page}`)
      if (response.ok) {
        const data = await response.json()
        emails.value = data.emails
        currentPage.value = data.currentPage
        totalPages.value = data.totalPages
      }
    } catch (error) {
      console.error('获取邮件失败:', error)
    } finally {
      isLoading.value = false
    }
  }

  // 获取单个邮件
  const fetchEmail = async (id: string) => {
    isLoading.value = true
    try {
      const response = await fetch(`/api/emails/${id}`)
      if (response.ok) {
        const email = await response.json()
        selectedEmail.value = email

        // 标记为已读
        const index = emails.value.findIndex(e => e.id === id)
        if (index !== -1) {
          emails.value[index].isRead = true
        }
      }
    } catch (error) {
      console.error('获取邮件详情失败:', error)
    } finally {
      isLoading.value = false
    }
  }

  // 删除邮件
  const deleteEmail = async (id: string) => {
    try {
      const response = await fetch(`/api/emails/${id}`, {
        method: 'DELETE',
      })
      if (response.ok) {
        emails.value = emails.value.filter(email => email.id !== id)
        if (selectedEmail.value?.id === id) {
          selectedEmail.value = null
        }
      }
    } catch (error) {
      console.error('删除邮件失败:', error)
    }
  }

  // 标记邮件为已读/未读
  const toggleRead = async (id: string) => {
    const email = emails.value.find(e => e.id === id)
    if (email) {
      try {
        const response = await fetch(`/api/emails/${id}/read`, {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ isRead: !email.isRead }),
        })
        if (response.ok) {
          email.isRead = !email.isRead
        }
      } catch (error) {
        console.error('更新邮件状态失败:', error)
      }
    }
  }

  // 设置过滤器
  const setFilter = (newFilter: Partial<typeof filter.value>) => {
    filter.value = { ...filter.value, ...newFilter }
  }

  // 清空过滤器
  const clearFilter = () => {
    filter.value = {
      search: '',
      isRead: null,
    }
  }

  return {
    // 状态
    emails: readonly(emails),
    selectedEmail: readonly(selectedEmail),
    isLoading: readonly(isLoading),
    currentPage: readonly(currentPage),
    totalPages: readonly(totalPages),
    filter: readonly(filter),

    // 计算属性
    filteredEmails,
    unreadCount,

    // 方法
    fetchEmails,
    fetchEmail,
    deleteEmail,
    toggleRead,
    setFilter,
    clearFilter,
  }
})

// 导出类型
export type { Email, MailboxState }
