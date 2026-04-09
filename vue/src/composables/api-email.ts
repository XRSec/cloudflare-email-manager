import { api, type ApiResponse } from './api-client'

type EmailListParams = {
  page?: number
  limit?: number
  search?: string
  status?: string
  sender?: string
  subject?: string
  start_date?: string
  end_date?: string
  has_attachments?: boolean
  sort?: string
  order?: 'asc' | 'desc'
}

const normalizeEmailListParams = (
  pageOrParams: number | EmailListParams = 1,
  limit = 20,
  search?: string,
  status?: string
) => {
  if (typeof pageOrParams === 'object') {
    return {
      page: pageOrParams.page || 1,
      limit: pageOrParams.limit || 20,
      ...pageOrParams
    }
  }

  return {
    page: pageOrParams,
    limit,
    search,
    status
  }
}

export const emailApiService = {
  async getEmails(
    pageOrParams: number | EmailListParams = 1,
    limit = 20,
    search?: string,
    status?: string
  ): Promise<ApiResponse<any>> {
    const params = normalizeEmailListParams(pageOrParams, limit, search, status)
    const urlParams = new URLSearchParams()

    urlParams.append('page', params.page.toString())
    urlParams.append('limit', params.limit.toString())
    if (params.search) urlParams.append('search', params.search)
    if (params.status) urlParams.append('status', params.status)
    if (params.sender) urlParams.append('sender', params.sender)
    if (params.subject) urlParams.append('subject', params.subject)
    if (params.start_date) urlParams.append('start_date', params.start_date)
    if (params.end_date) urlParams.append('end_date', params.end_date)
    if (params.has_attachments !== undefined) urlParams.append('has_attachments', String(params.has_attachments))
    if (params.sort) urlParams.append('sort', params.sort)
    if (params.order) urlParams.append('order', params.order)

    const response = await api.get(`/emails?${urlParams}`)
    return response.data
  },

  async getEmail(id: string): Promise<ApiResponse<any>> {
    const response = await api.get(`/emails/${id}`)
    return response.data
  },

  async deleteEmail(id: string): Promise<ApiResponse<any>> {
    const response = await api.delete(`/emails/${id}`)
    return response.data
  },

  async batchDeleteEmails(emailIds: string[]): Promise<ApiResponse<any>> {
    const response = await api.delete('/emails/batch', { data: { emailIds } })
    return response.data
  },

  async updateEmailReadStatus(id: string, isRead: boolean): Promise<ApiResponse<any>> {
    const response = await api.patch(`/emails/${id}/read-status`, { is_read: isRead })
    return response.data
  },

  async batchUpdateEmailReadStatus(emailIds: string[], isRead: boolean): Promise<ApiResponse<any>> {
    const response = await api.patch('/emails/batch/read-status', { emailIds, is_read: isRead })
    return response.data
  },

  async forwardEmail(
    id: string,
    payload:
      | { mode: 'webhook'; channelId: number }
      | { mode: 'recipient'; targetEmail: string; targetForwardType?: 'internal' | 'smtp' | 'cf'; from?: string }
  ): Promise<ApiResponse<any>> {
    const response = await api.post(`/emails/${id}/forward`, payload)
    return response.data
  },

  async sendEmail(
    toOrData: string | { to: string; from?: string; subject: string; content: string; content_type?: string },
    subject?: string,
    content?: string,
    from?: string,
    content_type: 'text' | 'html' | 'markdown' = 'markdown'
  ): Promise<ApiResponse<any>> {
    const emailData = typeof toOrData === 'string'
      ? {
        to: toOrData,
        subject: subject!,
        content: content!,
        from,
        content_type
      }
      : toOrData

    const response = await api.post('/emails/send', emailData)
    return response.data
  }
}
