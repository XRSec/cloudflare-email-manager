/**
 * API 服务模块
 * 基于 API 文档 v2.0.0 实现
 */

import axios, { type AxiosInstance, type AxiosResponse } from 'axios'

// API 响应类型
export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  message?: string
}

// 用户信息类型
export interface UserProfile {
  id: number
  username: string
  email?: string
  user_type: 'admin' | 'user'
  status: 1 | 2 | 3 // 1=激活, 2=停用, 3=删除
  deleted_at?: string
  webhook_url?: string
  created_at: string
  updated_at?: string
  settings?: UserSettings
}

export interface UserSettings {
  webhook_url?: string
  webhook_secret?: string
}

export interface UserSettingsUpdate {
  password?: string
  webhook_url?: string
  webhook_secret?: string
}

// 邮箱信息类型
export interface Mailbox {
  id: number
  address: string
  owner_id: number
  owner_username?: string
  created_at: string
  updated_at?: string
  status: 1 | 2 | 3 // 1=激活, 2=停用, 3=删除
  deleted_at?: string
}

export interface MailboxApplicationRequest {
  reason?: string
}

export interface MailboxApplicationResponse {
  application_id: number
  status: 1 | 2 | 3 // 1=待审核, 2=已批准, 3=已拒绝
}

export interface AdminMailboxCreateRequest {
  address: string
  owner_id: number
}

// 邮件信息类型
export interface EmailSummary {
  id: string
  subject: string
  from: string
  to: string
  status: 'received' | 'processed' | 'forwarded' | 'failed'
  received_at: string
}

export interface EmailDetail extends EmailSummary {
  content: string
  attachments: Attachment[]
}

export interface Attachment {
  id: string
  filename: string
  size: number
}

// 邮箱历史记录接口
export interface MailboxHistory {
  id: number;
  mailbox_id: number;
  user_id: number;
  owner_id: number;
  action_type: 1 | 2 | 3; // 1=创建, 2=删除, 3=停用
  created_at: string;
  user_username?: string;
  owner_username?: string;
  mailbox_address?: string;
}

// 转发规则类型
export interface ForwardRuleBase {
  rule_name: string
  sender_filter?: string
  keyword_filter?: string
  recipient_filter?: string
  webhook_url: string
  webhook_secret?: string
  webhook_type: 'dingtalk' | 'feishu' | 'custom'
  enabled: boolean
}

export interface ForwardRuleCreateRequest extends ForwardRuleBase {
  rule_name: string
  webhook_url: string
}

export interface ForwardRuleUpdateRequest extends ForwardRuleBase { }

export interface ForwardRuleResponse {
  id: number
  rule: ForwardRuleBase
  created_at: string
}

// 系统配置类型
export interface SystemConfig {
  debug_mode: boolean
  allow_registration: boolean
  auto_approve_mailbox: boolean
  supported_domains: string[]
  mail_retention_days: number
  attachment_max_size: number
  allow_user_send?: boolean
  max_mailboxes_per_user?: number
  storage_provider?: 'r2' | 's3' | 'local'
}

export interface SystemConfigUpdate {
  debug_mode?: boolean
  allow_registration?: boolean
  auto_approve_mailbox?: boolean
  supported_domains?: string[]
  mail_retention_days?: number
  attachment_max_size?: number
  allow_user_send?: boolean
  max_mailboxes_per_user?: number
  storage_provider?: 'r2' | 's3' | 'local'
}

// 分页响应类型
export interface PaginatedResponse<T> {
  total: number
  items: T[]
}

// 登录响应类型
export interface LoginResponse {
  message: string
}

// 管理员创建用户请求
export interface AdminUserCreateRequest {
  username: string
  password: string
  email: string
  user_type?: 'user' | 'admin'
}

// 申请处理请求
export interface ApplicationProcessRequest {
  action: 'approve' | 'reject'
}

class ApiService {
  private api: AxiosInstance

  constructor() {
    this.api = axios.create({
      baseURL: '/api',
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json'
      },
      withCredentials: true // 支持 cookie 认证
    })

    // 请求拦截器 - 使用 cookies 认证，不需要手动添加 Authorization header
    this.api.interceptors.request.use(
      (config) => {
        // 所有请求都会自动包含 cookies
        return config
      },
      (error) => {
        return Promise.reject(error)
      }
    )

    // 响应拦截器
    this.api.interceptors.response.use(
      (response: AxiosResponse<ApiResponse>) => {
        return response
      },
      (error) => {
        if (error.response?.status === 401) {
          // 未授权，清理所有认证数据并重定向到登录页
          this.clearAllAuthDataAndRedirect()
        }
        return Promise.reject(error)
      }
    )
  }

  // 清理所有认证数据并重定向到登录页
  private clearAllAuthDataAndRedirect() {
    // 清理 localStorage 中的认证信息
    localStorage.removeItem('user_info')
    localStorage.removeItem('auth_token')
    localStorage.removeItem('cem_persist_auth_token')

    // 清理 sessionStorage
    sessionStorage.clear()

    // 清理 cookies
    document.cookie = 'session_cookies=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'

    // 如果当前不在登录页，重定向到登录页（携带当前页面作为重定向参数）
    if (window.location.pathname !== '/login') {
      const currentUrl = encodeURIComponent(window.location.pathname + window.location.search)
      window.location.href = `/login?redirect=${currentUrl}`
    }
  }

  // ==================== 认证相关 API ====================
  async login(username: string, password: string): Promise<ApiResponse<LoginResponse>> {
    const response = await this.api.post('/auth/login', { username, password })
    // 使用 cookies 认证，不需要手动设置 token
    return response.data
  }

  async register(username: string, password: string, email: string): Promise<ApiResponse> {
    const response = await this.api.post('/auth/register', { username, password, email })
    return response.data
  }

  async logout(): Promise<ApiResponse> {
    const response = await this.api.post('/auth/logout')
    return response.data
  }

  async getCurrentUser(): Promise<ApiResponse<UserProfile>> {
    const response = await this.api.get('/users/me')
    return response.data
  }

  async updateUserSettings(settings: UserSettingsUpdate): Promise<ApiResponse> {
    const response = await this.api.put('/users/me', settings)
    return response.data
  }

  // ==================== 邮箱管理 API ====================
  async getMailboxes(page = 1, limit = 20, scope?: 'all'): Promise<ApiResponse<PaginatedResponse<Mailbox>>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())
    if (scope) {
      params.append('scope', scope)
    }

    const response = await this.api.get(`/mailboxes?${params}`)
    return response.data
  }

  async createMailboxApplication(application: MailboxApplicationRequest): Promise<ApiResponse<MailboxApplicationResponse>> {
    const response = await this.api.post('/mailboxes', application)
    return response.data
  }

  async getMailbox(id: number): Promise<ApiResponse<Mailbox>> {
    const response = await this.api.get(`/mailboxes/${id}`)
    return response.data
  }

  async deleteMailbox(id: number): Promise<ApiResponse> {
    const response = await this.api.delete(`/mailboxes/${id}`)
    return response.data
  }

  async toggleMailboxStatus(id: number, status: 'active' | 'disabled'): Promise<ApiResponse> {
    const response = await this.api.put(`/mailboxes/${id}/status`, { status })
    return response.data
  }

  async getMailboxApplications(page = 1, limit = 20): Promise<ApiResponse<PaginatedResponse<MailboxApplicationResponse>>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())

    const response = await this.api.get(`/mailboxes/applications?${params}`)
    return response.data
  }

  async processMailboxApplication(id: number, action: ApplicationProcessRequest): Promise<ApiResponse> {
    const response = await this.api.post(`/mailboxes/applications/${id}/process`, action)
    return response.data
  }

  // ==================== 邮件管理 API ====================
  async getEmails(page = 1, limit = 20, scope?: 'all', search?: string, status?: string): Promise<ApiResponse<PaginatedResponse<EmailSummary>>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())
    if (scope) params.append('scope', scope)
    if (search) params.append('search', search)
    if (status) params.append('status', status)

    const response = await this.api.get(`/emails?${params}`)
    return response.data
  }

  async getEmail(id: string): Promise<ApiResponse<EmailDetail>> {
    const response = await this.api.get(`/emails/${id}`)
    return response.data
  }

  async deleteEmail(id: string): Promise<ApiResponse> {
    const response = await this.api.delete(`/emails/${id}`)
    return response.data
  }

  async downloadAttachment(emailId: string, attachmentId: string): Promise<Blob> {
    const response = await this.api.get(`/emails/${emailId}/attachments/${attachmentId}`, {
      responseType: 'blob'
    })
    return response.data
  }

  async sendEmail(to: string, subject: string, content: string, from?: string, content_type: 'text' | 'html' | 'markdown' = 'markdown'): Promise<ApiResponse> {
    const response = await this.api.post('/emails/send', {
      to,
      from,
      subject,
      content,
      content_type
    })
    return response.data
  }

  // ==================== 转发规则 API ====================
  async getForwardRules(page = 1, limit = 20): Promise<ApiResponse<PaginatedResponse<ForwardRuleResponse>>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())

    const response = await this.api.get(`/forward-rules?${params}`)
    return response.data
  }

  async createForwardRule(rule: ForwardRuleCreateRequest): Promise<ApiResponse<ForwardRuleResponse>> {
    const response = await this.api.post('/forward-rules', rule)
    return response.data
  }

  async getForwardRule(id: number): Promise<ApiResponse<ForwardRuleResponse>> {
    const response = await this.api.get(`/forward-rules/${id}`)
    return response.data
  }

  async updateForwardRule(id: number, rule: ForwardRuleUpdateRequest): Promise<ApiResponse> {
    const response = await this.api.put(`/forward-rules/${id}`, rule)
    return response.data
  }

  async deleteForwardRule(id: number): Promise<ApiResponse> {
    const response = await this.api.delete(`/forward-rules/${id}`)
    return response.data
  }

  // ==================== 系统配置 API ====================
  async getSystemConfig(): Promise<ApiResponse<{ config: SystemConfig }>> {
    const response = await this.api.get('/system/config')
    return response.data
  }

  async getRegistrationStatus(): Promise<ApiResponse<{ allow_registration: boolean }>> {
    const response = await this.api.get('/system/registration-status')
    return response.data
  }

  async updateSystemConfig(config: SystemConfigUpdate): Promise<ApiResponse> {
    const response = await this.api.put('/system/config', config)
    return response.data
  }

  async getSystemHealth(): Promise<ApiResponse<{ status: string; timestamp: string }>> {
    const response = await this.api.get('/system/health')
    return response.data
  }

  // ==================== 管理员 API ====================
  async getUsers(page = 1, limit = 20, query = ''): Promise<ApiResponse<PaginatedResponse<UserProfile>>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())
    if (query) params.append('query', query)

    const response = await this.api.get(`/users?${params}`)
    return response.data
  }

  async createUser(username: string, password: string, user_type: 'admin' | 'user' = 'user'): Promise<ApiResponse<UserProfile>> {
    const response = await this.api.post('/users', { username, password, user_type })
    return response.data
  }

  async getUser(id: number): Promise<ApiResponse<UserProfile>> {
    const response = await this.api.get(`/users/${id}`)
    return response.data
  }

  async deleteUser(id: number): Promise<ApiResponse> {
    const response = await this.api.delete(`/users/${id}`)
    return response.data
  }

  async toggleUserStatus(id: number, status: 'active' | 'disabled'): Promise<ApiResponse> {
    const response = await this.api.put(`/users/${id}/status`, { status })
    return response.data
  }

  // 管理员邮箱管理
  async createMailboxForUser(mailboxData: AdminMailboxCreateRequest): Promise<ApiResponse<Mailbox>> {
    const response = await this.api.post('/mailboxes', mailboxData)
    return response.data
  }
}

// 导出单例实例
export const apiService = new ApiService()
export default apiService
