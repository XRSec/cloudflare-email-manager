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
  email: string
  role: 'admin' | 'user'
  created_at: string
  updated_at: string
  settings: UserSettings
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
  created_at: string
  status: 'active' | 'disabled' | 'pending'
}

export interface MailboxApplicationRequest {
  reason?: string
}

export interface MailboxApplicationResponse {
  application_id: number
  status: 'pending' | 'approved' | 'rejected'
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
  allow_user_send: boolean
  max_mailboxes_per_user: number
  storage_provider: 'r2' | 's3' | 'local'
}

export interface SystemConfigUpdate {
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
  token: string
  message: string
}

// 管理员创建用户请求
export interface AdminUserCreateRequest {
  username: string
  password: string
  email: string
  role?: 'user' | 'admin'
}

// 申请处理请求
export interface ApplicationProcessRequest {
  action: 'approve' | 'reject'
}

class ApiService {
  private api: AxiosInstance
  private token: string | null = null

  constructor() {
    this.api = axios.create({
      baseURL: '/api',
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json'
      },
      withCredentials: true // 支持 cookie 认证
    })

    // 请求拦截器
    this.api.interceptors.request.use(
      (config) => {
        if (this.token) {
          config.headers.Authorization = `Bearer ${this.token}`
        }
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
          // Token 过期，清除本地存储
          this.clearToken()
          window.location.href = '/login'
        }
        return Promise.reject(error)
      }
    )

    // 从本地存储恢复 token
    this.token = localStorage.getItem('token')
  }

  // 设置认证 token
  setToken(token: string) {
    this.token = token
    localStorage.setItem('token', token)
  }

  // 清除认证 token
  clearToken() {
    this.token = null
    localStorage.removeItem('token')
  }

  // 获取当前 token
  getToken() {
    return this.token
  }

  // ==================== 认证相关 API ====================
  async login(username: string, password: string): Promise<ApiResponse<LoginResponse>> {
    const response = await this.api.post('/auth/login', { username, password })
    if (response.data.success && response.data.data?.token) {
      this.setToken(response.data.data.token)
    }
    return response.data
  }

  async register(username: string, password: string, email: string): Promise<ApiResponse> {
    const response = await this.api.post('/auth/register', { username, password, email })
    return response.data
  }

  async logout(): Promise<ApiResponse> {
    const response = await this.api.post('/auth/logout')
    this.clearToken()
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
  async getMailboxes(page = 1, limit = 20): Promise<ApiResponse<PaginatedResponse<Mailbox>>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())

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
  async getSystemConfig(): Promise<ApiResponse<SystemConfig>> {
    const response = await this.api.get('/system/config')
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

  async createUser(userData: AdminUserCreateRequest): Promise<ApiResponse<UserProfile>> {
    const response = await this.api.post('/users', userData)
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

  // 管理员邮箱管理
  async createMailboxForUser(mailboxData: AdminMailboxCreateRequest): Promise<ApiResponse<Mailbox>> {
    const response = await this.api.post('/mailboxes', mailboxData)
    return response.data
  }
}

// 导出单例实例
export const apiService = new ApiService()
export default apiService
