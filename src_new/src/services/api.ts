/**
 * API 服务层
 */
import axios from 'axios'
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import type { 
  ApiResponse, 
  User, 
  Email, 
  EmailQueryParams,
  UserSettingsUpdate,
  LoginForm,
  RegisterForm,
  SystemConfig,
  ForwardRule,
  SimulateEmailForm
} from '@/types'

class ApiService {
  private instance: AxiosInstance
  private token: string | null = null

  constructor() {
    this.instance = axios.create({
      baseURL: '/api',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    })

    // 请求拦截器
    this.instance.interceptors.request.use(
      (config) => {
        if (this.token) {
          config.headers.Authorization = `Bearer ${this.token}`
        }
        return config
      },
      (error) => Promise.reject(error)
    )

    // 响应拦截器
    this.instance.interceptors.response.use(
      (response: AxiosResponse<ApiResponse>) => response,
      (error) => {
        if (error.response?.status === 401) {
          this.clearToken()
          // 可以触发登录页面跳转
          window.location.href = '/login'
        }
        return Promise.reject(error)
      }
    )
  }

  // 设置认证令牌
  setToken(token: string | null): void {
    this.token = token
    if (token) {
      localStorage.setItem('cem_persist_auth_token', token)
    } else {
      localStorage.removeItem('cem_persist_auth_token')
      localStorage.removeItem('auth_token') // 清理旧的键
    }
  }

  // 清除令牌
  clearToken(): void {
    this.setToken(null)
  }

  // 从存储中恢复令牌
  restoreToken(): void {
    const token = localStorage.getItem('cem_persist_auth_token') || 
                  localStorage.getItem('auth_token') // 兼容旧版本
    if (token) {
      this.token = token
    }
  }

  // 通用请求方法
  private async request<T = any>(config: AxiosRequestConfig): Promise<ApiResponse<T>> {
    try {
      const response = await this.instance.request<ApiResponse<T>>(config)
      return response.data
    } catch (error: any) {
      if (error.response?.data) {
        throw new Error(error.response.data.error || error.response.data.message || '请求失败')
      }
      throw new Error(error.message || '网络错误')
    }
  }

  // GET 请求
  async get<T = any>(url: string, params?: any): Promise<ApiResponse<T>> {
    return this.request<T>({ method: 'GET', url, params })
  }

  // POST 请求
  async post<T = any>(url: string, data?: any): Promise<ApiResponse<T>> {
    return this.request<T>({ method: 'POST', url, data })
  }

  // PUT 请求
  async put<T = any>(url: string, data?: any): Promise<ApiResponse<T>> {
    return this.request<T>({ method: 'PUT', url, data })
  }

  // DELETE 请求
  async delete<T = any>(url: string): Promise<ApiResponse<T>> {
    return this.request<T>({ method: 'DELETE', url })
  }

  // 认证相关 API
  async login(credentials: LoginForm): Promise<ApiResponse<{ token: string; user: User }>> {
    return this.post('/login', credentials)
  }

  async register(data: RegisterForm): Promise<ApiResponse<{ email_prefix: string }>> {
    return this.post('/register', data)
  }

  async logout(): Promise<ApiResponse> {
    return this.post('/logout')
  }

  async getCurrentUser(): Promise<ApiResponse<User>> {
    return this.get('/protected/me')
  }

  // 系统配置 API
  async getSystemConfig(): Promise<ApiResponse<{ config: SystemConfig }>> {
    return this.get('/system/config')
  }

  // 邮件相关 API
  async getEmails(params?: EmailQueryParams): Promise<ApiResponse<{
    emails: Email[]
    total: number
    page: number
    limit: number
  }>> {
    return this.get('/protected/emails', params)
  }

  async getEmail(id: number): Promise<ApiResponse<Email>> {
    return this.get(`/protected/emails/${id}`)
  }

  async deleteEmail(id: number): Promise<ApiResponse> {
    return this.delete(`/protected/emails/${id}`)
  }

  // 附件相关 API
  async downloadAttachment(id: number): Promise<Blob> {
    const response = await this.instance.get(`/protected/attachments/${id}/download`, {
      responseType: 'blob',
    })
    return response.data
  }

  // 用户设置 API
  async getUserSettings(): Promise<ApiResponse<UserSettingsUpdate>> {
    return this.get('/protected/settings')
  }

  async updateUserSettings(settings: UserSettingsUpdate): Promise<ApiResponse> {
    return this.put('/protected/settings', settings)
  }

  // 管理员 API
  async getUsers(): Promise<ApiResponse<{ users: User[] }>> {
    return this.get('/admin/users')
  }

  async deleteUser(id: number): Promise<ApiResponse> {
    return this.delete(`/admin/users/${id}`)
  }

  async sendUserInfo(id: number): Promise<ApiResponse> {
    return this.post(`/admin/users/${id}/send-info`)
  }

  async getForwardRules(): Promise<ApiResponse<{ rules: ForwardRule[] }>> {
    return this.get('/admin/forward-rules')
  }

  async deleteForwardRule(id: number): Promise<ApiResponse> {
    return this.delete(`/admin/forward-rules/${id}`)
  }

  async getAllEmails(): Promise<ApiResponse<{ emails: Email[] }>> {
    return this.get('/admin/emails')
  }

  async getAdminSettings(): Promise<ApiResponse<{ config: SystemConfig }>> {
    return this.get('/admin/settings')
  }

  async updateAdminSettings(config: Partial<SystemConfig>): Promise<ApiResponse> {
    return this.put('/admin/settings', config)
  }

  // 调试 API
  async simulateEmail(data: SimulateEmailForm): Promise<ApiResponse> {
    return this.post('/debug/simulate-email', data)
  }

  async getDebugInfo(): Promise<ApiResponse> {
    return this.get('/debug')
  }
}

// 创建单例实例
export const apiService = new ApiService()
export default apiService