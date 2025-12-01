import axios from 'axios'

// 创建 axios 实例
const api = axios.create({
  baseURL: '/api',
  timeout: 60000, // 增加到 60 秒，因为邮件详情可能需要解析大文件
  headers: {
    'Content-Type': 'application/json'
  },
  withCredentials: true // 支持 cookie 认证
})

// 请求拦截器
api.interceptors.request.use(
  (config) => {
    // 后端通过 HttpOnly cookies 自动解析用户信息，无需手动添加 headers
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// 响应拦截器
api.interceptors.response.use(
  (response) => {
    return response
  },
  (error) => {
    if (error.response?.status === 401) {
      // 未授权，清理用户信息并重定向到登录页
      localStorage.clear()
      // 重定向到登录页
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// API 响应类型
export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  message?: string
  code?: number
}

// 系统相关 API
export const systemApiService = {
  // 获取系统健康状态
  async getSystemHealth(): Promise<ApiResponse<any>> {
    const response = await api.get('/system/health')
    return response.data
  },

  // 获取注册状态
  async getRegistrationStatus(): Promise<ApiResponse<any>> {
    const response = await api.get('/system/registration-status')
    return response.data
  },

  // 获取系统配置
  async getSystemConfig(): Promise<ApiResponse<any>> {
    const response = await api.get('/system/config')
    return response.data
  },

  // 更新系统配置
  async updateSystemConfig(config: any): Promise<ApiResponse<any>> {
    const response = await api.put('/system/config', config)
    return response.data
  },

}

// 用户相关 API
export const userApiService = {
  // 获取用户信息
  async getUserProfile(): Promise<ApiResponse<any>> {
    const response = await api.get('/users/me')
    return response.data
  },

  // 更新用户设置
  async updateUserSettings(settings: any): Promise<ApiResponse<any>> {
    const response = await api.put('/users/me', settings)
    return response.data
  },

  async getUserList(page = 1, limit = 20, query?: string): Promise<ApiResponse<any>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())
    if (query) {
      params.append('query', query)
    }

    const response = await api.get(`/users?${params}`)
    return response.data
  },

  // 创建用户
  async createUser(userData: {
    username: string
    password: string
    email: string
  }): Promise<ApiResponse<any>> {
    const response = await api.post('/users', userData)
    return response.data
  },

  // 获取指定用户信息
  async getUserById(id: number): Promise<ApiResponse<any>> {
    const response = await api.get(`/users/${id}`)
    return response.data
  },

  // 删除用户（仅管理员）
  async deleteUser(id: number): Promise<ApiResponse<any>> {
    const response = await api.delete(`/users/${id}`)
    return response.data
  }
}

// 认证相关 API
export const authApiService = {
  // 用户登录
  async login(credentials: { username: string; password: string }): Promise<ApiResponse<any>> {
    const response = await api.post('/auth/login', credentials)
    return response.data
  },

  // 用户登出
  async logout(): Promise<ApiResponse<any>> {
    const response = await api.post('/auth/logout')
    return response.data
  }
}

// 邮件相关 API
export const emailApiService = {
  /**
   * 获取邮件列表
   * 
   * 单用户模式：系统中只有一个管理员用户，所有邮件都关联到该管理员。
   * scope 参数已废弃，不再使用。
   * 
   * @param pageOrParams 页码或参数对象
   * @param limit 每页数量（当 pageOrParams 为数字时使用）
   * @param search 搜索关键词（已废弃，使用对象参数）
   * @param status 邮件状态（已废弃，使用对象参数）
   */
  async getEmails(
    pageOrParams: number | { page?: number; limit?: number; search?: string; status?: string } = 1,
    limit = 20,
    search?: string,
    status?: string
  ): Promise<ApiResponse<any>> {
    let params: { page: number; limit: number; search?: string; status?: string }

    if (typeof pageOrParams === 'object') {
      // 对象参数
      params = {
        page: pageOrParams.page || 1,
        limit: pageOrParams.limit || 20,
        ...pageOrParams
      }
    } else {
      // 位置参数
      params = {
        page: pageOrParams,
        limit,
        search,
        status
      }
    }

    const urlParams = new URLSearchParams()
    urlParams.append('page', params.page.toString())
    urlParams.append('limit', params.limit.toString())
    // 注意：scope 参数已移除，单用户模式下不再需要
    if (params.search) urlParams.append('search', params.search)
    if (params.status) urlParams.append('status', params.status)

    const response = await api.get(`/emails?${urlParams}`)
    return response.data
  },

  // 获取邮件详情
  async getEmail(id: string): Promise<ApiResponse<any>> {
    const response = await api.get(`/emails/${id}`)
    return response.data
  },

  // 删除邮件
  async deleteEmail(id: string): Promise<ApiResponse<any>> {
    const response = await api.delete(`/emails/${id}`)
    return response.data
  },

  // 批量删除邮件
  async batchDeleteEmails(emailIds: string[]): Promise<ApiResponse<any>> {
    const response = await api.delete('/emails/batch', { data: { emailIds } })
    return response.data
  },

  // 更新邮件已读状态
  async updateEmailReadStatus(id: string, isRead: boolean): Promise<ApiResponse<any>> {
    const response = await api.patch(`/emails/${id}/read-status`, { is_read: isRead })
    return response.data
  },

  // 批量更新邮件已读状态
  async batchUpdateEmailReadStatus(emailIds: string[], isRead: boolean): Promise<ApiResponse<any>> {
    const response = await api.patch('/emails/batch/read-status', { emailIds, is_read: isRead })
    return response.data
  },

  // 发送邮件 - 支持两种调用方式
  async sendEmail(
    toOrData: string | { to: string; from?: string; subject: string; content: string; content_type?: string },
    subject?: string,
    content?: string,
    from?: string,
    content_type: 'text' | 'html' | 'markdown' = 'markdown'
  ): Promise<ApiResponse<any>> {
    let emailData: { to: string; from?: string; subject: string; content: string; content_type?: string }

    if (typeof toOrData === 'string') {
      // 位置参数调用方式 (to, subject, content, from?, content_type?)
      emailData = {
        to: toOrData,
        subject: subject!,
        content: content!,
        from,
        content_type
      }
    } else {
      // 对象参数调用方式
      emailData = toOrData
    }

    const response = await api.post('/emails/send', emailData)
    return response.data
  }
}

// 管理员相关 API（管理员专用功能）
// 注意：单用户模式下，这些 API 实际上与普通 API 相同，因为系统中只有一个管理员用户
export const adminApiService = {
  /**
   * 获取邮件列表（管理员视图）
   * 
   * 单用户模式：系统中只有一个管理员用户，所有邮件都关联到该管理员。
   * scope 参数已废弃，不再使用。
   */
  async getEmails(
    pageOrParams: number | { page?: number; limit?: number; search?: string; status?: string } = 1,
    limit = 20,
    search?: string,
    status?: string
  ): Promise<ApiResponse<any>> {
    let params: { page: number; limit: number; search?: string; status?: string }

    if (typeof pageOrParams === 'object') {
      params = {
        page: pageOrParams.page || 1,
        limit: pageOrParams.limit || 20,
        ...pageOrParams
      }
    } else {
      params = {
        page: pageOrParams,
        limit,
        search,
        status
      }
    }

    const urlParams = new URLSearchParams()
    urlParams.append('page', params.page.toString())
    urlParams.append('limit', params.limit.toString())
    // 注意：scope 参数已移除，单用户模式下不再需要
    if (params.search) urlParams.append('search', params.search)
    if (params.status) urlParams.append('status', params.status)

    const response = await api.get(`/emails?${urlParams}`)
    return response.data
  },

  // 获取所有用户列表（仅管理员）
  async getAllUsers(page = 1, limit = 20, query?: string): Promise<ApiResponse<any>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())
    if (query) {
      params.append('query', query)
    }

    const response = await api.get(`/users?${params}`)
    return response.data
  }
}

// 统一 API 服务导出
export const apiService = {
  ...systemApiService,
  ...userApiService,
  ...authApiService,
  ...emailApiService,
  getUserProfile: userApiService.getUserProfile,
  updateUserSettings: userApiService.updateUserSettings,
  getSystemHealth: systemApiService.getSystemHealth,
  getRegistrationStatus: systemApiService.getRegistrationStatus,
  getSystemConfig: systemApiService.getSystemConfig,
  updateSystemConfig: systemApiService.updateSystemConfig,
  login: authApiService.login,
  logout: authApiService.logout,
  getEmails: emailApiService.getEmails,
  getEmail: emailApiService.getEmail,
  deleteEmail: emailApiService.deleteEmail,
  sendEmail: emailApiService.sendEmail,
  // 数据库管理方法
  getDatabaseInfo: async (): Promise<ApiResponse<any>> => {
    const response = await api.get('/database/info')
    return response.data
  },
  getAllTablesData: async (): Promise<ApiResponse<any>> => {
    const response = await api.get('/database/tables')
    return response.data
  },
  initializeDatabase: async (confirmText: string): Promise<ApiResponse<any>> => {
    const response = await api.post('/database/init', { confirmText })
    return response.data
  },
  getDatabaseStats: async (): Promise<ApiResponse<any>> => {
    const response = await api.get('/database/stats')
    return response.data
  }
}

// 默认导出 axios 实例
export default api
