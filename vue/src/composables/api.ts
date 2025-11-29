import axios from 'axios'

// 创建 axios 实例
const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
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


  // 获取用户的转发规则
  async getForwardRules(page = 1, limit = 20): Promise<ApiResponse<any>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())

    const response = await api.get(`/forward-rules?${params}`)
    return response.data
  },

  // 创建转发规则
  async createForwardRule(ruleData: any): Promise<ApiResponse<any>> {
    const response = await api.post('/forward-rules', ruleData)
    return response.data
  },

  // 更新转发规则
  async updateForwardRule(id: number, ruleData: any): Promise<ApiResponse<any>> {
    const response = await api.put(`/forward-rules/${id}`, ruleData)
    return response.data
  },

  // 删除转发规则
  async deleteForwardRule(id: number): Promise<ApiResponse<any>> {
    const response = await api.delete(`/forward-rules/${id}`)
    return response.data
  },

  // ===== 管理员功能 =====

  // 获取用户列表（仅管理员）
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

  // 创建用户（仅管理员）
  async createUser(userData: {
    username: string
    password: string
    email: string
    user_type?: 'user' | 'admin'
  }): Promise<ApiResponse<any>> {
    const response = await api.post('/users', userData)
    return response.data
  },

  // 获取指定用户信息（仅管理员）
  async getUserById(id: number): Promise<ApiResponse<any>> {
    const response = await api.get(`/users/${id}`)
    return response.data
  },

  // 删除用户（仅管理员）
  async deleteUser(id: number): Promise<ApiResponse<any>> {
    const response = await api.delete(`/users/${id}`)
    return response.data
  },

  // 根据用户ID获取用户名
  async getUsernameById(userId: number): Promise<ApiResponse<any>> {
    const response = await api.get(`/user-info/username/${userId}`)
    return response.data
  },

  // 批量获取用户名
  async getUsernamesByIds(userIds: number[]): Promise<ApiResponse<any>> {
    const response = await api.post('/user-info/usernames', { user_ids: userIds })
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
  // 获取邮件列表 - 支持对象参数和位置参数
  async getEmails(
    pageOrParams: number | { page?: number; limit?: number; scope?: 'all'; search?: string; status?: string } = 1,
    limit = 20,
    scope?: 'all',
    search?: string,
    status?: string
  ): Promise<ApiResponse<any>> {
    let params: { page: number; limit: number; scope?: 'all'; search?: string; status?: string }

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
        scope,
        search,
        status
      }
    }

    const urlParams = new URLSearchParams()
    urlParams.append('page', params.page.toString())
    urlParams.append('limit', params.limit.toString())
    if (params.scope) urlParams.append('scope', params.scope)
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

// 转发规则 API
export const forwardRuleApiService = {
  async getForwardRules(
    pageOrParams: number | { page?: number; limit?: number; search?: string } = 1,
    limit = 20,
    search?: string
  ): Promise<ApiResponse<any>> {
    let params: { page: number; limit: number; search?: string }

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
        search
      }
    }

    const urlParams = new URLSearchParams()
    urlParams.append('page', params.page.toString())
    urlParams.append('limit', params.limit.toString())
    if (params.search) urlParams.append('search', params.search)

    const response = await api.get(`/forward-rules?${urlParams}`)
    return response.data
  },

  async createForwardRule(ruleData: any): Promise<ApiResponse<any>> {
    const response = await api.post('/forward-rules', ruleData)
    return response.data
  },

  async updateForwardRule(id: number, ruleData: any): Promise<ApiResponse<any>> {
    const response = await api.put(`/forward-rules/${id}`, ruleData)
    return response.data
  },

  async deleteForwardRule(id: number): Promise<ApiResponse<any>> {
    const response = await api.delete(`/forward-rules/${id}`)
    return response.data
  }
}

// 统一 API 服务导出
export const apiService = {
  ...systemApiService,
  ...userApiService,
  ...authApiService,
  ...emailApiService,
  ...forwardRuleApiService,
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
  getForwardRules: forwardRuleApiService.getForwardRules,
  createForwardRule: forwardRuleApiService.createForwardRule,
  updateForwardRule: forwardRuleApiService.updateForwardRule,
  deleteForwardRule: forwardRuleApiService.deleteForwardRule,
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
