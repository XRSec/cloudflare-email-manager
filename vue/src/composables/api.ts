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
    // 使用 cookies 认证，不需要手动添加 Authorization header
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
      // 未授权，清理所有认证数据并重定向到登录页
      localStorage.removeItem('user_info')
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

  // 清除系统缓存
  async clearSystemCache(): Promise<ApiResponse<any>> {
    const response = await api.post('/system/clear-cache')
    return response.data
  }
}

// 用户相关 API
export const userApiService = {
  // 获取用户信息
  async getUserProfile(): Promise<ApiResponse<any>> {
    const response = await api.get('/user/profile')
    return response.data
  },

  // 更新用户设置
  async updateUserSettings(settings: any): Promise<ApiResponse<any>> {
    const response = await api.put('/user/settings', settings)
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
  },

  // 用户注册
  async register(userData: { username: string; password: string; email: string }): Promise<ApiResponse<any>> {
    const response = await api.post('/auth/register', userData)
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

// 邮箱相关 API
export const mailboxApiService = {
  // 获取邮箱列表 - 支持对象参数和位置参数
  async getMailboxes(
    pageOrParams: number | { page?: number; limit?: number; scope?: 'all' } = 1,
    limit = 20,
    scope?: 'all'
  ): Promise<ApiResponse<any>> {
    let params: { page: number; limit: number; scope?: 'all' }

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
        scope
      }
    }

    const urlParams = new URLSearchParams()
    urlParams.append('page', params.page.toString())
    urlParams.append('limit', params.limit.toString())
    if (params.scope) urlParams.append('scope', params.scope)

    const response = await api.get(`/mailboxes?${urlParams}`)
    return response.data
  },

  // 获取邮箱详情
  async getMailbox(id: number): Promise<ApiResponse<any>> {
    const response = await api.get(`/mailboxes/${id}`)
    return response.data
  },

  // 创建邮箱
  async createMailbox(mailboxData: any): Promise<ApiResponse<any>> {
    const response = await api.post('/mailboxes', mailboxData)
    return response.data
  },

  // 删除邮箱
  async deleteMailbox(id: number): Promise<ApiResponse<any>> {
    const response = await api.delete(`/mailboxes/${id}`)
    return response.data
  },

  // 获取邮箱申请列表
  async getMailboxApplications(page = 1, limit = 20): Promise<ApiResponse<any>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())

    const response = await api.get(`/mailbox-applications?${params}`)
    return response.data
  },

  // 处理邮箱申请
  async processMailboxApplication(id: number, action: 'approve' | 'reject', reason?: string): Promise<ApiResponse<any>> {
    const response = await api.post(`/mailbox-applications/${id}/process`, { action, reason })
    return response.data
  },

  // 切换邮箱状态
  async toggleMailboxStatus(id: number, status: string): Promise<ApiResponse<any>> {
    const response = await api.put(`/mailboxes/${id}/status`, { status })
    return response.data
  },

  // 获取邮箱历史记录
  async getMailboxHistory(mailboxId: number): Promise<ApiResponse<any>> {
    const response = await api.get(`/mailbox-history/${mailboxId}`)
    return response.data
  }
}

// 管理员相关 API
export const adminApiService = {
  // 获取所有邮件（管理员）- 支持对象参数和位置参数
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

  // 获取所有用户列表 - 支持对象参数和位置参数
  async getAllUsers(
    pageOrParams: number | { page?: number; limit?: number; search?: string } = 1,
    limit = 20,
    search?: string
  ): Promise<ApiResponse<any>> {
    let params: { page: number; limit: number; search?: string }

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
        search
      }
    }

    const urlParams = new URLSearchParams()
    urlParams.append('page', params.page.toString())
    urlParams.append('limit', params.limit.toString())
    if (params.search) urlParams.append('search', params.search)

    const response = await api.get(`/admin/users?${urlParams}`)
    return response.data
  },

  // 获取用户详情
  async getUser(id: number): Promise<ApiResponse<any>> {
    const response = await api.get(`/admin/users/${id}`)
    return response.data
  },

  // 更新用户信息
  async updateUser(id: number, userData: any): Promise<ApiResponse<any>> {
    const response = await api.put(`/admin/users/${id}`, userData)
    return response.data
  },

  // 删除用户
  async deleteUser(id: number): Promise<ApiResponse<any>> {
    const response = await api.delete(`/admin/users/${id}`)
    return response.data
  },

  // 获取所有邮箱（管理员）- 支持对象参数和位置参数
  async getAllMailboxes(
    pageOrParams: number | { page?: number; limit?: number; search?: string } = 1,
    limit = 20,
    search?: string
  ): Promise<ApiResponse<any>> {
    let params: { page: number; limit: number; search?: string }

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
        search
      }
    }

    const urlParams = new URLSearchParams()
    urlParams.append('page', params.page.toString())
    urlParams.append('limit', params.limit.toString())
    if (params.search) urlParams.append('search', params.search)

    const response = await api.get(`/mailboxes?${urlParams}&scope=all`)
    return response.data
  },

  // 获取安全审计统计
  async getSecurityStats(days = 7): Promise<ApiResponse<any>> {
    const response = await api.get(`/security-audit/attack-stats?days=${days}`)
    return response.data
  },

  // 获取转发规则 - 支持对象参数和位置参数
  async getForwardRules(
    pageOrParams: number | { page?: number; limit?: number; scope?: 'all'; search?: string } = 1,
    limit = 20,
    scope?: 'all',
    search?: string
  ): Promise<ApiResponse<any>> {
    let params: { page: number; limit: number; scope?: 'all'; search?: string }

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
        search
      }
    }

    const urlParams = new URLSearchParams()
    urlParams.append('page', params.page.toString())
    urlParams.append('limit', params.limit.toString())
    if (params.scope) urlParams.append('scope', params.scope)
    if (params.search) urlParams.append('search', params.search)

    const response = await api.get(`/forward-rules?${urlParams}`)
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
  }
}

// 统一 API 服务导出
export const apiService = {
  ...systemApiService,
  ...userApiService,
  ...authApiService,
  ...emailApiService,
  ...mailboxApiService,
  ...adminApiService,
  // 添加别名方法
  getUserProfile: userApiService.getUserProfile,
  updateUserSettings: userApiService.updateUserSettings,
  getSystemHealth: systemApiService.getSystemHealth,
  getRegistrationStatus: systemApiService.getRegistrationStatus,
  getSystemConfig: systemApiService.getSystemConfig,
  updateSystemConfig: systemApiService.updateSystemConfig,
  clearSystemCache: systemApiService.clearSystemCache,
  login: authApiService.login,
  logout: authApiService.logout,
  register: authApiService.register,
  getEmails: emailApiService.getEmails,
  getEmail: emailApiService.getEmail,
  deleteEmail: emailApiService.deleteEmail,
  sendEmail: emailApiService.sendEmail,
  getMailboxes: mailboxApiService.getMailboxes,
  getMailbox: mailboxApiService.getMailbox,
  createMailbox: mailboxApiService.createMailbox,
  deleteMailbox: mailboxApiService.deleteMailbox,
  getMailboxApplications: mailboxApiService.getMailboxApplications,
  processMailboxApplication: mailboxApiService.processMailboxApplication,
  toggleMailboxStatus: mailboxApiService.toggleMailboxStatus,
  getMailboxHistory: mailboxApiService.getMailboxHistory,
  // 管理员方法
  getAllUsers: adminApiService.getAllUsers,
  getUser: adminApiService.getUser,
  updateUser: adminApiService.updateUser,
  deleteUser: adminApiService.deleteUser,
  getAllMailboxes: adminApiService.getAllMailboxes,
  getSecurityStats: adminApiService.getSecurityStats,
  getForwardRules: adminApiService.getForwardRules,
  createForwardRule: adminApiService.createForwardRule,
  updateForwardRule: adminApiService.updateForwardRule,
  deleteForwardRule: adminApiService.deleteForwardRule,
  // 管理员邮件方法
  getAdminEmails: adminApiService.getEmails
}

// 默认导出 axios 实例
export default api
