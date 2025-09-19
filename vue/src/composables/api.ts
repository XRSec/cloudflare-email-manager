import axios from 'axios'
import type { SystemHealth, ApiResponse, UserProfile, UserSettingsUpdate } from '@/types'

// ==================== API 实例 ====================

// 创建 API 实例
const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  },
  withCredentials: true
})

// ==================== API 服务 ====================

// 系统相关 API
export const systemApiService = {
  // 获取系统健康状态
  async getSystemHealth(): Promise<SystemHealth> {
    const response = await api.get('/system/health')
    return response.data
  },

  // 获取注册状态
  async getRegistrationStatus(): Promise<ApiResponse<{ allow_registration: boolean }>> {
    const response = await api.get('/system/registration-status')
    return response.data
  }
}

// 用户相关 API
export const userApiService = {
  // 获取当前用户信息
  async getUserProfile(): Promise<ApiResponse<UserProfile>> {
    const response = await api.get('/users/me')
    return response.data
  },

  // 更新用户设置
  async updateUserSettings(settings: UserSettingsUpdate): Promise<ApiResponse<any>> {
    const response = await api.put('/users/me', settings)
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

// 统一 API 服务导出
export const apiService = {
  ...systemApiService,
  ...userApiService,
  ...authApiService
}

// 默认导出 axios 实例
export default api