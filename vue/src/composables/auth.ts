import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useStorage } from '@vueuse/core'
import axios, { type AxiosResponse } from 'axios'
import type {
  UserProfile,
  LoginResponse,
  RegisterResponse,
  ApiResponse
} from '@/types'

// ==================== 类型定义 ====================

// API 响应基础接口

// ==================== API 实例 ====================

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
  (config: any) => {
    // 使用 cookies 认证，不需要手动添加 Authorization header
    return config
  },
  (error: any) => {
    return Promise.reject(error)
  }
)

// 响应拦截器
api.interceptors.response.use(
  (response: AxiosResponse<ApiResponse>) => {
    return response
  },
  (error: any) => {
    if (error.response?.status === 401) {
      // 未授权，清理所有认证数据并重定向到登录页
      clearAllAuthDataAndRedirect()
    }
    return Promise.reject(error)
  }
)

// ==================== 工具函数 ====================

// 清理所有认证数据并重定向到登录页
const clearAllAuthDataAndRedirect = () => {
  // 清理 localStorage 中的认证信息
  localStorage.removeItem('user_info')
  localStorage.removeItem('auth_token')
  localStorage.removeItem('cem_persist_auth_token')

  // 清理 localStorage 中的CEM相关缓存
  const cemKeys = Object.keys(localStorage).filter(key =>
    key.startsWith('cem_cache_') ||
    key.startsWith('cem_')
  )
  cemKeys.forEach(key => {
    localStorage.removeItem(key)
  })

  // 不再使用sessionStorage，统一使用localStorage

  // 清理 cookies
  document.cookie = 'session_cookies=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'

  // 如果当前不在登录页，重定向到登录页
  if (window.location.pathname !== '/login') {
    // 对于根路径，直接跳转到登录页（避免 redirect=%2F）
    if (window.location.pathname === '/') {
      window.location.href = '/login'
    } else {
      // 其他路径，携带重定向参数
      const currentUrl = encodeURIComponent(window.location.pathname + window.location.search)
      window.location.href = `/login?redirect=${currentUrl}`
    }
  }
}

// ==================== API 服务 ====================

// 认证相关 API
export const authApiService = {
  // 登录
  async login(username: string, password: string): Promise<LoginResponse> {
    const response = await api.post('/auth/login', { username, password })
    return response.data
  },

  // 注册
  async register(username: string, email: string, password: string): Promise<RegisterResponse> {
    const response = await api.post('/auth/register', { username, email, password })
    return response.data
  },

  // 获取当前用户信息
  async getCurrentUser(): Promise<ApiResponse<UserProfile>> {
    const response = await api.get('/users/me')
    return response.data
  },

  // 登出
  async logout(): Promise<void> {
    try {
      await api.post('/auth/logout')
    } catch (error) {
      console.error('登出请求失败:', error)
    } finally {
      // 无论后端登出是否成功，都清理本地状态
      clearAllAuthDataAndRedirect()
    }
  }
}

// ==================== 认证状态管理 ====================

export const useAuthStore = defineStore('auth', () => {
  // 状态
  const user = ref<UserProfile | null>(null)
  const loading = ref(false)

  // 使用 VueUse 的 useStorage 进行持久化存储
  const userStorage = useStorage('user_info', null as UserProfile | null, localStorage, {
    serializer: {
      read: (value: string) => {
        try {
          return value ? JSON.parse(value) : null
        } catch {
          return null
        }
      },
      write: (value: UserProfile | null) => {
        return value ? JSON.stringify(value) : ''
      }
    }
  })

  // 计算属性
  const isAuthenticated = computed(() => !!user.value)
  const isAdmin = computed(() => user.value?.user_type === 'admin')

  // 获取当前用户信息
  const fetchCurrentUser = async () => {
    loading.value = true
    try {
      const response = await authApiService.getCurrentUser()
      if (response.success && response.data) {
        user.value = response.data
        userStorage.value = response.data
        return { success: true }
      } else {
        // 用户可能未登录
        user.value = null
        userStorage.value = null
        return { success: false, error: response.message || '获取用户信息失败' }
      }
    } catch (error: any) {
      user.value = null
      userStorage.value = null
      return {
        success: false,
        error: error.response?.data?.message || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 登出
  const logout = async () => {
    loading.value = true
    try {
      await authApiService.logout()
    } catch (error) {
      console.error('登出失败:', error)
    } finally {
      // 无论后端登出是否成功，都清理本地状态
      user.value = null
      userStorage.value = null
      loading.value = false
    }
  }

  // 初始化认证状态
  const initAuth = async () => {
    // 首先尝试从存储恢复用户信息
    if (userStorage.value) {
      user.value = userStorage.value
    }

    // 然后尝试从服务器获取最新用户信息
    await fetchCurrentUser()
  }

  // 登录
  const login = async (username: string, password: string) => {
    loading.value = true
    try {
      const response = await authApiService.login(username, password)
      if (response.success && response.data) {
        // 登录成功后获取用户信息
        const userResult = await fetchCurrentUser()
        if (userResult.success) {
          return { success: true }
        } else {
          return { success: false, error: '获取用户信息失败' }
        }
      } else {
        return { success: false, error: response.message || '登录失败' }
      }
    } catch (error: any) {
      // 处理 HTTP 错误响应
      if (error.response?.status === 401) {
        return {
          success: false,
          error: error.response?.data?.message || '用户名或密码错误'
        }
      } else if (error.response?.status === 400) {
        return {
          success: false,
          error: error.response?.data?.message || '用户名和密码不能为空'
        }
      } else {
        return {
          success: false,
          error: error.response?.data?.message || '网络连接错误，请检查网络后重试'
        }
      }
    } finally {
      loading.value = false
    }
  }

  // 注册
  const register = async (username: string, email: string, password: string) => {
    loading.value = true
    try {
      const response = await authApiService.register(username, email, password)
      if (response.success) {
        return { success: true, message: response.message || '注册成功' }
      } else {
        return { success: false, error: response.message || '注册失败' }
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.message || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  return {
    // 状态
    user,
    loading,

    // 计算属性
    isAuthenticated,
    isAdmin,

    // 方法
    login,
    register,
    logout,
    fetchCurrentUser,
    initAuth
  }
})

// 导出认证核心功能（供其他文件直接使用）
// 注意：这些需要在 Pinia 初始化后才能使用
export const useAuthCore = () => {
  const store = useAuthStore()
  return {
    user: store.user,
    loading: store.loading,
    isAuthenticated: store.isAuthenticated,
    isAdmin: store.isAdmin,
    fetchCurrentUser: store.fetchCurrentUser,
    logout: store.logout,
    initAuth: store.initAuth
  }
}