import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useStorage } from '@vueuse/core'
import axios, { type AxiosResponse } from 'axios'
import type {
  UserProfile,
  LoginResponse,
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
      console.log('🧹 检测到401错误，清理认证数据并重定向...')

      // 清理所有本地数据
      localStorage.clear()
      document.cookie = 'session_cookies=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'

      // 重定向到登录页
      if (window.location.pathname !== '/login') {
        const redirectUrl = window.location.pathname === '/'
          ? '/login'
          : `/login?redirect=${encodeURIComponent(window.location.pathname + window.location.search)}`
        window.location.href = redirectUrl
      }
    }
    return Promise.reject(error)
  }
)

// ==================== API 服务 ====================

// 认证相关 API
export const authApiService = {
  // 登录
  async login(username: string, password: string): Promise<LoginResponse> {
    const response = await api.post('/auth/login', { username, password })
    return response.data
  },

  // 注册（已废弃，系统不支持注册）
  // async register(username: string, email: string, password: string): Promise<any> {
  //   const response = await api.post('/auth/register', { username, email, password })
  //   return response.data
  // },

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
      console.log('🧹 用户登出，清理认证数据并重定向...')

      // 清理所有本地数据
      localStorage.clear()
      document.cookie = 'session_cookies=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'

      // 重定向到登录页
      if (window.location.pathname !== '/login') {
        const redirectUrl = window.location.pathname === '/'
          ? '/login'
          : `/login?redirect=${encodeURIComponent(window.location.pathname + window.location.search)}`
        window.location.href = redirectUrl
      }
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
  const isAdmin = computed(() => user.value?.user_type === 1)

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
        // 登录成功，直接使用返回的用户信息
        console.log('✅ 登录成功，设置用户信息:', response.data.user)
        user.value = response.data.user // TODO 有意义吗？
        userStorage.value = response.data.user
        console.log('🔐 当前认证状态:', !!user.value)

        return { success: true }
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

  return {
    // 状态
    user,
    loading,

    // 计算属性
    isAuthenticated,
    isAdmin,

    // 方法
    login,
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