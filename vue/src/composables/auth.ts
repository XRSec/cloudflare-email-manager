import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useStorage } from '@vueuse/core'
import type {
  UserProfile,
  LoginResponse
} from '@/types'
import { authApiService } from './api-auth'

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
  // 单管理员模式：所有用户都是管理员，不再需要 isAdmin 判断

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
      // 检查是否是初始化认证检查（用于判断登录状态）
      // 在登录页或根路径时，401 是正常的检查结果，不应该清理数据
      const isInitialAuthCheck = window.location.pathname === '/login' || window.location.pathname === '/'

      if (isInitialAuthCheck && error.response?.status === 401) {
        // 初始化认证检查时的 401 是正常的，用于判断用户是否已登录
        // 不清理数据，保持原样，让 App.vue 的认证流程处理
        // 不清理 user.value 和 userStorage.value，保持之前的状态（可能是从 localStorage 恢复的）
        return {
          success: false,
          error: '用户未登录'
        }
      } else {
        // 其他情况（已登录后 session 过期等），清理数据
        user.value = null
        userStorage.value = null
        return {
          success: false,
          error: error.response?.data?.message || '网络错误'
        }
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
      const response = await authApiService.login({ username, password }) as LoginResponse
      if (response.success && response.data) {
        // 登录成功，直接使用返回的用户信息
        user.value = response.data.user // TODO 有意义吗？
        userStorage.value = response.data.user

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
    fetchCurrentUser: store.fetchCurrentUser,
    logout: store.logout,
    initAuth: store.initAuth
  }
}
