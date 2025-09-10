/**
 * 认证状态管理
 */
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { User, LoginForm, RegisterForm } from '@/types'
import { apiService } from '@/services/api'

export const useAuthStore = defineStore('auth', () => {
  // 状态
  const currentUser = ref<User | null>(null)
  const token = ref<string | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  // 计算属性
  const isAuthenticated = computed(() => !!currentUser.value && !!token.value)
  const isAdmin = computed(() => currentUser.value?.user_type === 'admin')

  // 操作
  const setUser = (user: User | null) => {
    currentUser.value = user
  }

  const setToken = (newToken: string | null) => {
    token.value = newToken
    apiService.setToken(newToken)
  }

  const setLoading = (isLoading: boolean) => {
    loading.value = isLoading
  }

  const setError = (errorMessage: string | null) => {
    error.value = errorMessage
  }

  const clearError = () => {
    error.value = null
  }

  // 登录
  const login = async (credentials: LoginForm): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.login(credentials)
      
      if (response.success && response.data) {
        setToken(response.data.token)
        setUser(response.data.user)
        return true
      }
      
      setError(response.error || '登录失败')
      return false
    } catch (err: any) {
      setError(err.message || '登录失败')
      return false
    } finally {
      setLoading(false)
    }
  }

  // 注册
  const register = async (data: RegisterForm): Promise<{ success: boolean; email_prefix?: string }> => {
    try {
      setLoading(true)
      setError(null)

      const response = await apiService.register(data)
      
      if (response.success && response.data) {
        return {
          success: true,
          email_prefix: response.data.email_prefix
        }
      }
      
      setError(response.error || '注册失败')
      return { success: false }
    } catch (err: any) {
      setError(err.message || '注册失败')
      return { success: false }
    } finally {
      setLoading(false)
    }
  }

  // 登出
  const logout = async () => {
    try {
      await apiService.logout()
    } catch (err) {
      console.warn('登出请求失败:', err)
    } finally {
      setToken(null)
      setUser(null)
      setError(null)
    }
  }

  // 检查认证状态
  const checkAuth = async (): Promise<boolean> => {
    try {
      // 恢复本地存储的 token
      apiService.restoreToken()
      const storedToken = localStorage.getItem('cem_persist_auth_token') || 
                         localStorage.getItem('auth_token')
      
      if (!storedToken) {
        return false
      }

      setToken(storedToken)
      
      const response = await apiService.getCurrentUser()
      
      if (response.success && response.data) {
        setUser(response.data)
        return true
      }
      
      // Token 无效，清除
      setToken(null)
      return false
    } catch (err) {
      console.warn('认证检查失败:', err)
      setToken(null)
      return false
    }
  }

  // 刷新用户信息
  const refreshUser = async (): Promise<boolean> => {
    try {
      if (!token.value) return false

      const response = await apiService.getCurrentUser()
      
      if (response.success && response.data) {
        setUser(response.data)
        return true
      }
      
      return false
    } catch (err) {
      console.warn('刷新用户信息失败:', err)
      return false
    }
  }

  return {
    // 状态
    currentUser: readonly(currentUser),
    token: readonly(token),
    loading: readonly(loading),
    error: readonly(error),
    
    // 计算属性
    isAuthenticated,
    isAdmin,
    
    // 操作
    setUser,
    setToken,
    setLoading,
    setError,
    clearError,
    login,
    register,
    logout,
    checkAuth,
    refreshUser
  }
})