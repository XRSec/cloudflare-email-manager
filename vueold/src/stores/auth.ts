/**
 * 认证状态管理 (VueUse 版本)
 */

import { createGlobalState, useStorage } from '@vueuse/core'
import { ref, computed, readonly } from 'vue'
import type { UserProfile } from '@/api'
import { apiService } from '@/api'

export const useAuthStore = createGlobalState(() => {
  // 状态
  const user = ref<UserProfile | null>(null)
  const loading = ref(false)

  // 计算属性
  const isAuthenticated = computed(() => !!user.value)
  const isAdmin = computed(() => user.value?.user_type === 'admin')

  // 登录
  const login = async (username: string, password: string) => {
    loading.value = true
    try {
      const response = await apiService.login(username, password)
      if (response.success && response.data) {
        // 登录成功后获取用户信息
        const userResult = await fetchCurrentUser()
        if (userResult.success) {
          // 存储用户信息到 localStorage
          localStorage.setItem('user_info', JSON.stringify(user.value))
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
  const register = async (username: string, password: string, email: string) => {
    loading.value = true
    try {
      const response = await apiService.register(username, password, email)
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

  // 登出
  const logout = async () => {
    loading.value = true
    try {
      await apiService.logout()
    } catch (error) {
      console.error('登出失败:', error)
    } finally {
      // 无论后端登出是否成功，都清理本地状态
      clearLocalAuthData()
      user.value = null
      loading.value = false
    }
  }

  // 清理本地认证数据（与 clearAllAuthDataAndRedirect 保持一致）
  const clearLocalAuthData = () => {
    // 清理 localStorage 中的认证信息
    localStorage.removeItem('user_info')
    localStorage.removeItem('auth_token')
    localStorage.removeItem('cem_persist_auth_token')

    // 清理 sessionStorage
    sessionStorage.clear()

    // 清理 cookies
    document.cookie = 'session_cookies=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'
  }

  // 获取当前用户信息
  const fetchCurrentUser = async () => {
    loading.value = true
    try {
      const response = await apiService.getCurrentUser()
      if (response.success && response.data) {
        user.value = response.data
        return { success: true }
      } else {
        // 用户可能未登录
        user.value = null
        return { success: false, error: response.message || '获取用户信息失败' }
      }
    } catch (error: any) {
      user.value = null
      return {
        success: false,
        error: error.response?.data?.message || '网络错误'
      }
    } finally {
      loading.value = false
    }
  }

  // 更新用户设置
  const updateUserSettings = async (settings: any) => {
    loading.value = true
    try {
      const response = await apiService.updateUserSettings(settings)
      if (response.success) {
        // 更新成功后重新获取用户信息
        await fetchCurrentUser()
        return { success: true, message: response.message || '设置更新成功' }
      } else {
        return { success: false, error: response.message || '设置更新失败' }
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

  // 初始化认证状态
  const initAuth = async () => {
    // 首先尝试从 localStorage 恢复用户信息
    const savedUser = localStorage.getItem('user_info')
    if (savedUser) {
      try {
        user.value = JSON.parse(savedUser)
      } catch (error) {
        console.error('解析用户信息失败:', error)
        localStorage.removeItem('user_info')
      }
    }

    // 然后尝试从服务器获取最新用户信息
    await fetchCurrentUser()
  }

  return {
    // 状态
    user: readonly(user),
    loading: readonly(loading),

    // 计算属性
    isAuthenticated,
    isAdmin,

    // 方法
    login,
    register,
    logout,
    fetchCurrentUser,
    updateUserSettings,
    initAuth
  }
})
