/**
 * 认证状态管理
 */

import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { UserProfile } from '@/api'
import { apiService } from '@/api'

export const useAuthStore = defineStore('auth', () => {
  // 状态
  const user = ref<UserProfile | null>(null)
  const token = ref<string | null>(apiService.getToken())
  const loading = ref(false)

  // 计算属性
  const isAuthenticated = computed(() => !!token.value && !!user.value)
  const isAdmin = computed(() => user.value?.role === 'admin')

  // 登录
  const login = async (username: string, password: string) => {
    loading.value = true
    try {
      const response = await apiService.login(username, password)
      if (response.success && response.data) {
        token.value = response.data.token
        // 登录成功后获取用户信息
        await fetchCurrentUser()
        return { success: true }
      } else {
        return { success: false, error: response.message || '登录失败' }
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
      user.value = null
      token.value = null
      loading.value = false
    }
  }

  // 获取当前用户信息
  const fetchCurrentUser = async () => {
    if (!token.value) return

    loading.value = true
    try {
      const response = await apiService.getCurrentUser()
      if (response.success && response.data) {
        user.value = response.data
        return { success: true }
      } else {
        // Token 可能已过期
        user.value = null
        token.value = null
        return { success: false, error: response.message || '获取用户信息失败' }
      }
    } catch (error: any) {
      user.value = null
      token.value = null
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
    if (token.value) {
      await fetchCurrentUser()
    }
  }

  return {
    // 状态
    user,
    token,
    loading,

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
