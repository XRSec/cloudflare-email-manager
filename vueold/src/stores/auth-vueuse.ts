import { createGlobalState, useStorage } from '@vueuse/core'
import { computed, ref } from 'vue'

// 用户信息接口
interface User {
  id: string
  username: string
  email: string
  role: string
  avatar?: string
}

// 认证状态接口
interface AuthState {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
}

// 创建全局状态
export const useAuthStore = createGlobalState(() => {
  // 使用 localStorage 持久化存储
  const token = useStorage('auth_token', null as string | null)
  const user = useStorage('auth_user', null as User | null)
  const isLoading = ref(false)

  // 计算属性
  const isAuthenticated = computed(() => !!token.value && !!user.value)

  // 登录方法
  const login = async (username: string, password: string) => {
    isLoading.value = true
    try {
      // 这里调用您的 API
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      })

      if (response.ok) {
        const data = await response.json()
        token.value = data.token
        user.value = data.user
        return { success: true }
      } else {
        return { success: false, error: '登录失败' }
      }
    } catch (error) {
      return { success: false, error: '网络错误' }
    } finally {
      isLoading.value = false
    }
  }

  // 登出方法
  const logout = () => {
    token.value = null
    user.value = null
  }

  // 更新用户信息
  const updateUser = (newUser: Partial<User>) => {
    if (user.value) {
      user.value = { ...user.value, ...newUser }
    }
  }

  return {
    // 状态
    user: readonly(user),
    token: readonly(token),
    isAuthenticated,
    isLoading: readonly(isLoading),

    // 方法
    login,
    logout,
    updateUser,
  }
})

// 导出类型
export type { User, AuthState }
