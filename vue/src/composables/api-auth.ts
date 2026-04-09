import { api, type ApiResponse } from './api-client'
import type { UserProfile } from '@/types'

export const authApiService = {
  async login(credentials: { username: string; password: string }): Promise<ApiResponse<any>> {
    const response = await api.post('/auth/login', credentials, {
      skipAuthRedirect: true
    })
    return response.data
  },

  async logout(): Promise<ApiResponse<any>> {
    const response = await api.post('/auth/logout', undefined, {
      skipAuthRedirect: true
    })
    return response.data
  },

  async getCurrentUser(): Promise<ApiResponse<UserProfile>> {
    const response = await api.get('/users/me', {
      skipAuthRedirect: true
    })
    return response.data
  }
}
