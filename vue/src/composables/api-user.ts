import { api, type ApiResponse } from './api-client'

export const userApiService = {
  async getUserProfile(): Promise<ApiResponse<any>> {
    const response = await api.get('/users/me')
    return response.data
  },

  async updateUserSettings(settings: any): Promise<ApiResponse<any>> {
    const response = await api.put('/users/me', settings)
    return response.data
  },

  async getUserList(page = 1, limit = 20, query?: string): Promise<ApiResponse<any>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())
    if (query) {
      params.append('query', query)
    }

    const response = await api.get(`/users?${params}`)
    return response.data
  },

  async createUser(userData: {
    username: string
    password: string
    email: string
  }): Promise<ApiResponse<any>> {
    const response = await api.post('/users', userData)
    return response.data
  },

  async getUserById(id: number): Promise<ApiResponse<any>> {
    const response = await api.get(`/users/${id}`)
    return response.data
  },

  async deleteUser(id: number): Promise<ApiResponse<any>> {
    const response = await api.delete(`/users/${id}`)
    return response.data
  }
}
