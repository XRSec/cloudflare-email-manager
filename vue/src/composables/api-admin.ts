import { api, type ApiResponse } from './api-client'
import { emailApiService } from './api-email'

export const adminApiService = {
  getEmails: emailApiService.getEmails,

  async getAllUsers(page = 1, limit = 20, query?: string): Promise<ApiResponse<any>> {
    const params = new URLSearchParams()
    params.append('page', page.toString())
    params.append('limit', limit.toString())
    if (query) {
      params.append('query', query)
    }

    const response = await api.get(`/users?${params}`)
    return response.data
  }
}
