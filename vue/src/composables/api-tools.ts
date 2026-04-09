import { api, type ApiResponse } from './api-client'

export const toolsApiService = {
  async getDatabaseInfo(): Promise<ApiResponse<any>> {
    const response = await api.get('/tools/d1/info')
    return response.data
  },

  async getAllTablesData(): Promise<ApiResponse<any>> {
    const response = await api.get('/tools/d1/tables')
    return response.data
  },

  async initializeDatabase(confirmText: string): Promise<ApiResponse<any>> {
    const response = await api.post('/tools/d1/init', { confirmText })
    return response.data
  },

  async getDatabaseStats(): Promise<ApiResponse<any>> {
    const response = await api.get('/tools/d1/stats')
    return response.data
  }
}
