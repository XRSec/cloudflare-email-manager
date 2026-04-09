import { api, type ApiResponse } from './api-client'
import { API_CACHE_KEYS, API_CACHE_TTL, cachedApiRequest, invalidateApiCache } from './api-cache'

export const systemApiService = {
  async getSystemHealth(): Promise<ApiResponse<any>> {
    const response = await api.get('/system/health')
    return response.data
  },

  async getSystemChanges(): Promise<ApiResponse<any>> {
    const response = await api.get('/system/changes', {
      params: { t: Date.now() },
      headers: {
        'Cache-Control': 'no-cache',
        Pragma: 'no-cache'
      }
    })
    return response.data
  },

  async getSystemConfig(options: { forceRefresh?: boolean } = {}): Promise<ApiResponse<any>> {
    return cachedApiRequest(
      API_CACHE_KEYS.SYSTEM_CONFIG,
      API_CACHE_TTL.SYSTEM_CONFIG,
      async () => {
        const response = await api.get('/system/config')
        return response.data
      },
      options
    )
  },

  async updateSystemConfig(config: any): Promise<ApiResponse<any>> {
    const response = await api.put('/system/config', config)
    invalidateApiCache([API_CACHE_KEYS.SYSTEM_CONFIG])
    return response.data
  }
}
