import axios from 'axios'

declare module 'axios' {
  interface AxiosRequestConfig {
    skipAuthRedirect?: boolean
  }

  interface InternalAxiosRequestConfig {
    skipAuthRedirect?: boolean
  }
}

export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  message?: string
  code?: number
  error?: string
}

export const api = axios.create({
  baseURL: '/api',
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json'
  },
  withCredentials: true
})

api.interceptors.request.use(
  (config) => config,
  (error) => Promise.reject(error)
)

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !error.config?.skipAuthRedirect) {
      localStorage.clear()
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export async function get(
  url: string,
  config?: { params?: Record<string, any> }
): Promise<ApiResponse<any>> {
  const response = await api.get(url, config)
  return response.data
}

export default api
