/**
 * 统一路由API管理器
 * 整合了路由配置、API调用、缓存管理、刷新管理等功能
 */

import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import { emailApiService } from './api-email'
import { systemApiService } from './api-system'
import { adminApiService } from './api-admin'
import { apiService } from './api'
import { useRequestManager } from './useRequestManager'
import { useAuthStore } from './auth'

// ==================== 类型定义 ====================

export type ApiMethod =
  | 'getEmails'
  | 'getEmail'
  | 'deleteEmail'
  | 'getSystemConfig'
  | 'updateSystemConfig'

export interface ApiParams {
  page?: number
  limit?: number
  search?: string
  status?: string
  sender?: string
  subject?: string
  start_date?: string
  end_date?: string
  has_attachments?: boolean
  sort?: string
  order?: 'asc' | 'desc'
  days?: number
  [key: string]: any
}

export interface ApiConfig {
  method: ApiMethod
  cacheKeyPrefix: string
  ttl?: number
  useCache?: boolean
  useSmartCache?: boolean
  dependencies?: string[]
  transform?: (data: any) => any
  enablePolling?: boolean
  pollingInterval?: number
  defaultParams?: ApiParams
}

export interface RouteConfig {
  routeName: string
  description: string
  requiresAuth: boolean
  adminOnly?: boolean
  apis: ApiConfig[]
  autoLoad?: boolean
}

// ==================== 路由配置 ====================

export const ROUTE_CONFIGS: Record<string, RouteConfig> = {
  inbox: {
    routeName: 'inbox',
    description: '收件箱',
    requiresAuth: true,
    adminOnly: true,
    autoLoad: true,
    apis: [
      {
        method: 'getEmails',
        cacheKeyPrefix: 'inbox_emails',
        ttl: 2 * 60 * 1000, // 2分钟
        useCache: true,
        useSmartCache: true,
        dependencies: ['new_email'],
        defaultParams: { page: 1, limit: 20, folder: 'inbox' }
      }
    ]
  },
  sent: {
    routeName: 'sent',
    description: '已发送',
    requiresAuth: true,
    adminOnly: true,
    autoLoad: true,
    apis: [
      {
        method: 'getEmails',
        cacheKeyPrefix: 'sent_emails',
        ttl: 2 * 60 * 1000,
        useCache: true,
        useSmartCache: true,
        dependencies: ['new_email'],
        defaultParams: { page: 1, limit: 20, folder: 'sent' }
      }
    ]
  },
  'system-settings': {
    routeName: 'system-settings',
    description: '系统设置',
    requiresAuth: true,
    adminOnly: true,
    autoLoad: true,
    apis: [
      {
        method: 'getSystemConfig',
        cacheKeyPrefix: 'system_settings',
        ttl: 10 * 60 * 1000, // 10分钟
        useCache: true,
        useSmartCache: false,
        defaultParams: {}
      }
    ]
  },
  'dashboard': {
    routeName: 'dashboard',
    description: '仪表板',
    requiresAuth: true,
    adminOnly: true,
    autoLoad: true,
    apis: [
      {
        method: 'getEmails',
        cacheKeyPrefix: 'dashboard_emails',
        ttl: 10 * 60 * 1000, // 10分钟
        useCache: true,
        useSmartCache: true,
        dependencies: ['new_email'],
        transform: (data: any) => {
          if (data?.success && data?.data) {
            return {
              success: true,
              data: {
                items: data.data.items || [],
                total: data.data.total || 0
              }
            }
          }
          return data
        },
        defaultParams: { page: 1, limit: 10 }
      }
    ]
  }
}

// ==================== API服务映射 ====================

interface ApiServiceMapping {
  service: any
  methods: ApiMethod[]
  description: string
}

const API_SERVICE_MAPPINGS: ApiServiceMapping[] = [
  {
    service: emailApiService,
    methods: ['getEmails', 'getEmail', 'deleteEmail'],
    description: '邮件相关API'
  },
  {
    service: adminApiService,
    methods: ['getEmails'],
    description: '管理员邮件API'
  },
  {
    service: systemApiService,
    methods: ['getSystemConfig', 'updateSystemConfig'],
    description: '系统配置API'
  }
]

// ==================== 统一路由API管理器 ====================

export function useRouteApiManager() {
  const route = useRoute()
  const authStore = useAuthStore()
  const requestManager = useRequestManager()

  // 当前路由配置
  const currentRouteConfig = computed(() => {
    const routeName = route.name as string
    return ROUTE_CONFIGS[routeName] || null
  })

  // 是否支持统一管理
  const isSupportedRoute = computed(() => {
    return currentRouteConfig.value !== null
  })

  // 是否有权限访问
  const hasPermission = computed(() => {
    const config = currentRouteConfig.value
    if (!config) return false

    if (config.requiresAuth && !authStore.isAuthenticated) {
      return false
    }

    // 单管理员模式：所有已认证用户都是管理员，不需要检查 adminOnly

    return true
  })

  // 获取API服务实例
  const getApiService = (method: ApiMethod) => {
    const mapping = API_SERVICE_MAPPINGS.find(mapping =>
      mapping.methods.includes(method)
    )

    if (mapping) {
      return mapping.service
    }

    // 默认使用统一API服务
    return apiService
  }

  // 生成缓存键
  const generateCacheKey = (apiConfig: ApiConfig, params: ApiParams = {}) => {
    const userId = authStore.user?.id
    if (!userId) return null

    const finalParams = { ...apiConfig.defaultParams, ...params }
    const paramString = Object.entries(finalParams)
      .filter(([_, value]) => value !== undefined && value !== null)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}_${value}`)
      .join('_')

    return `${apiConfig.cacheKeyPrefix}_${userId}_${paramString}`
  }

  // 调用API方法
  const callApi = async (
    method: ApiMethod,
    params: ApiParams = {},
    options: {
      forceRefresh?: boolean
      routeName?: string
      customConfig?: Partial<ApiConfig>
    } = {}
  ) => {
    const { forceRefresh = false, routeName, customConfig = {} } = options

    // 查找API配置
    let apiConfig: ApiConfig | undefined

    if (routeName) {
      const routeConfig = ROUTE_CONFIGS[routeName]
      if (routeConfig) {
        apiConfig = routeConfig.apis.find(api => api.method === method)
      }
    } else if (currentRouteConfig.value) {
      apiConfig = currentRouteConfig.value.apis.find(api => api.method === method)
    }

    // 如果没有找到配置，使用默认配置
    if (!apiConfig) {
      apiConfig = {
        method,
        cacheKeyPrefix: method,
        ttl: 5 * 60 * 1000,
        useCache: true,
        useSmartCache: false,
        defaultParams: {},
        ...customConfig
      }
    }

    // 合并自定义配置
    const finalConfig = { ...apiConfig, ...customConfig }

    // 合并参数
    const finalParams = { ...finalConfig.defaultParams, ...params }

    // 生成去重键
    const sortedParams = Object.keys(finalParams).sort().reduce((acc, key) => {
      acc[key] = finalParams[key]
      return acc
    }, {} as any)
    const dedupeKey = `${method}_${JSON.stringify(sortedParams)}`

    // 调用请求管理器
    const response = await requestManager.request(
      async () => {
        const apiService = getApiService(method)
        if (method === 'getSystemConfig') {
          return await (apiService as any)[method]({ forceRefresh })
        }
        return await (apiService as any)[method](finalParams)
      },
      sortedParams,
      {
        cacheKeyPrefix: finalConfig.cacheKeyPrefix,
        ttl: finalConfig.ttl || 5 * 60 * 1000,
        useCache: finalConfig.useCache !== false,
        forceRefresh,
        useSmartCache: finalConfig.useSmartCache || false,
        dependencies: finalConfig.dependencies || [],
        dedupeKey
      }
    )

    // 数据转换
    let transformedData = response
    if (finalConfig.transform && typeof finalConfig.transform === 'function') {
      transformedData = finalConfig.transform(response)
    }

    return transformedData
  }

  // 调用当前路由的API方法（兼容旧接口）
  const callApiMethod = async (params: ApiParams = {}, forceRefresh = false) => {
    const config = currentRouteConfig.value
    if (!config || config.apis.length === 0) {
      throw new Error('当前路由不支持统一API管理')
    }

    // 使用第一个API配置
    const apiConfig = config.apis[0]
    return callApi(apiConfig.method, params, { forceRefresh })
  }

  // 加载路由的所有API
  const loadRouteApis = async (
    routeName: string,
    options: {
      forceRefresh?: boolean
      params?: Record<string, any>
    } = {}
  ) => {
    const { forceRefresh = false, params = {} } = options
    const routeConfig = ROUTE_CONFIGS[routeName]

    if (!routeConfig) {
      console.warn(`路由 ${routeName} 未配置`)
      return {}
    }

    const results: Record<string, any> = {}

    // 并行加载所有接口
    const promises = routeConfig.apis.map(async api => {
      try {
        const apiParams = params[api.method] || params
        const data = await callApi(api.method, apiParams, {
          forceRefresh,
          routeName
        })
        results[api.method] = data
        return { method: api.method, data, success: true }
      } catch (error) {
        console.error(`❌ 接口调用失败: ${api.method}`, error)
        return { method: api.method, error, success: false }
      }
    })

    await Promise.allSettled(promises)
    return results
  }

  // 刷新路由的所有API
  const refreshRouteApis = async (routeName: string, params?: Record<string, any>) => {
    return loadRouteApis(routeName, { forceRefresh: true, params })
  }

  // 清除当前路由缓存
  const clearCurrentRouteCache = () => {
    const config = currentRouteConfig.value
    if (!config) return

    const userId = authStore.user?.id
    if (!userId) return

    // 清除所有API的缓存
    config.apis.forEach(api => {
      // const pattern = `${api.cacheKeyPrefix}_${userId}_*`
      requestManager.clearCacheByPrefix(api.cacheKeyPrefix)
    })
  }

  // 获取路由信息
  const getRouteInfo = () => {
    return currentRouteConfig.value
  }

  return {
    // 状态
    currentRouteConfig,
    isSupportedRoute,
    hasPermission,

    // 方法
    callApi,
    callApiMethod, // 兼容旧接口
    loadRouteApis,
    refreshRouteApis,
    clearCurrentRouteCache,
    getRouteInfo,
    getApiService,
    generateCacheKey
  }
}

// ==================== 全局刷新管理器（简化版） ====================

export function useRouteGlobalRefreshManager() {
  const { callApiMethod, isSupportedRoute, hasPermission, getRouteInfo, refreshRouteApis } = useRouteApiManager()
  const isRefreshing = ref(false)
  const lastRefreshTime = ref<number | null>(null)

  // 执行全局刷新
  const executeGlobalRefresh = async () => {
    if (isRefreshing.value) {
      return
    }

    if (!isSupportedRoute.value) {
      console.warn('⚠️ 当前路由不支持统一刷新管理')
      return
    }

    if (!hasPermission.value) {
      console.warn('⚠️ 没有权限执行全局刷新')
      return
    }

    isRefreshing.value = true
    lastRefreshTime.value = Date.now()

    try {
      const routeName = getRouteInfo()?.routeName
      if (routeName) {
        await refreshRouteApis(routeName)
      } else {
        await callApiMethod({}, true) // 强制刷新
      }
    } catch (error) {
      console.error('❌ 全局刷新失败:', error)
      throw error
    } finally {
      isRefreshing.value = false
    }
  }

  // 获取当前页面刷新信息
  const getCurrentPageRefreshInfo = () => {
    const routeInfo = getRouteInfo()
    return {
      routeName: routeInfo?.routeName || 'unknown',
      isSupported: isSupportedRoute.value,
      hasPermission: hasPermission.value,
      routeInfo,
      lastRefresh: lastRefreshTime.value
    }
  }

  return {
    isRefreshing,
    lastRefreshTime,
    executeGlobalRefresh,
    getCurrentPageRefreshInfo
  }
}

// ==================== 导出路由配置（用于 useApiManager 兼容） ====================

export const dashboardRouteConfig = {
  routeName: 'dashboard',
  apis: ROUTE_CONFIGS.dashboard.apis
}

export const inboxRouteConfig = {
  routeName: 'inbox',
  apis: ROUTE_CONFIGS.inbox.apis
}

export const systemSettingsRouteConfig = {
  routeName: 'system-settings',
  apis: ROUTE_CONFIGS['system-settings'].apis
}
