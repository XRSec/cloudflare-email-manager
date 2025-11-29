/**
 * 统一的路由API缓存映射管理器
 * 简化版本 - 每个页面对应独立的API方法，无需复杂的scope参数处理
 */

import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import { forwardRuleApiService, userApiService, emailApiService, systemApiService } from './api'
import { cacheService } from './cache'
import { useAuthStore } from './stores'

// API方法类型定义 - 按服务分类
export type EmailApiMethod = 'getEmails'
export type ForwardRuleMethod = 'getForwardRules'
export type UserApiMethod = 'getUserProfile'
export type SystemApiMethod = 'getSystemConfig'

// 联合类型
export type ApiMethod = EmailApiMethod | ForwardRuleMethod | UserApiMethod | SystemApiMethod

// API服务映射配置
interface ApiServiceMapping {
  service: any
  methods: ApiMethod[]
  description: string
}

// API服务映射表
const API_SERVICE_MAPPINGS: ApiServiceMapping[] = [
  {
    service: emailApiService,
    methods: ['getEmails'],
    description: '邮件相关API'
  },
  {
    service: userApiService,
    methods: ['getUserProfile'],
    description: '用户相关API'
  },
  {
    service: forwardRuleApiService,
    methods: ['getForwardRules'],
    description: '转发规则API'
  },
  {
    service: systemApiService,
    methods: ['getSystemConfig'],
    description: '系统配置API'
  }
]

// 缓存策略类型
export interface CacheStrategy {
  keyPrefix: string
  ttl: number // 缓存时间（毫秒）
  forceRefresh?: boolean // 是否强制刷新
}

// API参数类型
export interface ApiParams {
  page?: number
  limit?: number
  search?: string
  status?: string
  days?: number
  [key: string]: any
}

// 路由配置类型
export interface RouteConfig {
  routeName: string
  description: string
  apiMethod: ApiMethod
  apiParams: ApiParams
  requiresAuth: boolean
  adminOnly?: boolean
  cacheStrategy: CacheStrategy
}

// 路由API缓存映射配置 - 简化版本
export const ROUTE_API_CACHE_MAP: Record<string, RouteConfig> = {
  // 管理员全部邮件页面
  'all-emails': {
    routeName: 'all-emails',
    apiMethod: 'getEmails',
    apiParams: { page: 1, limit: 20, scope: 'all' },
    cacheStrategy: { keyPrefix: 'all_emails', ttl: 2 * 60 * 1000 },
    requiresAuth: true,
    adminOnly: true,
    description: '全部邮件'
  },

  // 转发规则页面
  'forward-rules': {
    routeName: 'forward-rules',
    apiMethod: 'getForwardRules',
    apiParams: { page: 1, limit: 20 },
    cacheStrategy: { keyPrefix: 'forward_rules', ttl: 5 * 60 * 1000 },
    requiresAuth: true,
    adminOnly: true,
    description: '转发管理'
  },

  // 系统设置页面
  'system-settings': {
    routeName: 'system-settings',
    apiMethod: 'getSystemConfig',
    apiParams: {},
    cacheStrategy: { keyPrefix: 'system_settings', ttl: 10 * 60 * 1000 },
    requiresAuth: true,
    adminOnly: true,
    description: '系统设置'
  }
}

// 验证API服务映射的完整性
const validateApiServiceMappings = () => {
  console.log('🔍 验证API服务映射完整性...')

  // 收集所有已定义的API方法
  const allMethods = new Set<ApiMethod>()
  API_SERVICE_MAPPINGS.forEach(mapping => {
    mapping.methods.forEach(method => allMethods.add(method))
  })

  // 收集路由配置中的所有API方法
  const routeMethods = new Set<string>()
  Object.values(ROUTE_API_CACHE_MAP).forEach(config => {
    routeMethods.add(config.apiMethod)
  })

  // 检查是否有路由配置中的方法没有在映射中定义
  const missingMappings = Array.from(routeMethods).filter(method => !allMethods.has(method as ApiMethod))
  if (missingMappings.length > 0) {
    console.warn('⚠️ 以下API方法缺少服务映射:', missingMappings)
  }

  // 检查是否有映射中的方法没有在路由配置中使用
  const unusedMappings = Array.from(allMethods).filter(method => !routeMethods.has(method))
  if (unusedMappings.length > 0) {
    console.warn('⚠️ 以下API方法映射未被使用:', unusedMappings)
  }

  console.log('✅ API服务映射验证完成')
  console.log(`📊 统计: 已定义方法 ${allMethods.size} 个, 路由使用 ${routeMethods.size} 个`)
}

// 在开发模式下自动验证
if (import.meta.env.DEV) {
  // 延迟执行，确保 ROUTE_API_CACHE_MAP 已经定义
  setTimeout(validateApiServiceMappings, 100)
}

// 路由API缓存映射器
export function useRouteApiCacheMapper() {
  const route = useRoute()
  const authStore = useAuthStore()

  // 当前路由配置
  const currentRouteConfig = computed(() => {
    const routeName = route.name as string
    return ROUTE_API_CACHE_MAP[routeName] || null
  })

  // 是否支持统一管理
  const isSupportedRoute = computed(() => {
    return currentRouteConfig.value !== null
  })

  // 是否有权限访问
  const hasPermission = computed(() => {
    const config = currentRouteConfig.value
    if (!config) return false

    // 检查是否需要认证
    if (config.requiresAuth && !authStore.isAuthenticated) {
      return false
    }

    // 检查是否需要管理员权限
    if (config.adminOnly && !authStore.isAdmin) {
      return false
    }

    return true
  })

  // 生成缓存键
  const generateCacheKey = (params: ApiParams = {}) => {
    const config = currentRouteConfig.value
    if (!config) return null

    const userId = authStore.user?.id
    if (!userId) return null

    const { keyPrefix } = config.cacheStrategy
    const finalParams = { ...config.apiParams, ...params } // 合并默认参数和传入参数

    // 过滤掉undefined和null值，并排序确保一致性
    const paramString = Object.entries(finalParams)
      .filter(([_, value]) => value !== undefined && value !== null)
      .sort(([a], [b]) => a.localeCompare(b)) // 排序确保一致性
      .map(([key, value]) => `${key}_${value}`)
      .join('_')

    const cacheKey = `${keyPrefix}_${userId}_${config.routeName}_${paramString}`

    console.log('🔑 生成缓存键:', {
      routeName: config.routeName,
      keyPrefix,
      userId,
      defaultParams: config.apiParams,
      passedParams: params,
      finalParams,
      paramString,
      cacheKey
    })

    return cacheKey
  }

  // 获取API服务实例
  const getApiService = () => {
    const config = currentRouteConfig.value
    if (!config) {
      console.warn('❌ 无法获取API服务：路由配置不存在')
      return null
    }

    // 根据API方法查找对应的服务
    const mapping = API_SERVICE_MAPPINGS.find(mapping =>
      mapping.methods.includes(config.apiMethod as ApiMethod)
    )

    if (mapping) {
      console.log(`🔧 选择API服务: ${mapping.description} (${config.apiMethod})`)
      return mapping.service
    }

    // 如果没有找到精确匹配，使用启发式规则
    console.warn(`⚠️ 未找到API方法 ${config.apiMethod} 的精确映射，使用启发式规则`)

    // 启发式规则：根据方法名和权限选择服务
    if (config.adminOnly ||
      config.apiMethod.includes('getAll') ||
      config.apiMethod.includes('getSecurity') ||
      config.apiMethod.includes('getSystem')) {
      console.log(`🔧 启发式选择: 管理员API服务 (${config.apiMethod})`)
      return adminApiService
    }

    console.log(`🔧 启发式选择: 用户API服务 (${config.apiMethod})`)
    return userApiService
  }

  // 调用API方法
  const callApiMethod = async (params: ApiParams = {}, forceRefresh = false) => {
    const config = currentRouteConfig.value
    if (!config) {
      throw new Error('当前路由不支持统一API管理')
    }

    const apiService = getApiService()
    if (!apiService) {
      throw new Error(`无法找到API服务: ${config.apiMethod}`)
    }

    // 合并参数
    const finalParams = { ...config.apiParams, ...params }

    console.log('🌐 调用API:', {
      method: config.apiMethod,
      params: finalParams,
      forceRefresh
    })

    try {
      // 检查缓存
      if (!forceRefresh) {
        const cacheKey = generateCacheKey(params)
        if (cacheKey) {
          const cachedData = cacheService.get(cacheKey)
          if (cachedData) {
            console.log('📦 使用缓存数据:', cacheKey)
            return cachedData
          }
        }
      }

      // 调用API
      const response = await (apiService as any)[String(config.apiMethod)](finalParams)

      // 缓存响应
      const cacheKey = generateCacheKey(params)
      if (cacheKey) {
        cacheService.set(cacheKey, response, config.cacheStrategy.ttl)
        console.log('💾 缓存API响应:', cacheKey)
      }

      return response
    } catch (error) {
      console.error('❌ API调用失败:', error)
      throw error
    }
  }

  // 清除当前路由缓存
  const clearCurrentRouteCache = () => {
    const config = currentRouteConfig.value
    if (!config) return

    const userId = authStore.user?.id
    if (!userId) return

    const pattern = `${config.cacheStrategy.keyPrefix}_${userId}_${config.routeName}_*`

    try {
      if (typeof (cacheService as any).clearByPattern === 'function') {
        (cacheService as any).clearByPattern(pattern)
        console.log(`🗑️ 清除缓存 - ${pattern}`)
      } else {
        console.warn('缓存服务不支持按模式清除，跳过缓存清除')
      }
    } catch (error) {
      console.warn('清除缓存失败:', error)
    }
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
    callApiMethod,
    clearCurrentRouteCache,
    generateCacheKey,
    getRouteInfo,

    // 工具方法
    getApiService,

    // 调试工具
    getApiServiceInfo: () => {
      const config = currentRouteConfig.value
      if (!config) return null

      const mapping = API_SERVICE_MAPPINGS.find(mapping =>
        mapping.methods.includes(config.apiMethod as ApiMethod)
      )

      return {
        routeName: config.routeName,
        apiMethod: config.apiMethod,
        serviceDescription: mapping?.description || '未知服务',
        serviceMethods: mapping?.methods || [],
        isExactMatch: !!mapping,
        availableMethods: Object.getOwnPropertyNames(mapping?.service || {}).filter(name =>
          typeof mapping?.service[name] === 'function'
        )
      }
    }
  }
}

// 全局刷新管理器
export function useGlobalRefreshManager() {
  const { callApiMethod, isSupportedRoute, hasPermission, getRouteInfo } = useRouteApiCacheMapper()
  const isRefreshing = ref(false)
  const lastRefreshTime = ref<number | null>(null)

  // 执行全局刷新
  const executeGlobalRefresh = async () => {
    if (isRefreshing.value) {
      console.log('🔄 全局刷新已在进行中，跳过')
      return
    }

    if (!isSupportedRoute.value) {
      console.log('⚠️ 当前路由不支持统一刷新管理')
      return
    }

    if (!hasPermission.value) {
      console.log('⚠️ 没有权限执行全局刷新')
      return
    }

    isRefreshing.value = true
    lastRefreshTime.value = Date.now()

    try {
      console.log('🌍 开始全局刷新')
      const routeInfo = getRouteInfo()
      console.log('📋 使用统一刷新管理器', routeInfo)

      await callApiMethod({}, true) // 强制刷新

      console.log('✅ 全局刷新完成')
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

// 统一全局刷新管理器
export function useUnifiedGlobalRefreshManager() {
  const { executeGlobalRefresh, isRefreshing, getCurrentPageRefreshInfo } = useGlobalRefreshManager()

  return {
    executeGlobalRefresh,
    isRefreshing,
    getCurrentPageRefreshInfo
  }
}