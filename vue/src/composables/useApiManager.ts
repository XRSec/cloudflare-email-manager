/**
 * 统一接口管理器
 * 提供接口路由映射、统一调用、定时轮询、数据存储等功能
 */

import { ref, computed, onUnmounted } from 'vue'
import { useRequestManager } from './useRequestManager'
import { apiService } from './api'

// 接口方法类型
export type ApiMethod =
  | 'getEmails'
  | 'getEmail'
  | 'deleteEmail'
  | 'getSystemConfig'
  | 'updateSystemConfig'

// 接口配置
export interface ApiConfig {
  /** 接口方法名 */
  method: ApiMethod
  /** 缓存键前缀 */
  cacheKeyPrefix: string
  /** 缓存时间（毫秒） */
  ttl?: number
  /** 是否使用缓存 */
  useCache?: boolean
  /** 是否使用智能缓存 */
  useSmartCache?: boolean
  /** 缓存依赖项 */
  dependencies?: string[]
  /** 数据转换函数（可选） */
  transform?: (data: any) => any
  /** 是否支持定时轮询 */
  enablePolling?: boolean
  /** 轮询间隔（毫秒） */
  pollingInterval?: number
}

// 接口路由配置
export interface ApiRouteConfig {
  /** 路由名称 */
  routeName: string
  /** 接口配置列表 */
  apis: ApiConfig[]
  /** 是否自动加载 */
  autoLoad?: boolean
}

// 轮询任务
interface PollingTask {
  routeName: string
  method: ApiMethod
  interval: number
  timerId: number
  params?: any
  callback?: (data: any) => void
}

/**
 * 统一接口管理器
 */
export function useApiManager() {
  const requestManager = useRequestManager()

  // 存储的数据
  const storedData = ref<Map<string, any>>(new Map())

  // 轮询任务列表
  const pollingTasks = ref<Map<string, PollingTask>>(new Map())

  // 接口路由配置
  const routeConfigs = ref<Map<string, ApiRouteConfig>>(new Map())

  /**
   * 注册接口路由配置
   */
  const registerRoute = (config: ApiRouteConfig) => {
    routeConfigs.value.set(config.routeName, config)
    console.log('📋 注册接口路由:', config.routeName, config.apis.map(a => a.method))
  }

  /**
   * 调用接口
   */
  const callApi = async <T = any>(
    method: ApiMethod,
    params?: any,
    options: {
      forceRefresh?: boolean
      routeName?: string
      customConfig?: Partial<ApiConfig>
    } = {}
  ): Promise<T> => {
    const { forceRefresh = false, routeName, customConfig = {} } = options

    // 查找接口配置
    let apiConfig: ApiConfig | undefined

    if (routeName) {
      const routeConfig = routeConfigs.value.get(routeName)
      if (routeConfig) {
        apiConfig = routeConfig.apis.find(api => api.method === method)
      }
    }

    // 如果没有找到配置，使用默认配置
    if (!apiConfig) {
      apiConfig = {
        method,
        cacheKeyPrefix: method,
        ttl: 5 * 60 * 1000,
        useCache: true,
        useSmartCache: false,
        ...customConfig
      }
    }

    // 合并自定义配置
    const finalConfig = { ...apiConfig, ...customConfig }

    // 生成去重键（确保参数顺序一致）
    const sortedParams = params ? Object.keys(params).sort().reduce((acc, key) => {
      acc[key] = params[key]
      return acc
    }, {} as any) : {}
    const dedupeKey = `${method}_${JSON.stringify(sortedParams)}`

    console.log(`🔑 生成去重键: ${dedupeKey}`, { method, params: sortedParams, forceRefresh })

    // 调用请求管理器
    const response = await requestManager.request(
      async () => {
        console.log(`🌐 执行API调用: ${method}`, params)
        // 调用实际的API方法
        const apiResponse = await (apiService as any)[method](params)
        console.log(`✅ API调用完成: ${method}`, { success: apiResponse?.success })
        return apiResponse
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

    // 存储数据
    const storageKey = `${method}_${JSON.stringify(params || {})}`
    storedData.value.set(storageKey, transformedData)

    return transformedData
  }

  /**
   * 获取存储的数据
   */
  const getStoredData = <T = any>(method: ApiMethod, params?: any): T | undefined => {
    const storageKey = `${method}_${JSON.stringify(params || {})}`
    return storedData.value.get(storageKey) as T | undefined
  }

  /**
   * 清除存储的数据
   */
  const clearStoredData = (method?: ApiMethod, params?: any) => {
    if (method) {
      const storageKey = `${method}_${JSON.stringify(params || {})}`
      storedData.value.delete(storageKey)
    } else {
      storedData.value.clear()
    }
  }

  /**
   * 启动定时轮询
   */
  const startPolling = (
    method: ApiMethod,
    params: any,
    options: {
      interval?: number
      routeName?: string
      callback?: (data: any) => void
    } = {}
  ) => {
    const { interval = 30000, routeName, callback } = options

    // 查找接口配置
    let apiConfig: ApiConfig | undefined
    if (routeName) {
      const routeConfig = routeConfigs.value.get(routeName)
      if (routeConfig) {
        apiConfig = routeConfig.apis.find(api => api.method === method)
      }
    }

    // 检查是否支持轮询
    if (apiConfig && apiConfig.enablePolling === false) {
      console.warn(`接口 ${method} 不支持轮询`)
      return
    }

    const pollingInterval = apiConfig?.pollingInterval || interval
    const taskKey = `${method}_${JSON.stringify(params || {})}`

    // 如果已经存在轮询任务，先停止
    if (pollingTasks.value.has(taskKey)) {
      stopPolling(method, params)
    }

    // 立即执行一次
    callApi(method, params, { routeName }).then(data => {
      if (callback) {
        callback(data)
      }
    })

    // 创建定时器
    const timerId = window.setInterval(() => {
      callApi(method, params, { routeName, forceRefresh: true }).then(data => {
        if (callback) {
          callback(data)
        }
      })
    }, pollingInterval)

    // 保存轮询任务
    pollingTasks.value.set(taskKey, {
      routeName: routeName || '',
      method,
      interval: pollingInterval,
      timerId,
      params,
      callback
    })

    console.log(`🔄 启动轮询: ${method}，间隔: ${pollingInterval}ms`)
  }

  /**
   * 停止定时轮询
   */
  const stopPolling = (method: ApiMethod, params?: any) => {
    const taskKey = `${method}_${JSON.stringify(params || {})}`
    const task = pollingTasks.value.get(taskKey)

    if (task) {
      clearInterval(task.timerId)
      pollingTasks.value.delete(taskKey)
      console.log(`⏹️ 停止轮询: ${method}`)
    }
  }

  /**
   * 停止所有轮询
   */
  const stopAllPolling = () => {
    pollingTasks.value.forEach(task => {
      clearInterval(task.timerId)
    })
    pollingTasks.value.clear()
    console.log('⏹️ 停止所有轮询')
  }

  /**
   * 加载路由的所有接口
   */
  const loadRouteApis = async (
    routeName: string,
    options: {
      forceRefresh?: boolean
      params?: Record<string, any>
    } = {}
  ) => {
    const { forceRefresh = false, params = {} } = options
    const routeConfig = routeConfigs.value.get(routeName)

    if (!routeConfig) {
      console.warn(`路由 ${routeName} 未注册`)
      return {}
    }

    const results: Record<string, any> = {}

    // 并行加载所有接口（使用 Promise.allSettled 确保所有请求都完成）
    const promises = routeConfig.apis.map(async api => {
      try {
        const apiParams = params[api.method] || params
        console.log(`📡 调用接口: ${api.method}`, { params: apiParams, forceRefresh, routeName })
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

    console.log(`✅ 路由 ${routeName} 的所有接口加载完成`, Object.keys(results))
    return results
  }

  /**
   * 刷新路由的所有接口
   */
  const refreshRouteApis = async (routeName: string, params?: Record<string, any>) => {
    return loadRouteApis(routeName, { forceRefresh: true, params })
  }

  /**
   * 获取路由配置
   */
  const getRouteConfig = (routeName: string): ApiRouteConfig | undefined => {
    return routeConfigs.value.get(routeName)
  }

  /**
   * 获取轮询任务列表
   */
  const getPollingTasks = () => {
    return Array.from(pollingTasks.value.values())
  }

  // 组件卸载时清理
  onUnmounted(() => {
    stopAllPolling()
  })

  return {
    // 配置
    registerRoute,
    getRouteConfig,

    // 接口调用
    callApi,
    loadRouteApis,
    refreshRouteApis,

    // 数据存储
    getStoredData,
    clearStoredData,

    // 轮询
    startPolling,
    stopPolling,
    stopAllPolling,
    getPollingTasks,

    // 状态
    storedData: computed(() => Object.fromEntries(storedData.value)),
    pollingTasks: computed(() => getPollingTasks())
  }
}

// 全局接口管理器实例
let globalApiManager: ReturnType<typeof useApiManager> | null = null

/**
 * 获取全局接口管理器实例
 */
export function getGlobalApiManager() {
  if (!globalApiManager) {
    globalApiManager = useApiManager()
  }
  return globalApiManager
}

