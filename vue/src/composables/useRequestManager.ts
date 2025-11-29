/**
 * 统一请求管理器
 * 提供请求去重、缓存管理、刷新控制等功能
 */

import { ref, computed } from 'vue'
import { cacheService } from './cache'
import { smartCache } from './smartCache'

// 请求配置
export interface RequestConfig {
  /** 缓存键前缀 */
  cacheKeyPrefix?: string
  /** 缓存时间（毫秒），默认5分钟 */
  ttl?: number
  /** 是否使用缓存，默认true */
  useCache?: boolean
  /** 是否强制刷新，默认false */
  forceRefresh?: boolean
  /** 缓存依赖项 */
  dependencies?: string[]
  /** 是否使用智能缓存，默认false（使用简单缓存） */
  useSmartCache?: boolean
  /** 请求去重键（如果不提供，将自动生成） */
  dedupeKey?: string
}

// 请求状态
interface RequestState {
  promise: Promise<any>
  timestamp: number
}

// 全局请求状态管理（用于去重）
const pendingRequests = new Map<string, RequestState>()

// 清理过期的请求状态（超过30秒的请求状态会被清理）
const cleanupPendingRequests = () => {
  const now = Date.now()
  const timeout = 30 * 1000 // 30秒

  for (const [key, state] of pendingRequests.entries()) {
    if (now - state.timestamp > timeout) {
      pendingRequests.delete(key)
    }
  }
}

// 生成请求去重键
const generateDedupeKey = (url: string, params?: any): string => {
  const paramString = params ? JSON.stringify(params) : ''
  return `${url}_${paramString}`
}

// 生成缓存键
const generateCacheKey = (prefix: string, params?: any): string => {
  if (!params || Object.keys(params).length === 0) {
    return prefix
  }

  const paramString = Object.entries(params)
    .filter(([_, value]) => value !== undefined && value !== null)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}_${value}`)
    .join('_')

  return `${prefix}_${paramString}`
}

/**
 * 统一请求管理器
 */
export function useRequestManager() {
  // 请求统计
  const requestStats = ref({
    total: 0,
    cached: 0,
    deduped: 0,
    fresh: 0
  })

  /**
   * 执行请求
   * @param requestFn 请求函数
   * @param params 请求参数
   * @param config 请求配置
   */
  const request = async <T = any>(
    requestFn: (params?: any) => Promise<T>,
    params?: any,
    config: RequestConfig = {}
  ): Promise<T> => {
    const {
      cacheKeyPrefix = 'request',
      ttl = 5 * 60 * 1000, // 默认5分钟
      useCache = true,
      forceRefresh = false,
      dependencies = [],
      useSmartCache = false,
      dedupeKey
    } = config

    // 生成去重键
    const requestKey = dedupeKey || generateDedupeKey('request', params)

    // 清理过期的请求状态
    cleanupPendingRequests()

    // 检查是否有正在进行的相同请求（去重）
    const pendingRequest = pendingRequests.get(requestKey)
    if (pendingRequest) {
      // 如果强制刷新，等待当前请求完成后，再发送新请求
      if (forceRefresh) {
        console.log('🔄 强制刷新：等待当前请求完成', requestKey)
        // 等待当前请求完成（忽略错误）
        try {
          await pendingRequest.promise
        } catch (e) {
          // 忽略错误，继续执行
        }
        // 从待处理列表中移除，允许发送新请求
        pendingRequests.delete(requestKey)
        // 继续执行下面的逻辑，发送新的请求
      } else {
        console.log('🔄 请求去重：使用正在进行的请求', requestKey)
        requestStats.value.deduped++
        return pendingRequest.promise
      }
    }

    // 生成缓存键
    const cacheKey = generateCacheKey(cacheKeyPrefix, params)

    // 检查缓存（如果不强制刷新）
    if (useCache && !forceRefresh) {
      let cached: T | null | undefined = null

      if (useSmartCache) {
        cached = smartCache.get<T>(cacheKey)
      } else {
        cached = cacheService.get<T>(cacheKey) || null
      }

      if (cached) {
        console.log('📦 使用缓存数据:', cacheKey)
        requestStats.value.cached++
        return cached
      }
    }

    // 创建请求Promise
    const requestPromise = (async () => {
      try {
        console.log('🌐 发送请求:', { cacheKey, params, forceRefresh })
        requestStats.value.total++

        // 执行请求
        const response = await requestFn(params)

        // 缓存响应
        if (useCache) {
          if (useSmartCache) {
            smartCache.set(cacheKey, response, {
              ttl,
              dependencies
            })
          } else {
            cacheService.set(cacheKey, response, ttl)
          }
          console.log('💾 缓存响应:', cacheKey)
        }

        requestStats.value.fresh++
        return response
      } catch (error) {
        console.error('❌ 请求失败:', error)
        throw error
      } finally {
        // 请求完成后，从待处理列表中移除
        pendingRequests.delete(requestKey)
      }
    })()

    // 将请求添加到待处理列表
    pendingRequests.set(requestKey, {
      promise: requestPromise,
      timestamp: Date.now()
    })

    return requestPromise
  }

  /**
   * 清除缓存
   * @param prefix 缓存键前缀
   * @param params 参数（可选，如果提供则清除特定缓存）
   */
  const clearCache = (prefix: string, params?: any) => {
    const cacheKey = generateCacheKey(prefix, params)

    // 清除简单缓存
    cacheService.delete(cacheKey)

    // 清除智能缓存
    smartCache.delete(cacheKey)

    console.log('🗑️ 清除缓存:', cacheKey)
  }

  /**
   * 清除所有相关缓存（按前缀）
   * @param prefix 缓存键前缀
   */
  const clearCacheByPrefix = (prefix: string) => {
    // 清除简单缓存
    const keys = cacheService.keys()
    keys.forEach(key => {
      if (key.startsWith(prefix)) {
        cacheService.delete(key)
      }
    })

    // 清除智能缓存（智能缓存使用Map，需要遍历）
    // 注意：smartCache 没有按前缀清除的方法，这里先跳过
    // 如果需要，可以在 smartCache 中添加相应方法

    console.log('🗑️ 清除缓存前缀:', prefix)
  }

  /**
   * 获取请求统计
   */
  const getStats = () => {
    return {
      ...requestStats.value,
      pending: pendingRequests.size
    }
  }

  /**
   * 重置统计
   */
  const resetStats = () => {
    requestStats.value = {
      total: 0,
      cached: 0,
      deduped: 0,
      fresh: 0
    }
  }

  /**
   * 清除所有待处理的请求
   */
  const clearPendingRequests = () => {
    pendingRequests.clear()
    console.log('🗑️ 清除所有待处理请求')
  }

  return {
    // 方法
    request,
    clearCache,
    clearCacheByPrefix,
    getStats,
    resetStats,
    clearPendingRequests,

    // 状态
    requestStats: computed(() => requestStats.value)
  }
}

// 全局请求管理器实例（可选，用于全局使用）
let globalRequestManager: ReturnType<typeof useRequestManager> | null = null

/**
 * 获取全局请求管理器实例
 */
export function getGlobalRequestManager() {
  if (!globalRequestManager) {
    globalRequestManager = useRequestManager()
  }
  return globalRequestManager
}

