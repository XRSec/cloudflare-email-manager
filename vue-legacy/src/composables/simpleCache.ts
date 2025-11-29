// 简化的缓存系统 - 专注实用性
import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'

// 简化的缓存状态
export enum CacheStatus {
  FRESH = 'fresh',     // 新鲜数据
  EXPIRED = 'expired'  // 已过期
}

interface CacheEntry<T = any> {
  data: T
  timestamp: number
  ttl: number
}

// 路由缓存配置 - 大幅简化
const ROUTE_CACHE_TTL: Record<string, number> = {
  'dashboard': 2 * 60 * 1000,      // 仪表板 2分钟
  'emails': 30 * 1000,             // 邮件 30秒
  'mailboxes': 5 * 60 * 1000,      // 邮箱 5分钟
  'settings': 30 * 60 * 1000,      // 设置 30分钟
  'admin-users': 5 * 60 * 1000,    // 用户管理 5分钟
  'admin-emails': 30 * 1000,       // 全部邮件 30秒
}

class SimpleCache {
  private cache = new Map<string, CacheEntry>()

  // 生成缓存键 - 利用路径
  generateKey(path: string, params?: Record<string, any>): string {
    let key = `route:${path}`
    if (params && Object.keys(params).length > 0) {
      const paramStr = Object.keys(params)
        .sort()
        .map(k => `${k}=${params[k]}`)
        .join('&')
      key += `?${paramStr}`
    }
    return key
  }

  // 设置缓存
  set<T>(key: string, data: T, routeName?: string): void {
    const ttl = routeName ? ROUTE_CACHE_TTL[routeName] || 5 * 60 * 1000 : 5 * 60 * 1000
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl
    })
  }

  // 获取缓存
  get<T>(key: string): { data: T | null; status: CacheStatus } {
    const entry = this.cache.get(key) as CacheEntry<T> | undefined

    if (!entry) {
      return { data: null, status: CacheStatus.EXPIRED }
    }

    const isExpired = Date.now() - entry.timestamp > entry.ttl
    if (isExpired) {
      this.cache.delete(key)
      return { data: null, status: CacheStatus.EXPIRED }
    }

    return { data: entry.data, status: CacheStatus.FRESH }
  }

  // 删除缓存
  delete(key: string): void {
    this.cache.delete(key)
  }

  // 清空相关缓存
  clearByPattern(pattern: string): void {
    const regex = new RegExp(pattern)
    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        this.cache.delete(key)
      }
    }
  }

  // 获取简单统计
  getStats() {
    return {
      totalEntries: this.cache.size,
      memoryUsage: JSON.stringify([...this.cache.entries()]).length
    }
  }
}

export const simpleCache = new SimpleCache()

// 简化的页面数据 Hook
export function usePageData<T>(
  loader: () => Promise<T>,
  options: {
    cacheTTL?: number
    cacheKey?: string
  } = {}
) {
  const route = useRoute()
  const loading = ref(false)
  const data = ref<T | null>(null)
  const error = ref<Error | null>(null)

  // 生成缓存键
  const cacheKey = computed(() => {
    if (options.cacheKey) return options.cacheKey
    return simpleCache.generateKey(route.path, route.query)
  })

  // 加载数据
  const loadData = async (forceRefresh = false): Promise<T | null> => {
    if (loading.value) return data.value

    // 检查缓存
    if (!forceRefresh) {
      const cached = simpleCache.get<T>(cacheKey.value)
      if (cached.status === CacheStatus.FRESH) {
        data.value = cached.data
        return cached.data
      }
    }

    loading.value = true
    error.value = null

    try {
      const result = await loader()
      data.value = result

      // 设置缓存
      simpleCache.set(cacheKey.value, result, route.name as string)

      return result
    } catch (err) {
      error.value = err as Error
      throw err
    } finally {
      loading.value = false
    }
  }

  // 刷新数据
  const refresh = () => loadData(true)

  // 清除缓存
  const clearCache = () => {
    simpleCache.delete(cacheKey.value)
  }

  return {
    data,
    loading,
    error,
    loadData,
    refresh,
    clearCache
  }
}

export default simpleCache
