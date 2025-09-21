// 智能缓存系统 - 路由驱动的现代化缓存架构
import { ref, computed, watch, readonly } from 'vue'
import { useRoute, useRouter } from 'vue-router'

// 缓存状态枚举
export enum CacheStatus {
  FRESH = 'fresh',         // 新鲜数据
  STALE = 'stale',         // 过期但可用
  EXPIRED = 'expired',     // 已过期
  LOADING = 'loading',     // 加载中
  ERROR = 'error'          // 错误状态
}

// 缓存条目接口
interface CacheEntry<T = any> {
  data: T
  timestamp: number
  ttl: number
  version: string
  status: CacheStatus
  dependencies: string[]
  metadata?: Record<string, any>
}

// 路由缓存配置
interface RouteCacheConfig {
  ttl: number                    // 缓存时间 (ms)
  staleWhileRevalidate: number   // 在重新验证时使用过期数据的时间
  dependencies: string[]         // 依赖的其他缓存键
  autoRefresh: boolean          // 是否自动刷新
  refreshInterval?: number      // 自动刷新间隔
  persistToStorage: boolean     // 是否持久化到 localStorage
}

// 默认缓存配置
const DEFAULT_CACHE_CONFIG: RouteCacheConfig = {
  ttl: 5 * 60 * 1000,          // 5分钟
  staleWhileRevalidate: 60 * 1000, // 1分钟
  dependencies: [],
  autoRefresh: false,
  persistToStorage: false
}

// 路由特定缓存配置
const ROUTE_CACHE_CONFIGS: Record<string, Partial<RouteCacheConfig>> = {
  'dashboard': {
    ttl: 2 * 60 * 1000,         // 仪表板数据2分钟过期
    autoRefresh: true,
    refreshInterval: 30 * 1000,   // 30秒刷新
    dependencies: ['user_info']
  },
  'emails': {
    ttl: 30 * 1000,             // 邮件列表30秒过期
    staleWhileRevalidate: 10 * 1000,
    autoRefresh: true,
    refreshInterval: 15 * 1000,
    dependencies: ['mailboxes']
  },
  'mailboxes': {
    ttl: 10 * 60 * 1000,        // 邮箱列表10分钟过期
    dependencies: ['user_info']
  },
  'settings': {
    ttl: 60 * 60 * 1000,        // 设置1小时过期
    persistToStorage: true
  },
  'admin-users': {
    ttl: 5 * 60 * 1000,         // 用户管理5分钟过期
    dependencies: ['user_info']
  }
}

class SmartCacheManager {
  private cache = new Map<string, CacheEntry>()
  private refreshTimers = new Map<string, NodeJS.Timeout>()
  private dependencyGraph = new Map<string, Set<string>>()

  constructor() {
    // 从 localStorage 恢复持久化缓存
    this.restoreFromStorage()

    // 监听页面可见性变化
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        this.refreshStaleData()
      }
    })

    // 页面卸载时保存持久化缓存
    window.addEventListener('beforeunload', () => {
      this.saveToStorage()
    })
  }

  // 生成缓存键
  generateCacheKey(routeName: string, params?: Record<string, any>, query?: Record<string, any>): string {
    let key = `route:${routeName}`

    if (params && Object.keys(params).length > 0) {
      const paramStr = Object.keys(params)
        .sort()
        .map(k => `${k}=${encodeURIComponent(params[k])}`)
        .join('&')
      key += `?${paramStr}`
    }

    if (query && Object.keys(query).length > 0) {
      const queryStr = Object.keys(query)
        .sort()
        .map(k => `${k}=${encodeURIComponent(query[k])}`)
        .join('&')
      key += `${params ? '&' : '?'}${queryStr}`
    }

    return key
  }

  // 获取路由缓存配置
  private getRouteCacheConfig(routeName: string): RouteCacheConfig {
    const config = ROUTE_CACHE_CONFIGS[routeName] || {}
    return { ...DEFAULT_CACHE_CONFIG, ...config }
  }

  // 设置缓存
  set<T>(key: string, data: T, routeName?: string, metadata?: Record<string, any>): void {
    const config = routeName ? this.getRouteCacheConfig(routeName) : DEFAULT_CACHE_CONFIG

    const entry: CacheEntry<T> = {
      data,
      timestamp: Date.now(),
      ttl: config.ttl,
      version: this.generateVersion(),
      status: CacheStatus.FRESH,
      dependencies: config.dependencies,
      metadata
    }

    this.cache.set(key, entry)

    // 建立依赖关系
    this.updateDependencyGraph(key, config.dependencies)

    // 设置自动刷新
    if (config.autoRefresh && config.refreshInterval && routeName) {
      this.setupAutoRefresh(key, config.refreshInterval, routeName)
    }

    // 持久化到存储
    if (config.persistToStorage) {
      this.persistToStorage(key, entry)
    }

    console.log(`✅ 缓存已设置: ${key}`, { config, entry })
  }

  // 获取缓存
  get<T>(key: string): { data: T | null; status: CacheStatus } {
    const entry = this.cache.get(key) as CacheEntry<T> | undefined

    if (!entry) {
      return { data: null, status: CacheStatus.EXPIRED }
    }

    const now = Date.now()
    const age = now - entry.timestamp
    const config = this.getRouteCacheConfigByKey(key)

    // 判断缓存状态
    if (age < entry.ttl) {
      return { data: entry.data, status: CacheStatus.FRESH }
    } else if (age < entry.ttl + config.staleWhileRevalidate) {
      return { data: entry.data, status: CacheStatus.STALE }
    } else {
      return { data: null, status: CacheStatus.EXPIRED }
    }
  }

  // 删除缓存及其依赖
  delete(key: string): void {
    this.cache.delete(key)
    this.clearAutoRefresh(key)
    this.removeFromStorage(key)

    // 删除依赖此键的其他缓存
    this.invalidateDependents(key)

    console.log(`🗑️ 缓存已删除: ${key}`)
  }

  // 批量删除缓存
  deletePattern(pattern: string): void {
    const regex = new RegExp(pattern)
    const keysToDelete = Array.from(this.cache.keys()).filter(key => regex.test(key))

    keysToDelete.forEach(key => this.delete(key))
    console.log(`🗑️ 批量删除缓存: ${pattern}`, keysToDelete)
  }

  // 使缓存失效（但不删除，等待重新验证）
  invalidate(key: string): void {
    const entry = this.cache.get(key)
    if (entry) {
      entry.status = CacheStatus.EXPIRED
      console.log(`❌ 缓存已失效: ${key}`)
    }
  }

  // 使依赖此键的所有缓存失效
  private invalidateDependents(key: string): void {
    const dependents = this.dependencyGraph.get(key) || new Set()
    dependents.forEach(dependent => {
      this.invalidate(dependent)
    })
  }

  // 清空所有缓存
  clear(): void {
    this.cache.clear()
    this.clearAllAutoRefresh()
    this.clearStorage()
    console.log('🧹 所有缓存已清空')
  }

  // 获取缓存统计
  getStats() {
    const stats = {
      totalEntries: this.cache.size,
      fresh: 0,
      stale: 0,
      expired: 0,
      memoryUsage: 0
    }

    this.cache.forEach((entry, key) => {
      const { status } = this.get(key)
      if (status === CacheStatus.FRESH) stats.fresh++
      else if (status === CacheStatus.STALE) stats.stale++
      else if (status === CacheStatus.EXPIRED) stats.expired++
      stats.memoryUsage += JSON.stringify(entry).length
    })

    return stats
  }

  // 刷新过期数据
  private refreshStaleData(): void {
    this.cache.forEach((_entry, key) => {
      const { status } = this.get(key)
      if (status === CacheStatus.STALE || status === CacheStatus.EXPIRED) {
        // 触发重新获取数据的事件
        window.dispatchEvent(new CustomEvent('cache:refresh', { detail: { key } }))
      }
    })
  }

  // 生成版本号
  private generateVersion(): string {
    return `v${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
  }

  // 更新依赖图
  private updateDependencyGraph(key: string, dependencies: string[]): void {
    dependencies.forEach(dep => {
      if (!this.dependencyGraph.has(dep)) {
        this.dependencyGraph.set(dep, new Set())
      }
      this.dependencyGraph.get(dep)!.add(key)
    })
  }

  // 根据缓存键获取配置
  private getRouteCacheConfigByKey(key: string): RouteCacheConfig {
    const routeName = key.split(':')[1]?.split('?')[0] || ''
    return this.getRouteCacheConfig(routeName)
  }

  // 设置自动刷新
  private setupAutoRefresh(key: string, interval: number, routeName: string): void {
    this.clearAutoRefresh(key)

    const timer = setInterval(() => {
      const entry = this.cache.get(key)
      if (entry && document.visibilityState === 'visible') {
        // 触发刷新事件
        window.dispatchEvent(new CustomEvent('cache:auto-refresh', {
          detail: { key, routeName }
        }))
      }
    }, interval)

    this.refreshTimers.set(key, timer)
  }

  // 清除自动刷新
  private clearAutoRefresh(key: string): void {
    const timer = this.refreshTimers.get(key)
    if (timer) {
      clearInterval(timer)
      this.refreshTimers.delete(key)
    }
  }

  // 清除所有自动刷新
  private clearAllAutoRefresh(): void {
    this.refreshTimers.forEach(timer => clearInterval(timer))
    this.refreshTimers.clear()
  }

  // 持久化到存储
  private persistToStorage(key: string, entry: CacheEntry): void {
    try {
      const storageKey = `cache:${key}`
      localStorage.setItem(storageKey, JSON.stringify(entry))
    } catch (error) {
      console.warn('缓存持久化失败:', error)
    }
  }

  // 从存储恢复
  private restoreFromStorage(): void {
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const storageKey = localStorage.key(i)
        if (storageKey?.startsWith('cache:')) {
          const cacheKey = storageKey.replace('cache:', '')
          const data = localStorage.getItem(storageKey)
          if (data) {
            const entry = JSON.parse(data) as CacheEntry
            // 检查是否过期
            const age = Date.now() - entry.timestamp
            if (age < entry.ttl + 24 * 60 * 60 * 1000) { // 24小时内的数据才恢复
              this.cache.set(cacheKey, entry)
            } else {
              localStorage.removeItem(storageKey)
            }
          }
        }
      }
    } catch (error) {
      console.warn('缓存恢复失败:', error)
    }
  }

  // 保存到存储
  private saveToStorage(): void {
    this.cache.forEach((entry, key) => {
      const config = this.getRouteCacheConfigByKey(key)
      if (config.persistToStorage) {
        this.persistToStorage(key, entry)
      }
    })
  }

  // 从存储删除
  private removeFromStorage(key: string): void {
    try {
      localStorage.removeItem(`cache:${key}`)
    } catch (error) {
      console.warn('缓存删除失败:', error)
    }
  }

  // 清空存储
  private clearStorage(): void {
    try {
      const keysToRemove: string[] = []
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i)
        if (key?.startsWith('cache:')) {
          keysToRemove.push(key)
        }
      }
      keysToRemove.forEach(key => localStorage.removeItem(key))
    } catch (error) {
      console.warn('清空缓存存储失败:', error)
    }
  }
}

// 全局缓存管理器实例
export const smartCache = new SmartCacheManager()

// 路由缓存 Hook
export function useRouteCache<T>() {
  const route = useRoute()

  // 生成当前路由的缓存键
  const cacheKey = computed(() =>
    smartCache.generateCacheKey(String(route.name || ''), route.params, route.query)
  )

  // 获取缓存数据
  const getCachedData = (): { data: T | null; status: CacheStatus } => {
    return smartCache.get<T>(cacheKey.value)
  }

  // 设置缓存数据
  const setCachedData = (data: T, metadata?: Record<string, any>) => {
    smartCache.set(cacheKey.value, data, route.name as string, metadata)
  }

  // 删除当前路由缓存
  const clearCache = () => {
    smartCache.delete(cacheKey.value)
  }

  // 刷新当前路由缓存
  const refreshCache = () => {
    smartCache.invalidate(cacheKey.value)
  }

  // 监听路由变化，清理不相关的缓存
  watch(() => route.name, (newRoute, oldRoute) => {
    if (newRoute !== oldRoute) {
      // 可以在这里实现路由切换时的缓存策略
      console.log(`🔄 路由变化: ${String(oldRoute || '')} → ${String(newRoute || '')}`)
    }
  })

  return {
    cacheKey: readonly(cacheKey),
    getCachedData,
    setCachedData,
    clearCache,
    refreshCache
  }
}

// 页面数据管理 Hook
export function usePageData<T>(
  loader: () => Promise<T>,
  options: {
    immediate?: boolean
    refreshOnWindowFocus?: boolean
    refreshOnReconnect?: boolean
  } = {}
) {
  const { getCachedData, setCachedData, refreshCache } = useRouteCache<T>()

  const loading = ref(false)
  const error = ref<Error | null>(null)
  const data = ref<T | null>(null)

  // 加载数据
  const loadData = async (forceRefresh = false): Promise<T | null> => {
    if (loading.value) return data.value

    loading.value = true
    error.value = null

    try {
      // 检查缓存
      if (!forceRefresh) {
        const cached = getCachedData()
        if (cached.status === CacheStatus.FRESH || cached.status === CacheStatus.STALE) {
          data.value = cached.data
          loading.value = false

          // 如果是过期数据，在后台刷新
          if (cached.status === CacheStatus.STALE) {
            loadData(true).catch(console.error)
          }

          return cached.data
        }
      }

      // 从服务器加载
      const result = await loader()
      data.value = result
      setCachedData(result)

      return result
    } catch (err) {
      error.value = err as Error
      console.error('数据加载失败:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  // 刷新数据
  const refresh = () => loadData(true)

  // 自动加载
  if (options.immediate !== false) {
    loadData().catch(console.error)
  }

  // 监听缓存刷新事件
  const handleCacheRefresh = () => {
    refresh().catch(console.error)
  }

  window.addEventListener('cache:refresh', handleCacheRefresh as EventListener)
  window.addEventListener('cache:auto-refresh', handleCacheRefresh as EventListener)

  // 监听窗口焦点
  if (options.refreshOnWindowFocus) {
    const handleFocus = () => refresh()
    window.addEventListener('focus', handleFocus)
  }

  // 监听网络重连
  if (options.refreshOnReconnect) {
    const handleOnline = () => refresh()
    window.addEventListener('online', handleOnline)
  }

  return {
    data: readonly(data),
    loading: readonly(loading),
    error: readonly(error),
    loadData,
    refresh,
    clearCache: refreshCache
  }
}

export default smartCache
