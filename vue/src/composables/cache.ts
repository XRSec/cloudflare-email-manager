// 缓存服务 - 统一使用localStorage
interface CacheEntry<T> {
  value: T
  expiry: number
  size: number
}

class CacheService {
  private readonly CACHE_PREFIX = 'cem_cache_'
  private readonly MAX_TOTAL_SIZE = 50 * 1024 * 1024 // 50MB 总限制

  set<T>(key: string, value: T, ttl: number): void {
    try {
      const expiry = Date.now() + ttl
      const serializedValue = JSON.stringify(value)
      const size = new Blob([serializedValue]).size

      // 检查总大小限制
      if (size > this.MAX_TOTAL_SIZE) {
        console.warn(`缓存项 ${key} 过大 (${size} bytes)，跳过缓存`)
        return
      }

      const entry: CacheEntry<T> = {
        value,
        expiry,
        size
      }

      const cacheKey = this.CACHE_PREFIX + key
      localStorage.setItem(cacheKey, JSON.stringify(entry))

      console.log(`缓存已保存: ${key} (${size} bytes)`)
    } catch (error) {
      console.error(`保存缓存失败 ${key}:`, error)
    }
  }

  get<T>(key: string): T | undefined {
    try {
      const cacheKey = this.CACHE_PREFIX + key
      const item = localStorage.getItem(cacheKey)

      if (!item) {
        return undefined
      }

      const entry: CacheEntry<T> = JSON.parse(item)

      if (Date.now() > entry.expiry) {
        localStorage.removeItem(cacheKey)
        return undefined
      }

      return entry.value as T
    } catch (error) {
      console.error(`获取缓存失败 ${key}:`, error)
      return undefined
    }
  }

  delete(key: string): void {
    try {
      const cacheKey = this.CACHE_PREFIX + key
      localStorage.removeItem(cacheKey)
    } catch (error) {
      console.error(`删除缓存失败 ${key}:`, error)
    }
  }

  clear(): void {
    try {
      const keys = Object.keys(localStorage)
      keys.forEach(key => {
        if (key.startsWith(this.CACHE_PREFIX)) {
          localStorage.removeItem(key)
        }
      })
    } catch (error) {
      console.error('清空缓存失败:', error)
    }
  }

  size(): number {
    try {
      const keys = Object.keys(localStorage)
      return keys.filter(key => key.startsWith(this.CACHE_PREFIX)).length
    } catch (error) {
      console.error('获取缓存大小失败:', error)
      return 0
    }
  }

  keys(): string[] {
    try {
      const keys = Object.keys(localStorage)
      return keys
        .filter(key => key.startsWith(this.CACHE_PREFIX))
        .map(key => key.substring(this.CACHE_PREFIX.length))
    } catch (error) {
      console.error('获取缓存键失败:', error)
      return []
    }
  }

  // 获取缓存统计信息
  getStats(): { totalSize: number; itemCount: number; averageSize: number } {
    try {
      const keys = Object.keys(localStorage)
      let totalSize = 0
      let itemCount = 0

      keys.forEach(key => {
        if (key.startsWith(this.CACHE_PREFIX)) {
          const item = localStorage.getItem(key)
          if (item) {
            totalSize += new Blob([item]).size
            itemCount++
          }
        }
      })

      return {
        totalSize,
        itemCount,
        averageSize: itemCount > 0 ? Math.round(totalSize / itemCount) : 0
      }
    } catch (error) {
      console.error('获取缓存统计失败:', error)
      return { totalSize: 0, itemCount: 0, averageSize: 0 }
    }
  }

  // 生成缓存键
  generateKey(route: string, params?: Record<string, any>): string {
    const baseKey = `page_${route}`
    if (!params) return baseKey

    const paramStr = Object.keys(params)
      .sort()
      .map(key => `${key}=${params[key]}`)
      .join('&')

    return `${baseKey}_${paramStr}`
  }
}

// 全局缓存实例
export const cacheService = new CacheService()

// 页面刷新管理器
export class PageRefreshManager {
  private refreshHandlers = new Map<string, () => Promise<void>>()

  // 注册页面的刷新处理函数
  registerPageRefresh(routeName: string, handler: () => Promise<void>): void {
    this.refreshHandlers.set(routeName, handler)
  }

  // 注销页面的刷新处理函数
  unregisterPageRefresh(routeName: string): void {
    this.refreshHandlers.delete(routeName)
  }

  // 刷新当前页面
  async refreshCurrentPage(routeName: string): Promise<void> {
    const handler = this.refreshHandlers.get(routeName)
    if (handler) {
      await handler()
    } else {
      console.warn(`No refresh handler registered for route: ${routeName}`)
    }
  }

  // 清理当前页面缓存并刷新
  async clearAndRefreshCurrentPage(routeName: string): Promise<void> {
    // 清理所有与该页面相关的缓存
    const keys = cacheService.keys()
    const pageKeys = keys.filter(key => key.includes(`page_${routeName}`))
    pageKeys.forEach(key => cacheService.delete(key))

    // 刷新页面
    await this.refreshCurrentPage(routeName)
  }

  // 获取所有已注册的页面
  getRegisteredPages(): string[] {
    return Array.from(this.refreshHandlers.keys())
  }
}

// 全局刷新管理器实例
export const pageRefreshManager = new PageRefreshManager()

// 缓存装饰器 - 用于API调用
export function withCache<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  cacheKey: string | ((...args: Parameters<T>) => string),
  ttl?: number
): T {
  return (async (...args: Parameters<T>) => {
    const key = typeof cacheKey === 'function' ? cacheKey(...args) : cacheKey

    // 尝试从缓存获取
    const cached = cacheService.get(key)
    if (cached !== null) {
      console.log(`Cache hit for key: ${key}`)
      return cached
    }

    // 缓存未命中，调用原函数
    console.log(`Cache miss for key: ${key}, calling API`)
    const result = await fn(...args)

    // 将结果存入缓存
    cacheService.set(key, result, ttl || 300000)

    return result
  }) as T
}

// 页面数据加载器 - 带缓存
export class PageDataLoader {
  constructor(
    private routeName: string,
    private loader: () => Promise<any>,
    private cacheKey?: string,
    private ttl?: number
  ) { }

  async load(forceRefresh = false): Promise<any> {
    const key = this.cacheKey || `page_${this.routeName}`

    // 如果强制刷新，先清除缓存
    if (forceRefresh) {
      cacheService.delete(key)
    }

    // 尝试从缓存获取
    const cached = cacheService.get(key)
    if (cached && !forceRefresh) {
      console.log(`Cache hit for page: ${this.routeName}`)
      return cached
    }

    // 缓存未命中，调用加载器
    console.log(`Cache miss for page: ${this.routeName}, loading data`)
    const result = await this.loader()

    // 将结果存入缓存
    if (this.ttl) {
      cacheService.set(key, result, this.ttl)
    }

    return result
  }
}
