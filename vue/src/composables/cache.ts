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

  // 按模式清除缓存（支持通配符）
  clearByPattern(pattern: string): void {
    try {
      // 将通配符模式转换为正则表达式
      // 例如: "system_settings_1_system-settings_*" -> /^system_settings_1_system-settings_.*$/
      const regexPattern = pattern.replace(/\*/g, '.*').replace(/\?/g, '.')
      const regex = new RegExp(`^${regexPattern}$`)

      const keys = this.keys()
      let clearedCount = 0

      keys.forEach(key => {
        if (regex.test(key)) {
          this.delete(key)
          clearedCount++
        }
      })
    } catch (error) {
      console.error(`按模式清除缓存失败 ${pattern}:`, error)
    }
  }

  clearByPrefix(prefix: string): number {
    let clearedCount = 0

    this.keys().forEach(key => {
      if (key.startsWith(prefix)) {
        this.delete(key)
        clearedCount++
      }
    })

    return clearedCount
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
    if (cached !== undefined) {
      return cached
    }

    // 缓存未命中，调用原函数
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
      return cached
    }

    // 缓存未命中，调用加载器
    const result = await this.loader()

    // 将结果存入缓存
    if (this.ttl) {
      cacheService.set(key, result, this.ttl)
    }

    return result
  }
}

// ==================== 浏览器缓存管理（Cache-Control） ====================

/**
 * 应用存储管理器
 * 管理前端应用存储（localStorage、sessionStorage、IndexedDB）
 * 注意：HTTP 缓存（Cache-Control）由后端 Worker 控制，前端无法管理
 */
export class BrowserCacheManager {
  /**
   * 清理所有应用存储
   * 包括：localStorage、sessionStorage、IndexedDB
   * 注意：HTTP 缓存由后端通过 Cache-Control 响应头控制，无法通过前端清理
   */
  async clearAllBrowserCache(): Promise<{
    success: boolean
    cleared: string[]
    errors: string[]
  }> {
    const cleared: string[] = []
    const errors: string[] = []

    try {
      // 注意：Service Worker 缓存已移除，项目未使用 Service Worker

      // 2. 清理 localStorage（保留 cem_cache_ 前缀的缓存，只清理其他）
      try {
        const keys = Object.keys(localStorage)
        let clearedCount = 0
        keys.forEach(key => {
          if (!key.startsWith('cem_cache_') && !key.startsWith('user_info') && !key.startsWith('systemConfig')) {
            localStorage.removeItem(key)
            clearedCount++
          }
        })
        if (clearedCount > 0) {
          cleared.push(`localStorage (${clearedCount} 项)`)
        }
      } catch (error) {
        errors.push(`localStorage 清理失败: ${error}`)
        console.error('❌ localStorage 清理失败:', error)
      }

      // 3. 清理 sessionStorage
      try {
        const count = sessionStorage.length
        sessionStorage.clear()
        if (count > 0) {
          cleared.push(`sessionStorage (${count} 项)`)
        }
      } catch (error) {
        errors.push(`sessionStorage 清理失败: ${error}`)
        console.error('❌ sessionStorage 清理失败:', error)
      }

      // 4. 清理 IndexedDB
      if ('indexedDB' in window) {
        try {
          const databases = await indexedDB.databases()
          await Promise.all(
            databases.map(db => {
              return new Promise<void>((resolve, reject) => {
                const deleteReq = indexedDB.deleteDatabase(db.name!)
                deleteReq.onsuccess = () => resolve()
                deleteReq.onerror = () => reject(deleteReq.error)
                deleteReq.onblocked = () => {
                  console.warn(`IndexedDB ${db.name} 删除被阻止`)
                  resolve() // 继续执行
                }
              })
            })
          )
          if (databases.length > 0) {
            cleared.push(`IndexedDB (${databases.length} 个数据库)`)
          }
        } catch (error) {
          errors.push(`IndexedDB 清理失败: ${error}`)
          console.error('❌ IndexedDB 清理失败:', error)
        }
      }

      // 注意：HTTP 缓存（Cache-Control）由后端 Worker 通过响应头控制
      // 前端无法直接清理 HTTP 缓存，需要用户手动刷新页面或清除浏览器缓存

      return {
        success: errors.length === 0,
        cleared,
        errors
      }
    } catch (error) {
      errors.push(`清理过程出错: ${error}`)
      return {
        success: false,
        cleared,
        errors
      }
    }
  }

  /**
   * 获取应用存储统计信息
   * 注意：HTTP 缓存统计无法获取，由浏览器自动管理
   */
  async getBrowserCacheStats(): Promise<{
    localStorage: number
    sessionStorage: number
    indexedDB: number
    totalSize: number
  }> {
    const stats = {
      localStorage: 0,
      sessionStorage: 0,
      indexedDB: 0,
      totalSize: 0
    }

    try {
      // 注意：Service Worker 缓存已移除，项目未使用 Service Worker

      // localStorage
      stats.localStorage = Object.keys(localStorage).length

      // sessionStorage
      stats.sessionStorage = Object.keys(sessionStorage).length

      // IndexedDB
      if ('indexedDB' in window) {
        const databases = await indexedDB.databases()
        stats.indexedDB = databases.length
      }

      // 计算总大小（粗略估算）
      let totalSize = 0
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i)
        if (key) {
          totalSize += localStorage.getItem(key)?.length || 0
        }
      }
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i)
        if (key) {
          totalSize += sessionStorage.getItem(key)?.length || 0
        }
      }
      stats.totalSize = totalSize
    } catch (error) {
      console.error('获取浏览器缓存统计失败:', error)
    }

    return stats
  }

  /**
   * 注意：Cache-Control HTTP 响应头由后端（Worker）设置
   * 前端无法直接设置 HTTP 响应头，只能通过 meta 标签影响页面本身的缓存行为
   * 静态资源（CSS、JS、图片等）的 Cache-Control 已在 worker/src/main.ts 中配置：
   * - HTML: no-cache, no-store, must-revalidate
   * - CSS/JS/字体/图片: public, max-age=31536000, immutable (1年)
   * - 其他: public, max-age=3600 (1小时)
   */
}

// 全局浏览器缓存管理器实例
export const browserCacheManager = new BrowserCacheManager()
