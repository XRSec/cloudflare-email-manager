/**
 * 智能缓存管理系统
 * 支持缓存失效、依赖关系、分层缓存等高级功能
 */

interface CacheEntry {
  data: any
  timestamp: number
  ttl: number
  dependencies: string[]
  version: number
}

interface CacheConfig {
  ttl: number
  dependencies: string[]
  version: number
  maxSize?: number
}

class SmartCacheManager {
  private cache = new Map<string, CacheEntry>()
  private dependencies = new Map<string, Set<string>>()

  constructor() {
    // 初始化缓存管理器
  }

  /**
   * 设置缓存
   */
  set(key: string, data: any, config: Partial<CacheConfig> = {}): void {
    const entry: CacheEntry = {
      data,
      timestamp: Date.now(),
      ttl: config.ttl || 5 * 60 * 1000, // 默认5分钟
      dependencies: config.dependencies || [],
      version: config.version || 1
    }

    this.cache.set(key, entry)
    this.updateDependencies(key, entry.dependencies)
    this.cleanup()
  }

  /**
   * 获取缓存
   */
  get<T = any>(key: string): T | null {
    const entry = this.cache.get(key)

    if (!entry) {
      return null
    }

    // 检查是否过期
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key)
      this.removeDependencies(key)
      return null
    }

    return entry.data as T
  }

  /**
   * 删除缓存
   */
  delete(key: string): boolean {
    const deleted = this.cache.delete(key)
    if (deleted) {
      this.removeDependencies(key)
    }
    return deleted
  }

  /**
   * 使依赖的缓存失效
   */
  invalidate(dependency: string): void {
    const dependents = this.dependencies.get(dependency)
    if (dependents) {
      for (const key of dependents) {
        this.cache.delete(key)
      }
      this.dependencies.delete(dependency)
    }
  }

  /**
   * 批量失效
   */
  invalidateMultiple(dependencies: string[]): void {
    dependencies.forEach(dep => this.invalidate(dep))
  }

  /**
   * 更新依赖关系
   */
  private updateDependencies(key: string, dependencies: string[]): void {
    // 移除旧的依赖关系
    this.removeDependencies(key)

    // 添加新的依赖关系
    dependencies.forEach(dep => {
      if (!this.dependencies.has(dep)) {
        this.dependencies.set(dep, new Set())
      }
      this.dependencies.get(dep)!.add(key)
    })
  }

  /**
   * 移除依赖关系
   */
  private removeDependencies(key: string): void {
    for (const [dep, keys] of this.dependencies.entries()) {
      keys.delete(key)
      if (keys.size === 0) {
        this.dependencies.delete(dep)
      }
    }
  }

  /**
   * 清理过期缓存
   */
  private cleanup(): void {
    const now = Date.now()
    const toDelete: string[] = []

    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp > entry.ttl) {
        toDelete.push(key)
      }
    }

    toDelete.forEach(key => this.delete(key))
  }

  /**
   * 获取缓存统计
   */
  getStats() {
    const totalSize = Array.from(this.cache.values())
      .reduce((sum, entry) => sum + JSON.stringify(entry.data).length, 0)

    return {
      totalKeys: this.cache.size,
      totalSize,
      dependencies: this.dependencies.size
    }
  }

  /**
   * 清空所有缓存
   */
  clear(): void {
    this.cache.clear()
    this.dependencies.clear()
  }
}

// 创建全局缓存实例
export const smartCache = new SmartCacheManager()

// 注意：CacheKeys、CacheDependencies 和 cacheInvalidation 已迁移到统一接口管理器
// 这些导出保留用于向后兼容，但建议使用统一接口管理器

export default smartCache