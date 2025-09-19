/**
 * 统一缓存管理器
 * 提供前后端一致的缓存接口
 */

interface CacheItem<T> {
  data: T
  timestamp: number
  ttl: number
  version?: string
}

interface CacheMetrics {
  hits: number
  misses: number
  errors: number
  totalKeys: number
  memoryUsage: number
}

export class UnifiedCacheManager {
  private prefix = 'cem_'
  private defaultTTL = 30 * 60 * 1000 // 30分钟
  private metrics: CacheMetrics = {
    hits: 0,
    misses: 0,
    errors: 0,
    totalKeys: 0,
    memoryUsage: 0
  }

  // 缓存键常量
  static readonly KEYS = {
    SYSTEM_CONFIG: 'system:config',
    REGISTRATION_STATUS: 'system:registration',
    DEBUG_MODE: 'system:debug',
    USER_INFO: 'user:info',
    USER_SETTINGS: 'user:settings',
    EMAIL_LIST: 'emails:list',
    MAILBOX_LIST: 'mailboxes:list',
    FORWARD_RULES: 'rules:forward'
  } as const

  // TTL常量
  static readonly TTL = {
    SHORT: 5 * 60 * 1000,      // 5分钟
    MEDIUM: 30 * 60 * 1000,    // 30分钟
    LONG: 2 * 60 * 60 * 1000,  // 2小时
    VERY_LONG: 24 * 60 * 60 * 1000 // 24小时
  } as const

  /**
   * 设置缓存
   */
  set<T>(key: string, data: T, ttl = this.defaultTTL): boolean {
    try {
      const item: CacheItem<T> = {
        data,
        timestamp: Date.now(),
        ttl
      }

      const serialized = JSON.stringify(item)
      sessionStorage.setItem(this.prefix + key, serialized)

      this.updateMetrics()
      return true
    } catch (error) {
      this.metrics.errors++
      console.error(`[Cache] 设置缓存失败: ${key}`, error)

      // 如果存储空间不足，清理过期缓存
      if (error instanceof DOMException && error.name === 'QuotaExceededError') {
        this.cleanExpired()
        try {
          const retryItem: CacheItem<T> = {
            data,
            timestamp: Date.now(),
            ttl
          }
          sessionStorage.setItem(this.prefix + key, JSON.stringify(retryItem))
          return true
        } catch (retryError) {
          console.error(`[Cache] 重试设置缓存失败: ${key}`, retryError)
        }
      }

      return false
    }
  }

  /**
   * 获取缓存
   */
  get<T>(key: string): T | null {
    try {
      const item = sessionStorage.getItem(this.prefix + key)
      if (!item) {
        this.metrics.misses++
        return null
      }

      const parsed: CacheItem<T> = JSON.parse(item)

      // 检查是否过期
      if (Date.now() - parsed.timestamp > parsed.ttl) {
        this.delete(key)
        this.metrics.misses++
        return null
      }

      this.metrics.hits++
      return parsed.data
    } catch (error) {
      this.metrics.errors++
      console.error(`[Cache] 获取缓存失败: ${key}`, error)
      this.delete(key)
      return null
    }
  }

  /**
   * 删除缓存
   */
  delete(key: string): boolean {
    try {
      sessionStorage.removeItem(this.prefix + key)
      this.updateMetrics()
      return true
    } catch (error) {
      this.metrics.errors++
      console.error(`[Cache] 删除缓存失败: ${key}`, error)
      return false
    }
  }

  /**
   * 清空所有缓存
   */
  clear(): boolean {
    try {
      const keysToRemove: string[] = []
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i)
        if (key && key.startsWith(this.prefix)) {
          keysToRemove.push(key)
        }
      }

      keysToRemove.forEach(key => sessionStorage.removeItem(key))
      this.updateMetrics()
      return true
    } catch (error) {
      this.metrics.errors++
      console.error('[Cache] 清空缓存失败:', error)
      return false
    }
  }

  /**
   * 检查缓存是否有效
   */
  isValid(key: string): boolean {
    const item = sessionStorage.getItem(this.prefix + key)
    if (!item) return false

    try {
      const parsed: CacheItem<any> = JSON.parse(item)
      return Date.now() - parsed.timestamp <= parsed.ttl
    } catch {
      return false
    }
  }

  /**
   * 清理过期缓存
   */
  cleanExpired(): number {
    let cleanedCount = 0
    const keysToCheck: string[] = []

    // 收集所有缓存键
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i)
      if (key && key.startsWith(this.prefix)) {
        keysToCheck.push(key.substring(this.prefix.length))
      }
    }

    // 检查并清理过期项
    keysToCheck.forEach(key => {
      if (!this.isValid(key)) {
        this.delete(key)
        cleanedCount++
      }
    })

    this.updateMetrics()
    return cleanedCount
  }

  /**
   * 获取缓存信息
   */
  getCacheInfo() {
    this.updateMetrics()
    return {
      ...this.metrics,
      hitRate: this.metrics.hits / (this.metrics.hits + this.metrics.misses) || 0,
      lastCleanup: new Date().toISOString()
    }
  }

  /**
   * 更新指标
   */
  private updateMetrics() {
    this.metrics.totalKeys = 0
    this.metrics.memoryUsage = 0

    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i)
      if (key && key.startsWith(this.prefix)) {
        this.metrics.totalKeys++
        const value = sessionStorage.getItem(key)
        if (value) {
          this.metrics.memoryUsage += key.length + value.length
        }
      }
    }
  }

  // ==================== 业务方法 ====================

  /**
   * 获取系统配置（需要认证）
   */
  async getSystemConfig(): Promise<any> {
    const cached = this.get(UnifiedCacheManager.KEYS.SYSTEM_CONFIG)
    if (cached) return cached

    try {
      const response = await fetch('/api/system/config', {
        credentials: 'include'
      })
      if (response.ok) {
        const data = await response.json()
        if (data.success && data.data) {
          this.set(UnifiedCacheManager.KEYS.SYSTEM_CONFIG, data.data, UnifiedCacheManager.TTL.LONG)
          return data.data
        }
      }
    } catch (error) {
      console.error('[Cache] 获取系统配置失败:', error)
    }

    return null
  }

  /**
   * 获取系统健康状态（无需认证）
   * 包含系统状态、健康检查、配置信息
   */
  async getSystemHealth(): Promise<any> {
    const cached = this.get('system:health')
    if (cached) return cached

    try {
      const response = await fetch('/api/system/health')
      if (response.ok) {
        const data = await response.json()
        if (data.success && data.data) {
          this.set('system:health', data.data.health, UnifiedCacheManager.TTL.SHORT)
          return data.data.health
        }
      }
    } catch (error) {
      console.error('[Cache] 获取系统健康状态失败:', error)
    }

    return null
  }

  /**
   * 获取系统健康状态（简单版本）
   */
  async isSystemHealthy(): Promise<boolean> {
    const health = await this.getSystemHealth()
    return health?.status === 1
  }

  /**
   * 获取注册状态
   */
  async getRegistrationStatus(): Promise<boolean> {
    const cached = this.get<boolean>(UnifiedCacheManager.KEYS.REGISTRATION_STATUS)
    if (cached !== null) return cached

    try {
      const response = await fetch('/api/system/registration-status')
      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          const allowRegistration = data.data.allow_registration
          this.set(UnifiedCacheManager.KEYS.REGISTRATION_STATUS, allowRegistration, UnifiedCacheManager.TTL.MEDIUM)
          return allowRegistration
        }
      }
    } catch (error) {
      console.error('[Cache] 获取注册状态失败:', error)
    }

    return false
  }

  /**
   * 获取用户信息
   */
  async getUserInfo(): Promise<any> {
    const cached = this.get(UnifiedCacheManager.KEYS.USER_INFO)
    if (cached) return cached

    try {
      const response = await fetch('/api/users/me')
      if (response.ok) {
        const data = await response.json()
        if (data.success && data.data) {
          this.set(UnifiedCacheManager.KEYS.USER_INFO, data.data, UnifiedCacheManager.TTL.MEDIUM)
          return data.data
        }
      }
    } catch (error) {
      console.error('[Cache] 获取用户信息失败:', error)
    }

    return null
  }

  /**
   * 更新用户信息
   */
  updateUserInfo(userInfo: any): void {
    this.set(UnifiedCacheManager.KEYS.USER_INFO, userInfo, UnifiedCacheManager.TTL.MEDIUM)
  }

  /**
   * 清理用户相关缓存
   */
  clearUserCache(): void {
    this.delete(UnifiedCacheManager.KEYS.USER_INFO)
    this.delete(UnifiedCacheManager.KEYS.USER_SETTINGS)
    this.delete(UnifiedCacheManager.KEYS.EMAIL_LIST)
    this.delete(UnifiedCacheManager.KEYS.MAILBOX_LIST)
  }

  /**
   * 清理系统配置缓存
   */
  clearSystemCache(): void {
    this.delete(UnifiedCacheManager.KEYS.SYSTEM_CONFIG)
    this.delete(UnifiedCacheManager.KEYS.REGISTRATION_STATUS)
    this.delete(UnifiedCacheManager.KEYS.DEBUG_MODE)
  }

  /**
   * 刷新所有缓存
   */
  async refreshAll(): Promise<void> {
    this.clear()

    // 重新获取关键数据
    await Promise.all([
      this.getSystemConfig(),
      this.getRegistrationStatus(),
      this.getUserInfo()
    ])
  }
}

// 导出单例实例
export const unifiedCache = new UnifiedCacheManager()

// 自动清理过期缓存（每5分钟）
setInterval(() => {
  const cleaned = unifiedCache.cleanExpired()
  if (cleaned > 0) {
    console.log(`[Cache] 清理了 ${cleaned} 个过期缓存项`)
  }
}, 5 * 60 * 1000)
