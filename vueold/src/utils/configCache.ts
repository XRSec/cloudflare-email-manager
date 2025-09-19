/**
 * 配置缓存管理模块
 * 统一管理系统配置的缓存策略
 */

interface CacheItem<T> {
  data: T
  timestamp: number
  ttl: number
  version?: string // 配置版本号，用于检测更新
}

interface SystemConfig {
  allow_registration: boolean
  debug_mode: boolean
  domains: string[]
  max_attachment_size: number
  [key: string]: any
}

class ConfigCacheManager {
  private prefix = 'cem_config_'
  private defaultTTL = 30 * 60 * 1000 // 30分钟默认缓存
  private configVersion = '1.0.0' // 配置版本号

  // 缓存TTL配置
  private cacheTTL = {
    // 系统配置 - 30分钟，因为很少变更
    system_config: 30 * 60 * 1000,
    // 注册状态 - 10分钟，可能被管理员修改
    registration_status: 10 * 60 * 1000,
    // 用户信息 - 5分钟，相对稳定
    user_info: 5 * 60 * 1000,
    // 调试模式 - 15分钟，管理员可能修改
    debug_mode: 15 * 60 * 1000
  }

  /**
   * 设置缓存
   */
  set<T>(key: string, data: T, ttl?: number, version?: string): void {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      console.warn('[ConfigCache] SessionStorage 不可用')
      return
    }

    const cacheItem: CacheItem<T> = {
      data,
      timestamp: Date.now(),
      ttl: ttl || this.cacheTTL[key as keyof typeof this.cacheTTL] || this.defaultTTL,
      version: version || this.configVersion
    }

    try {
      const serialized = JSON.stringify(cacheItem)
      sessionStorage.setItem(this.prefix + key, serialized)
      console.log(`[ConfigCache] 缓存已设置: ${key}`)
    } catch (error) {
      console.error(`[ConfigCache] 设置缓存失败: ${key}`, error)
      if (error instanceof DOMException && error.name === 'QuotaExceededError') {
        this.cleanExpired()
        // 重试一次
        try {
          const retrySerialized = JSON.stringify(cacheItem)
          sessionStorage.setItem(this.prefix + key, retrySerialized)
        } catch (retryError) {
          console.error(`[ConfigCache] 重试设置缓存失败: ${key}`, retryError)
        }
      }
    }
  }

  /**
   * 获取缓存
   */
  get<T>(key: string): T | null {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      return null
    }

    try {
      const serialized = sessionStorage.getItem(this.prefix + key)
      if (!serialized) return null

      const item: CacheItem<T> = JSON.parse(serialized)

      // 检查是否过期
      if (Date.now() - item.timestamp > item.ttl) {
        this.delete(key)
        console.log(`[ConfigCache] 缓存已过期: ${key}`)
        return null
      }

      // 检查版本号（如果提供）
      if (item.version && item.version !== this.configVersion) {
        this.delete(key)
        console.log(`[ConfigCache] 缓存版本过期: ${key}`)
        return null
      }

      return item.data
    } catch (error) {
      console.error(`[ConfigCache] 获取缓存失败: ${key}`, error)
      this.delete(key)
      return null
    }
  }

  /**
   * 删除缓存
   */
  delete(key: string): void {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      return
    }
    sessionStorage.removeItem(this.prefix + key)
  }

  /**
   * 清理过期缓存
   */
  cleanExpired(): void {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      return
    }

    const keysToCheck: string[] = []
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i)
      if (key && key.startsWith(this.prefix)) {
        keysToCheck.push(key.substring(this.prefix.length))
      }
    }

    keysToCheck.forEach(key => {
      this.get(key) // get 方法会自动删除过期项
    })
  }

  /**
   * 清空所有配置缓存
   */
  clear(): void {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      return
    }

    const keysToRemove: string[] = []
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i)
      if (key && key.startsWith(this.prefix)) {
        keysToRemove.push(key)
      }
    }

    keysToRemove.forEach(key => sessionStorage.removeItem(key))
    console.log('[ConfigCache] 已清空所有配置缓存')
  }

  /**
   * 获取注册状态（带缓存）
   */
  async getRegistrationStatus(forceRefresh = false): Promise<boolean> {
    const cacheKey = 'registration_status'
    
    if (!forceRefresh) {
      const cached = this.get<{ allow_registration: boolean }>(cacheKey)
      if (cached) {
        console.log('[ConfigCache] 使用缓存的注册状态')
        return cached.allow_registration
      }
    }

    try {
      // 使用专门的注册状态API
      const response = await fetch('/api/system/registration-status')
      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          this.set(cacheKey, data.data)
          return data.data.allow_registration
        }
      }
    } catch (error) {
      console.error('[ConfigCache] 获取注册状态失败:', error)
    }

    // 降级到系统配置API
    try {
      const response = await fetch('/api/system/config')
      if (response.ok) {
        const data = await response.json()
        if (data.success && data.data.config) {
          const allowRegistration = data.data.config.allow_registration
          this.set(cacheKey, { allow_registration: allowRegistration })
          return allowRegistration
        }
      }
    } catch (error) {
      console.error('[ConfigCache] 获取系统配置失败:', error)
    }

    // 默认不允许注册
    return false
  }

  /**
   * 获取系统配置（带缓存）
   */
  async getSystemConfig(forceRefresh = false): Promise<SystemConfig | null> {
    const cacheKey = 'system_config'
    
    if (!forceRefresh) {
      const cached = this.get<SystemConfig>(cacheKey)
      if (cached) {
        console.log('[ConfigCache] 使用缓存的系统配置')
        return cached
      }
    }

    try {
      const response = await fetch('/api/system/config')
      if (response.ok) {
        const data = await response.json()
        if (data.success && data.data.config) {
          this.set(cacheKey, data.data.config)
          return data.data.config
        }
      }
    } catch (error) {
      console.error('[ConfigCache] 获取系统配置失败:', error)
    }

    return null
  }

  /**
   * 更新配置缓存（当配置变更时调用）
   */
  updateConfig(key: string, newData: any): void {
    this.set(key, newData)
    console.log(`[ConfigCache] 配置已更新: ${key}`)
  }

  /**
   * 检查缓存是否有效
   */
  isValid(key: string): boolean {
    const cached = this.get(key)
    return cached !== null
  }

  /**
   * 获取缓存信息（用于调试）
   */
  getCacheInfo(): Record<string, any> {
    const info: Record<string, any> = {}
    
    if (typeof window === 'undefined' || !window.sessionStorage) {
      return info
    }

    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i)
      if (key && key.startsWith(this.prefix)) {
        const cacheKey = key.substring(this.prefix.length)
        const item = this.get(cacheKey)
        if (item) {
          info[cacheKey] = {
            hasData: true,
            timestamp: new Date().toISOString()
          }
        }
      }
    }

    return info
  }
}

// 导出单例实例
export const configCache = new ConfigCacheManager()

// 导出类型
export type { SystemConfig, CacheItem }
