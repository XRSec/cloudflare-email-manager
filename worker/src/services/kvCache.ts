/**
 * Workers KV 缓存服务
 * 提供与前端一致的缓存接口
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
}

export class KVCacheService {
  private metrics: CacheMetrics = {
    hits: 0,
    misses: 0,
    errors: 0,
    totalKeys: 0
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
    SHORT: 300,      // 5分钟
    MEDIUM: 1800,    // 30分钟
    LONG: 7200,      // 2小时
    VERY_LONG: 86400 // 24小时
  } as const

  constructor(private kv: any) { }

  /**
   * 设置缓存
   */
  async set<T>(key: string, data: T, ttl: number = KVCacheService.TTL.MEDIUM): Promise<boolean> {
    try {
      const item: CacheItem<T> = {
        data,
        timestamp: Date.now(),
        ttl: ttl * 1000 // 转换为毫秒
      }

      const value = JSON.stringify(item)
      await this.kv.put(key, value, { expirationTtl: ttl })

      this.updateMetrics()
      return true
    } catch (error) {
      this.metrics.errors++
      console.error(`[KVCache] 设置缓存失败: ${key}`, error)
      return false
    }
  }

  /**
   * 获取缓存
   */
  async get<T>(key: string): Promise<T | null> {
    try {
      const value = await this.kv.get(key)
      if (!value) {
        this.metrics.misses++
        return null
      }

      const parsed: CacheItem<T> = JSON.parse(value)

      // 检查是否过期
      if (Date.now() - parsed.timestamp > parsed.ttl) {
        await this.kv.delete(key)
        this.metrics.misses++
        return null
      }

      this.metrics.hits++
      return parsed.data
    } catch (error) {
      this.metrics.errors++
      console.error(`[KVCache] 获取缓存失败: ${key}`, error)
      return null
    }
  }

  /**
   * 删除缓存
   */
  async delete(key: string): Promise<boolean> {
    try {
      await this.kv.delete(key)
      this.updateMetrics()
      return true
    } catch (error) {
      this.metrics.errors++
      console.error(`[KVCache] 删除缓存失败: ${key}`, error)
      return false
    }
  }

  /**
   * 批量获取
   */
  async mget<T>(keys: string[]): Promise<Record<string, T | null>> {
    const results: Record<string, T | null> = {}

    await Promise.all(
      keys.map(async (key) => {
        results[key] = await this.get<T>(key)
      })
    )

    return results
  }

  /**
   * 批量设置
   */
  async mset<T>(items: Array<{ key: string, data: T, ttl?: number }>): Promise<boolean> {
    try {
      await Promise.all(
        items.map(({ key, data, ttl }) => this.set(key, data, ttl))
      )
      return true
    } catch (error) {
      console.error('[KVCache] 批量设置缓存失败:', error)
      return false
    }
  }

  /**
   * 检查缓存是否存在
   */
  async exists(key: string): Promise<boolean> {
    const value = await this.kv.get(key)
    return value !== null
  }

  /**
   * 获取缓存信息
   */
  getCacheInfo() {
    this.updateMetrics()
    return {
      ...this.metrics,
      hitRate: this.metrics.hits / (this.metrics.hits + this.metrics.misses) || 0,
      lastUpdate: new Date().toISOString()
    }
  }

  /**
   * 更新指标
   */
  private updateMetrics() {
    // KV 无法直接获取键数量，这里使用估算
    this.metrics.totalKeys = this.metrics.hits + this.metrics.misses
  }

  // ==================== 业务方法 ====================

  /**
   * 获取系统配置
   */
  async getSystemConfig(): Promise<any> {
    return this.get(KVCacheService.KEYS.SYSTEM_CONFIG)
  }

  /**
   * 设置系统配置
   */
  async setSystemConfig(config: any): Promise<boolean> {
    return this.set(KVCacheService.KEYS.SYSTEM_CONFIG, config, 7200)
  }

  /**
   * 获取注册状态
   */
  async getRegistrationStatus(): Promise<boolean | null> {
    return this.get<boolean>(KVCacheService.KEYS.REGISTRATION_STATUS)
  }

  /**
   * 设置注册状态
   */
  async setRegistrationStatus(allowRegistration: boolean): Promise<boolean> {
    return this.set(KVCacheService.KEYS.REGISTRATION_STATUS, allowRegistration, KVCacheService.TTL.MEDIUM)
  }

  /**
   * 获取用户信息
   */
  async getUserInfo(userId: number): Promise<any> {
    return this.get(`user:${userId}`)
  }

  /**
   * 设置用户信息
   */
  async setUserInfo(userId: number, userInfo: any): Promise<boolean> {
    return this.set(`user:${userId}`, userInfo, KVCacheService.TTL.MEDIUM)
  }

  /**
   * 清理用户相关缓存
   */
  async clearUserCache(userId: number): Promise<boolean> {
    const keys = [
      `user:${userId}`,
      `user:${userId}:settings`,
      `user:${userId}:emails`,
      `user:${userId}:mailboxes`
    ]

    try {
      await Promise.all(keys.map(key => this.kv.delete(key)))
      return true
    } catch (error) {
      console.error('[KVCache] 清理用户缓存失败:', error)
      return false
    }
  }

  /**
   * 清理系统配置缓存
   */
  async clearSystemCache(): Promise<boolean> {
    const keys = [
      KVCacheService.KEYS.SYSTEM_CONFIG,
      KVCacheService.KEYS.REGISTRATION_STATUS,
      KVCacheService.KEYS.DEBUG_MODE
    ]

    try {
      await Promise.all(keys.map(key => this.kv.delete(key)))
      return true
    } catch (error) {
      console.error('[KVCache] 清理系统缓存失败:', error)
      return false
    }
  }

  /**
   * 清理所有缓存
   */
  async clearAll(): Promise<boolean> {
    try {
      // 注意：KV 没有批量删除所有键的方法
      // 这里只能删除已知的键
      const knownKeys = [
        KVCacheService.KEYS.SYSTEM_CONFIG,
        KVCacheService.KEYS.REGISTRATION_STATUS,
        KVCacheService.KEYS.DEBUG_MODE,
        KVCacheService.KEYS.USER_INFO,
        KVCacheService.KEYS.USER_SETTINGS,
        KVCacheService.KEYS.EMAIL_LIST,
        KVCacheService.KEYS.MAILBOX_LIST,
        KVCacheService.KEYS.FORWARD_RULES
      ]

      await Promise.all(knownKeys.map(key => this.kv.delete(key)))
      return true
    } catch (error) {
      console.error('[KVCache] 清理所有缓存失败:', error)
      return false
    }
  }
}

/**
 * 缓存策略服务
 * 结合 KV 缓存和数据库
 */
export class CacheStrategyService {
  constructor(
    private kvCache: KVCacheService,
    private db: D1Database
  ) { }

  /**
   * 获取系统配置（带缓存策略）
   */
  async getSystemConfig(): Promise<any> {
    // 1. 检查 KV 缓存
    let config = await this.kvCache.getSystemConfig()
    if (config) return config

    // 2. 从数据库获取
    const { getSystemConfig } = await import('./settings')
    config = await getSystemConfig(this.db)
    if (!config) return null

    // 3. 写入 KV 缓存
    await this.kvCache.setSystemConfig(config)

    return config
  }

  /**
   * 更新系统配置（带缓存失效）
   */
  async updateSystemConfig(newConfig: any): Promise<boolean> {
    try {
      // 1. 更新数据库
      const { setSystemSetting } = await import('./settings')
      await setSystemSetting(this.db, 'allow_registration', newConfig.allow_registration.toString())
      await setSystemSetting(this.db, 'debug_mode', newConfig.debug_mode.toString())
      // ... 其他配置项

      // 2. 更新 KV 缓存
      await this.kvCache.setSystemConfig(newConfig)

      return true
    } catch (error) {
      console.error('[CacheStrategy] 更新系统配置失败:', error)
      return false
    }
  }

  /**
   * 获取用户信息（带缓存策略）
   */
  async getUserInfo(userId: number): Promise<any> {
    // 1. 检查 KV 缓存
    let user = await this.kvCache.getUserInfo(userId)
    if (user) return user

    // 2. 从数据库获取
    const { findUserById } = await import('./user')
    const userResult = await findUserById(this.db, userId)
    if (!userResult) return null
    user = userResult

    // 3. 写入 KV 缓存
    await this.kvCache.setUserInfo(userId, user)

    return user
  }

  /**
   * 更新用户信息（带缓存失效）
   */
  async updateUserInfo(userId: number, userInfo: any): Promise<boolean> {
    try {
      // 1. 更新数据库
      // 注意：这里需要实现updateUser方法
      // const { updateUser } = await import('./user')
      // await updateUser(this.db, userId, userInfo)

      // 2. 更新 KV 缓存
      await this.kvCache.setUserInfo(userId, userInfo)

      return true
    } catch (error) {
      console.error('[CacheStrategy] 更新用户信息失败:', error)
      return false
    }
  }

  /**
   * 缓存失效策略
   */
  async invalidateUserCache(userId: number): Promise<void> {
    await this.kvCache.clearUserCache(userId)
  }

  async invalidateSystemCache(): Promise<void> {
    await this.kvCache.clearSystemCache()
  }
}
