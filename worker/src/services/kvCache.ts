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
    EMAIL_LIST: 'emails:list',
    EMAIL_DETAIL: 'emails:detail:',
    ATTACHMENT: 'attachment:',        // 附件缓存前缀
    EMAIL_RAW: 'email:raw:',          // 原始邮件缓存前缀
    DASHBOARD_STATS: 'dashboard:stats', // 仪表板统计数据
    EMAIL_COUNT: 'stats:email_count',   // 邮件数量
    R2_FILE_COUNT: 'stats:r2_file_count', // R2文件数量
    FORWARD_LOGS: 'forward_logs:',    // 转发日志缓存前缀
  } as const

  // TTL常量
  static readonly TTL = {
    SHORT: 300,        // 5分钟
    MEDIUM: 1800,      // 30分钟
    LONG: 7200,        // 2小时
    VERY_LONG: 86400,  // 24小时
    IMMUTABLE: 604800  // 7天（不可变资源，如附件）
  } as const

  // 附件缓存配置
  static readonly ATTACHMENT_CONFIG = {
    MAX_SIZE: 1024 * 1024,  // 只缓存 < 1MB 的附件（避免占用太多 KV 存储）
    TTL: 604800              // 7天（附件内容不会变）
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
      const { errorLog } = await import('../utils/debug');
      errorLog('KVCache', `设置缓存失败: ${key}`, error);
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
      const { errorLog } = await import('../utils/debug');
      errorLog('KVCache', `获取缓存失败: ${key}`, error);
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
      const { errorLog } = await import('../utils/debug');
      errorLog('KVCache', `删除缓存失败: ${key}`, error);
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
      const { errorLog } = await import('../utils/debug');
      errorLog('KVCache', '批量设置缓存失败:', error);
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
   * 清理系统配置缓存
   */
  async clearSystemCache(): Promise<boolean> {
    const keys = [
      KVCacheService.KEYS.SYSTEM_CONFIG
    ]

    try {
      await Promise.all(keys.map(key => this.kv.delete(key)))
      return true
    } catch (error) {
      const { errorLog } = await import('../utils/debug');
      errorLog('KVCache', '清理系统缓存失败:', error);
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
        KVCacheService.KEYS.EMAIL_LIST
      ]

      await Promise.all(knownKeys.map(key => this.kv.delete(key)))
      return true
    } catch (error) {
      const { errorLog } = await import('../utils/debug');
      errorLog('KVCache', '清理所有缓存失败:', error);
      return false
    }
  }

  /**
   * 缓存二进制数据（用于附件缓存）
   * @param key 缓存键
   * @param data 二进制数据
   * @param metadata 元数据（contentType、size等）
   * @param ttl 过期时间（秒）
   */
  async setBinary(
    key: string,
    data: ArrayBuffer | ReadableStream,
    metadata?: Record<string, string>,
    ttl: number = KVCacheService.ATTACHMENT_CONFIG.TTL
  ): Promise<boolean> {
    try {
      // 如果是 ReadableStream，需要先转换为 ArrayBuffer
      let buffer: ArrayBuffer;
      if (data instanceof ReadableStream) {
        const response = new Response(data);
        buffer = await response.arrayBuffer();
      } else {
        buffer = data;
      }

      // 检查大小限制（只缓存小于 1MB 的附件）
      if (buffer.byteLength > KVCacheService.ATTACHMENT_CONFIG.MAX_SIZE) {
        const { debugLog } = await import('../utils/debug');
        debugLog('KVCache', `附件过大，不缓存: ${key} (${buffer.byteLength} bytes)`);
        return false;
      }

      // 存储到 KV（使用 arrayBuffer 类型）
      await this.kv.put(key, buffer, {
        expirationTtl: ttl,
        metadata: {
          ...metadata,
          timestamp: Date.now().toString(),
          size: buffer.byteLength.toString()
        }
      });

      this.updateMetrics();
      const { debugLog } = await import('../utils/debug');
      debugLog('KVCache', `缓存附件成功: ${key} (${buffer.byteLength} bytes, TTL: ${ttl}s)`);
      return true;
    } catch (error) {
      this.metrics.errors++;
      const { errorLog } = await import('../utils/debug');
      errorLog('KVCache', `缓存附件失败: ${key}`, error);
      return false;
    }
  }

  /**
   * 获取二进制数据（用于附件缓存）
   * @param key 缓存键
   * @returns 二进制数据和元数据
   */
  async getBinary(key: string): Promise<{ data: ArrayBuffer, metadata: Record<string, string> } | null> {
    try {
      const result = await this.kv.getWithMetadata(key, 'arrayBuffer');

      if (!result.value || !result.metadata) {
        this.metrics.misses++;
        return null;
      }

      this.metrics.hits++;
      const { debugLog } = await import('../utils/debug');
      debugLog('KVCache', `从缓存读取附件: ${key}`);

      return {
        data: result.value as ArrayBuffer,
        metadata: result.metadata as Record<string, string>
      };
    } catch (error) {
      this.metrics.errors++;
      const { errorLog } = await import('../utils/debug');
      errorLog('KVCache', `读取缓存附件失败: ${key}`, error);
      return null;
    }
  }

  /**
   * 获取附件缓存键
   */
  static getAttachmentKey(attachmentId: string): string {
    return `${KVCacheService.KEYS.ATTACHMENT}${attachmentId}`;
  }

  /**
   * 获取原始邮件缓存键
   */
  static getEmailRawKey(emailId: string): string {
    return `${KVCacheService.KEYS.EMAIL_RAW}${emailId}`;
  }

  /**
   * 获取仪表板统计数据
   */
  async getDashboardStats(): Promise<any> {
    return this.get(KVCacheService.KEYS.DASHBOARD_STATS)
  }

  /**
   * 设置仪表板统计数据
   */
  async setDashboardStats(stats: any): Promise<boolean> {
    return this.set(KVCacheService.KEYS.DASHBOARD_STATS, stats, KVCacheService.TTL.SHORT)
  }

  /**
   * 获取邮件数量
   */
  async getEmailCount(): Promise<number | null> {
    return this.get<number>(KVCacheService.KEYS.EMAIL_COUNT)
  }

  /**
   * 设置邮件数量
   */
  async setEmailCount(count: number): Promise<boolean> {
    return this.set(KVCacheService.KEYS.EMAIL_COUNT, count, KVCacheService.TTL.SHORT)
  }

  /**
   * 获取 R2 文件数量
   */
  async getR2FileCount(): Promise<number | null> {
    return this.get<number>(KVCacheService.KEYS.R2_FILE_COUNT)
  }

  /**
   * 设置 R2 文件数量
   */
  async setR2FileCount(count: number): Promise<boolean> {
    return this.set(KVCacheService.KEYS.R2_FILE_COUNT, count, KVCacheService.TTL.SHORT)
  }

  /**
   * 清理仪表板缓存
   */
  async clearDashboardCache(): Promise<boolean> {
    const keys = [
      KVCacheService.KEYS.DASHBOARD_STATS,
      KVCacheService.KEYS.EMAIL_COUNT,
      KVCacheService.KEYS.R2_FILE_COUNT
    ]

    try {
      await Promise.all(keys.map(key => this.kv.delete(key)))
      return true
    } catch (error) {
      const { errorLog } = await import('../utils/debug');
      errorLog('KVCache', '清理仪表板缓存失败:', error);
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
      const { errorLog } = await import('../utils/debug');
      errorLog('CacheStrategy', '更新系统配置失败:', error);
      return false
    }
  }

  /**
   * 缓存失效策略
   */
  async invalidateSystemCache(): Promise<void> {
    await this.kvCache.clearSystemCache()
  }
}
