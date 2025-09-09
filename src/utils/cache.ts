/**
 * 全局缓存管理系统
 * 用于缓存系统配置、用户信息等
 */

interface CacheItem<T> {
    data: T;
    timestamp: number;
    ttl: number; // Time to live in milliseconds
}

class GlobalCache {
    private cache: Map<string, CacheItem<any>> = new Map();
    private defaultTTL = 5 * 60 * 1000; // 默认5分钟

    /**
     * 设置缓存
     */
    set<T>(key: string, data: T, ttl?: number): void {
        this.cache.set(key, {
            data,
            timestamp: Date.now(),
            ttl: ttl || this.defaultTTL
        });
    }

    /**
     * 获取缓存
     */
    get<T>(key: string): T | null {
        const item = this.cache.get(key);
        
        if (!item) {
            return null;
        }

        // 检查是否过期
        if (Date.now() - item.timestamp > item.ttl) {
            this.cache.delete(key);
            return null;
        }

        return item.data as T;
    }

    /**
     * 删除特定缓存
     */
    delete(key: string): void {
        this.cache.delete(key);
    }

    /**
     * 清空所有缓存
     */
    clear(): void {
        this.cache.clear();
        console.log('[Cache] 所有缓存已清空');
    }

    /**
     * 刷新特定缓存（删除以便下次重新获取）
     */
    refresh(key: string): void {
        this.cache.delete(key);
        console.log(`[Cache] 缓存已刷新: ${key}`);
    }

    /**
     * 获取所有缓存键
     */
    keys(): string[] {
        return Array.from(this.cache.keys());
    }

    /**
     * 检查缓存是否存在且有效
     */
    has(key: string): boolean {
        const item = this.cache.get(key);
        if (!item) return false;
        
        if (Date.now() - item.timestamp > item.ttl) {
            this.cache.delete(key);
            return false;
        }
        
        return true;
    }
}

// 导出全局缓存实例
export const cache = new GlobalCache();

// 缓存键常量
export const CACHE_KEYS = {
    SYSTEM_CONFIG: 'system_config',
    USER_INFO: 'user_info',
    DEBUG_MODE: 'debug_mode',
    ALLOW_REGISTRATION: 'allow_registration',
    DOMAINS: 'domains',
    EMAIL_LIST: 'email_list',
    ADMIN_USERS: 'admin_users',
    FORWARD_RULES: 'forward_rules'
};

// 缓存TTL配置（毫秒）
export const CACHE_TTL = {
    SHORT: 60 * 1000,           // 1分钟
    MEDIUM: 5 * 60 * 1000,       // 5分钟
    LONG: 30 * 60 * 1000,        // 30分钟
    VERY_LONG: 60 * 60 * 1000    // 1小时
};