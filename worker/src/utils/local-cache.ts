/**
 * LocalStorage 缓存管理系统
 * 用于在浏览器中持久化缓存系统配置、用户信息等数据
 * 数据会持久化存储，不会在标签页关闭后清除
 */

// 类型定义（兼容 Worker 环境）
interface StorageItem {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
    clear(): void;
    length: number;
    key(index: number): string | null;
}

// 使用 any 类型来避免 TypeScript 错误，因为这些代码会在浏览器中运行
declare const window: any;
declare const localStorage: StorageItem;

interface CacheItem<T> {
    data: T;
    timestamp: number;
    ttl: number; // Time to live in milliseconds
}

class LocalStorageCache {
    private prefix = 'cem_cache_'; // 缓存键前缀，避免与其他应用冲突
    private defaultTTL = 5 * 60 * 1000; // 默认5分钟

    /**
     * 设置缓存
     * 自动将数据序列化为 JSON 字符串
     */
    set<T>(key: string, data: T, ttl?: number): void {
        if (typeof window === 'undefined' || !window.localStorage) {
            console.warn('[LocalCache] LocalStorage 不可用');
            return;
        }

        const cacheItem: CacheItem<T> = {
            data,
            timestamp: Date.now(),
            ttl: ttl || this.defaultTTL
        };

        try {
            const serialized = JSON.stringify(cacheItem);
            localStorage.setItem(this.prefix + key, serialized);
            console.log(`[LocalCache] 缓存已设置: ${key}`);
        } catch (error) {
            console.error(`[LocalCache] 设置缓存失败: ${key}`, error);
            // 如果是配额超出错误，尝试清理过期缓存
            if (error instanceof DOMException && error.name === 'QuotaExceededError') {
                this.cleanExpired();
                // 重试一次
                try {
                    const serialized = JSON.stringify(cacheItem);
                    localStorage.setItem(this.prefix + key, serialized);
                } catch (retryError) {
                    console.error(`[LocalCache] 重试设置缓存失败: ${key}`, retryError);
                }
            }
        }
    }

    /**
     * 获取缓存
     * 自动反序列化 JSON 字符串
     */
    get<T>(key: string): T | null {
        if (typeof window === 'undefined' || !window.localStorage) {
            return null;
        }

        try {
            const serialized = localStorage.getItem(this.prefix + key);
            if (!serialized) {
                return null;
            }

            const item: CacheItem<T> = JSON.parse(serialized);
            
            // 检查是否过期
            if (Date.now() - item.timestamp > item.ttl) {
                this.delete(key);
                console.log(`[LocalCache] 缓存已过期并删除: ${key}`);
                return null;
            }

            return item.data;
        } catch (error) {
            console.error(`[LocalCache] 获取缓存失败: ${key}`, error);
            // 如果解析失败，删除损坏的缓存项
            this.delete(key);
            return null;
        }
    }

    /**
     * 删除特定缓存
     */
    delete(key: string): void {
        if (typeof window === 'undefined' || !window.localStorage) {
            return;
        }

        localStorage.removeItem(this.prefix + key);
        console.log(`[LocalCache] 缓存已删除: ${key}`);
    }

    /**
     * 清空所有缓存
     * 只清空带有前缀的缓存项
     */
    clear(): void {
        if (typeof window === 'undefined' || !window.localStorage) {
            return;
        }

        const keysToRemove: string[] = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(this.prefix)) {
                keysToRemove.push(key);
            }
        }

        keysToRemove.forEach(key => localStorage.removeItem(key));
        console.log(`[LocalCache] 已清空 ${keysToRemove.length} 个缓存项`);
    }

    /**
     * 刷新特定缓存（删除以便下次重新获取）
     */
    refresh(key: string): void {
        this.delete(key);
        console.log(`[LocalCache] 缓存已刷新: ${key}`);
    }

    /**
     * 获取所有缓存键（不包含前缀）
     */
    keys(): string[] {
        if (typeof window === 'undefined' || !window.localStorage) {
            return [];
        }

        const keys: string[] = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(this.prefix)) {
                keys.push(key.substring(this.prefix.length));
            }
        }
        return keys;
    }

    /**
     * 检查缓存是否存在且有效
     */
    has(key: string): boolean {
        const item = this.get(key);
        return item !== null;
    }

    /**
     * 清理所有过期的缓存项
     */
    cleanExpired(): void {
        if (typeof window === 'undefined' || !window.localStorage) {
            return;
        }

        const keysToCheck: string[] = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(this.prefix)) {
                keysToCheck.push(key.substring(this.prefix.length));
            }
        }

        let cleanedCount = 0;
        keysToCheck.forEach(key => {
            // get 方法会自动删除过期项
            const value = this.get(key);
            if (value === null) {
                cleanedCount++;
            }
        });

        if (cleanedCount > 0) {
            console.log(`[LocalCache] 清理了 ${cleanedCount} 个过期缓存项`);
        }
    }

    /**
     * 获取缓存大小（字节）
     */
    getSize(): number {
        if (typeof window === 'undefined' || !window.localStorage) {
            return 0;
        }

        let size = 0;
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(this.prefix)) {
                const value = localStorage.getItem(key);
                if (value) {
                    size += key.length + value.length;
                }
            }
        }
        return size * 2; // 字符串在 JavaScript 中使用 UTF-16，每个字符 2 字节
    }

    /**
     * 获取缓存统计信息
     */
    getStats(): { count: number; size: number; sizeInKB: number; keys: string[] } {
        const keys = this.keys();
        const size = this.getSize();
        
        return {
            count: keys.length,
            size: size,
            sizeInKB: Math.round(size / 1024 * 100) / 100,
            keys: keys
        };
    }
}

// 导出全局 localStorage 缓存实例
export const localCache = new LocalStorageCache();

// 缓存键常量
export const LOCAL_CACHE_KEYS = {
    SYSTEM_CONFIG: 'system_config',
    USER_INFO: 'user_info',
    DEBUG_MODE: 'debug_mode',
    ALLOW_REGISTRATION: 'allow_registration',
    DOMAINS: 'domains',
    EMAIL_LIST: 'email_list',
    ADMIN_USERS: 'admin_users',
    FORWARD_RULES: 'forward_rules',
    CURRENT_PAGE: 'current_page',
    FILTER_SETTINGS: 'filter_settings',
    SORT_SETTINGS: 'sort_settings'
};

// 缓存TTL配置（毫秒）
export const CACHE_TTL = {
    SHORT: 60 * 1000,           // 1分钟
    MEDIUM: 5 * 60 * 1000,       // 5分钟
    LONG: 30 * 60 * 1000,        // 30分钟
    VERY_LONG: 60 * 60 * 1000    // 1小时
};

// 用于持久化存储的 localStorage 管理器（仅用于 token 等需要持久化的数据）
export class PersistentStorage {
    private prefix = 'cem_persist_';

    setToken(token: string): void {
        if (typeof window !== 'undefined' && window.localStorage) {
            localStorage.setItem(this.prefix + 'token', token);
        }
    }

    getToken(): string | null {
        if (typeof window === 'undefined' || !window.localStorage) {
            return null;
        }
        return localStorage.getItem(this.prefix + 'token');
    }

    removeToken(): void {
        if (typeof window !== 'undefined' && window.localStorage) {
            localStorage.removeItem(this.prefix + 'token');
        }
    }

    clear(): void {
        if (typeof window !== 'undefined' && window.localStorage) {
            const keysToRemove: string[] = [];
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && key.startsWith(this.prefix)) {
                    keysToRemove.push(key);
                }
            }
            keysToRemove.forEach(key => localStorage.removeItem(key));
        }
    }
}

export const persistentStorage = new PersistentStorage();