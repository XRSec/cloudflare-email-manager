/**
 * 系统设置服务
 */

import type { D1Database } from '@cloudflare/workers-types';
import type { SystemSetting, SystemConfig } from '../types';

// 系统设置缓存
let systemSettingsCache: Map<string, string> = new Map();
let cacheInitialized = false;

/**
 * 初始化系统设置缓存
 */
export async function initializeSystemSettings(db: D1Database): Promise<void> {
    if (cacheInitialized) return;

    try {
        const settings = await db.prepare(`
            SELECT key, value
            FROM system_settings
        `).all();

        systemSettingsCache.clear();
        for (const setting of settings.results) {
            systemSettingsCache.set(setting.key as string, setting.value as string);
        }

        // 设置默认值
        const defaultSettings = {
            'allow_registration': 'false',
            'cleanup_days': '7',
            'max_attachment_size': '52428800',
            'cookie_max_age': '604800', // 7天
            'jwt_secret': 'your-jwt-secret-change-this-in-production',
            'primary_domain': 'example.com',
            'admin_email': '',
            'domains': '["example.com"]', // JSON 数组格式存储多个域名
            'debug_mode': 'false'
        };

        for (const [key, defaultValue] of Object.entries(defaultSettings)) {
            if (!systemSettingsCache.has(key)) {
                systemSettingsCache.set(key, defaultValue);
                await db.prepare(`
                    INSERT OR IGNORE INTO system_settings (key, value, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                `).bind(key, defaultValue).run();
            }
        }

        cacheInitialized = true;
        console.log('系统设置缓存已初始化');
    } catch (error) {
        console.error('初始化系统设置缓存失败:', error);
    }
}

/**
 * 获取系统设置
 */
export async function getSystemSetting(db: D1Database, key: string): Promise<string | null> {
    // 确保缓存已初始化
    await initializeSystemSettings(db);

    return systemSettingsCache.get(key) || null;
}

/**
 * 设置系统设置
 */
export async function setSystemSetting(db: D1Database, key: string, value: string): Promise<void> {
    await db.prepare(`
        INSERT OR REPLACE INTO system_settings (key, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    `).bind(key, value).run();

    // 更新缓存
    systemSettingsCache.set(key, value);
}

/**
 * 刷新系统设置缓存
 */
export async function refreshSystemSettings(db: D1Database): Promise<void> {
    cacheInitialized = false;
    await initializeSystemSettings(db);
}

/**
 * 获取系统配置（结构化）
 */
export async function getSystemConfig(db: D1Database): Promise<SystemConfig> {
    await initializeSystemSettings(db);

    const allowRegistration = systemSettingsCache.get('allow_registration') === 'true';
    const cleanupDays = parseInt(systemSettingsCache.get('cleanup_days') || '7');
    const maxAttachmentSize = parseInt(systemSettingsCache.get('max_attachment_size') || '52428800');
    const debugMode = systemSettingsCache.get('debug_mode') === 'true';
    const cookieMaxAge = parseInt(systemSettingsCache.get('cookie_max_age') || '604800');

    let domains: string[] = [];
    try {
        const domainsStr = systemSettingsCache.get('domains') || '[]';
        domains = JSON.parse(domainsStr);
    } catch (error) {
        console.error('解析域名配置失败:', error);
        domains = [];
    }

    // 如果没有配置多域名，使用单个域名配置
    if (domains.length === 0) {
        const singleDomain = systemSettingsCache.get('domain');
        if (singleDomain) {
            domains = [singleDomain];
        }
    }

    return {
        allow_registration: allowRegistration,
        cleanup_days: cleanupDays,
        max_attachment_size: maxAttachmentSize,
        debug_mode: debugMode,
        domains,
        cookie_max_age: cookieMaxAge
    };
}

/**
 * 更新系统配置
 */
export async function updateSystemConfig(db: D1Database, config: Partial<SystemConfig>): Promise<void> {
    const updates: Array<{ key: string; value: string }> = [];

    if (config.allow_registration !== undefined) {
        updates.push({ key: 'allow_registration', value: config.allow_registration.toString() });
    }

    if (config.cleanup_days !== undefined) {
        updates.push({ key: 'cleanup_days', value: config.cleanup_days.toString() });
    }

    if (config.max_attachment_size !== undefined) {
        updates.push({ key: 'max_attachment_size', value: config.max_attachment_size.toString() });
    }

    if (config.debug_mode !== undefined) {
        updates.push({ key: 'debug_mode', value: config.debug_mode.toString() });
    }

    if (config.domains !== undefined) {
        updates.push({ key: 'domains', value: JSON.stringify(config.domains) });
    }

    if (config.cookie_max_age !== undefined) {
        updates.push({ key: 'cookie_max_age', value: config.cookie_max_age.toString() });
    }

    // 批量更新
    for (const update of updates) {
        await setSystemSetting(db, update.key, update.value);
    }
}

/**
 * 获取所有系统设置
 */
export async function getAllSystemSettings(db: D1Database): Promise<SystemSetting[]> {
    const result = await db.prepare(`
        SELECT key, value, description, created_at, updated_at
        FROM system_settings
        ORDER BY key
    `).all();

    return result.results.map(row => ({
        key: row.key as string,
        value: row.value as string,
        description: row.description as string | undefined,
        created_at: row.created_at as string | undefined,
        updated_at: row.updated_at as string | undefined,
    }));
}

/**
 * 获取JWT密钥（从数据库读取）
 */
export async function getJWTSecret(db: D1Database): Promise<string> {
    await initializeSystemSettings(db);
    return systemSettingsCache.get('jwt_secret') || 'your-jwt-secret-change-this-in-production';
}

/**
 * 获取主域名（从数据库读取）
 */
export async function getPrimaryDomain(db: D1Database): Promise<string> {
    await initializeSystemSettings(db);
    return systemSettingsCache.get('primary_domain') || 'example.com';
}

/**
 * 根据邮件地址自动匹配域名
 */
export async function matchDomainForEmail(db: D1Database, emailAddress: string): Promise<string | null> {
    const config = await getSystemConfig(db);
    const emailDomain = emailAddress.split('@')[1]?.toLowerCase();

    if (!emailDomain) {
        return null;
    }

    // 查找匹配的域名
    const matchedDomain = config.domains.find(domain =>
        domain.toLowerCase() === emailDomain
    );

    return matchedDomain || null;
}
