/**
 * 系统设置服务
 */

import type { D1Database } from '@cloudflare/workers-types';
import type { SystemSetting, SystemConfig } from '../types';
import { generateJWTSecret, isValidJWTSecret } from '../utils/jwt-secret';
import { SYSTEM_DEFAULTS, validateConfigValue } from '../config/constants';

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

        // 设置默认值（仅用于初始化）
        const defaultSettings = {
            'allow_registration': String(SYSTEM_DEFAULTS.ALLOW_REGISTRATION ? 1 : 0),
            'cleanup_days': String(SYSTEM_DEFAULTS.CLEANUP_DAYS),
            'max_attachment_size': String(SYSTEM_DEFAULTS.MAX_ATTACHMENT_SIZE),
            'cookie_max_age': String(SYSTEM_DEFAULTS.COOKIE_MAX_AGE),
            'debug_mode': String(SYSTEM_DEFAULTS.DEBUG_MODE ? 1 : 0),
            'auto_approve_mailbox': String(SYSTEM_DEFAULTS.AUTO_APPROVE_MAILBOX ? 1 : 0),
            'admin_email': SYSTEM_DEFAULTS.ADMIN_EMAIL,
            // 注意：domains 和 primary_domain 需要用户配置，没有默认值
        };

        // 特殊处理 JWT Secret
        const existingJwtSecret = systemSettingsCache.get('jwt_secret');
        if (!existingJwtSecret || !isValidJWTSecret(existingJwtSecret)) {
            // 生成新的安全的 JWT Secret
            const newJwtSecret = generateJWTSecret();
            systemSettingsCache.set('jwt_secret', newJwtSecret);
            await db.prepare(`
                INSERT OR REPLACE INTO system_settings (key, value, description, updated_at)
                VALUES ('jwt_secret', ?, 'JWT签名密钥（自动生成）', CURRENT_TIMESTAMP)
            `).bind(newJwtSecret).run();
            console.log('🔑 已生成新的安全 JWT Secret');
        }

        // 处理其他设置
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
 * 批量更新系统设置缓存（不写入数据库）
 * 用于 health 接口等场景，避免重复查询
 */
export function updateSystemSettingsCache(updates: Record<string, string>): void {
    for (const [key, value] of Object.entries(updates)) {
        systemSettingsCache.set(key, value);
    }
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

    // 辅助函数：获取必需设置
    const getRequiredSetting = (key: string): string => {
        const value = systemSettingsCache.get(key);
        if (!value) {
            throw new Error(`系统设置 '${key}' 未配置或为空`);
        }
        return value;
    };

    // 辅助函数：获取可选设置
    const getOptionalSetting = (key: string, defaultValue: string): string => {
        return systemSettingsCache.get(key) || defaultValue;
    };

    try {
        // 必需配置项
        const allowRegistration = parseInt(getRequiredSetting('allow_registration')) === 1;
        const cleanupDays = parseInt(getRequiredSetting('cleanup_days'));
        const maxAttachmentSize = parseInt(getRequiredSetting('max_attachment_size'));
        const cookieMaxAge = parseInt(getRequiredSetting('cookie_max_age'));

        // 可选配置项
        const debugMode = parseInt(getOptionalSetting('debug_mode', '0')) === 1;
        const autoApproveMailbox = parseInt(getOptionalSetting('auto_approve_mailbox', '0')) === 1;
        const adminEmail = getOptionalSetting('admin_email', '');

        // 获取域名列表
        let domains: string[] = [];
        const domainsStr = systemSettingsCache.get('domains');
        if (domainsStr) {
            try {
                domains = JSON.parse(domainsStr);
            } catch (error) {
                console.error('解析域名配置失败:', error);
            }
        }

        // 如果没有配置多域名，尝试单个域名
        if (domains.length === 0) {
            const singleDomain = systemSettingsCache.get('domain');
            if (singleDomain) {
                domains = [singleDomain];
            } else {
                throw new Error('未配置任何域名');
            }
        }

        // 获取 JWT 密钥 - 必须存在且有效
        const jwtSecret = await getJWTSecret(db);
        const maskedJWTSecret = maskJWTSecret(jwtSecret);

        // 主域名
        const primaryDomain = getOptionalSetting('primary_domain', domains[0]);

        return {
            allow_registration: allowRegistration ? 1 : 0,
            cleanup_days: cleanupDays,
            max_attachment_size: maxAttachmentSize,
            attachment_max_size: maxAttachmentSize, // 兼容字段
            debug_mode: debugMode ? 1 : 0,
            auto_approve_mailbox: autoApproveMailbox ? 1 : 0,
            supported_domains: domains, // 必需字段
            domains, // 兼容字段
            mail_retention_days: cleanupDays, // 兼容字段
            cookie_max_age: cookieMaxAge,
            jwt_secret: maskedJWTSecret, // 显示前后各四位
            admin_email: adminEmail,
            primary_domain: primaryDomain
        };
    } catch (error) {
        console.error('获取系统配置失败:', error);
        throw error;
    }
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

    if (config.auto_approve_mailbox !== undefined) {
        updates.push({ key: 'auto_approve_mailbox', value: config.auto_approve_mailbox.toString() });
    }

    if (config.domains !== undefined) {
        updates.push({ key: 'domains', value: JSON.stringify(config.domains) });
    }

    if (config.cookie_max_age !== undefined) {
        updates.push({ key: 'cookie_max_age', value: config.cookie_max_age.toString() });
    }

    // JWT密钥处理：空字符串表示自动生成新密钥，非空则使用提供的值
    if (config.jwt_secret !== undefined) {
        if (config.jwt_secret === '') {
            // 空字符串表示自动生成新密钥
            const newSecret = generateJWTSecret();
            updates.push({ key: 'jwt_secret', value: newSecret });
            console.log('🔑 自动生成新的 JWT 密钥');
        } else {
            // 非空则使用提供的值
            updates.push({ key: 'jwt_secret', value: config.jwt_secret });
            console.log('🔑 使用提供的 JWT 密钥');
        }
    }

    if (config.admin_email !== undefined) {
        updates.push({ key: 'admin_email', value: config.admin_email });
    }

    if (config.primary_domain !== undefined) {
        updates.push({ key: 'primary_domain', value: config.primary_domain });
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
 * 掩码 JWT 密钥，只显示前后各四位
 */
function maskJWTSecret(secret: string): string {
    if (!secret || secret.length <= 8) {
        return '****';
    }

    const start = secret.substring(0, 4);
    const end = secret.substring(secret.length - 4);
    const middle = '*'.repeat(Math.max(4, secret.length - 8));

    return `${start}${middle}${end}`;
}

/**
 * 获取JWT密钥（从数据库读取）
 * 如果不存在或无效，将自动生成新的密钥
 */
export async function getJWTSecret(db: D1Database): Promise<string> {
    await initializeSystemSettings(db);

    let jwtSecret = systemSettingsCache.get('jwt_secret');

    // 检查密钥是否有效
    if (!jwtSecret || !isValidJWTSecret(jwtSecret)) {
        console.warn('⚠️ JWT Secret 不存在或无效，生成新的密钥...');

        // 生成新的密钥
        jwtSecret = generateJWTSecret();

        // 保存到数据库和缓存
        await db.prepare(`
            INSERT OR REPLACE INTO system_settings (key, value, description, updated_at)
            VALUES ('jwt_secret', ?, 'JWT签名密钥（自动生成）', CURRENT_TIMESTAMP)
        `).bind(jwtSecret).run();

        systemSettingsCache.set('jwt_secret', jwtSecret);
        console.log('✅ 新的 JWT Secret 已生成并保存');
    }

    return jwtSecret;
}

/**
 * 获取主域名（从数据库读取）
 */
export async function getPrimaryDomain(db: D1Database): Promise<string> {
    await initializeSystemSettings(db);

    const primaryDomain = systemSettingsCache.get('primary_domain');
    if (!primaryDomain) {
        // 尝试获取第一个域名
        const domainsStr = systemSettingsCache.get('domains');
        if (domainsStr) {
            try {
                const domains = JSON.parse(domainsStr);
                if (Array.isArray(domains) && domains.length > 0) {
                    return domains[0];
                }
            } catch (error) {
                console.error('解析域名列表失败:', error);
            }
        }

        // 尝试单个域名配置
        const singleDomain = systemSettingsCache.get('domain');
        if (singleDomain) {
            return singleDomain;
        }

        throw new Error('未找到任何可用域名配置');
    }

    return primaryDomain;
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
    const matchedDomain = config.domains?.find(domain =>
        domain.toLowerCase() === emailDomain
    );

    return matchedDomain || null;
}
