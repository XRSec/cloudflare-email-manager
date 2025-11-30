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
        // 注意：所有配置项统一使用数字格式存储到数据库（开关配置：1=启用/开启，0=禁用/关闭）
        const defaultSettings = {
            'allow_registration': String(SYSTEM_DEFAULTS.ALLOW_REGISTRATION),
            'mail_retention_days': String(SYSTEM_DEFAULTS.MAIL_RETENTION_DAYS),
            'attachment_retention_days': String(SYSTEM_DEFAULTS.ATTACHMENT_RETENTION_DAYS),
            'max_attachment_size': String(SYSTEM_DEFAULTS.MAX_ATTACHMENT_SIZE),
            'cookie_max_age': String(SYSTEM_DEFAULTS.COOKIE_MAX_AGE),
            'debug_mode': String(SYSTEM_DEFAULTS.DEBUG_MODE),
            'api_rate_limit': String(SYSTEM_DEFAULTS.API_RATE_LIMIT),
            'api_rate_limit_max_requests': String(SYSTEM_DEFAULTS.API_RATE_LIMIT_MAX_REQUESTS),
            // 注意：supported_domains 需要用户配置，没有默认值
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
            const { debugLog } = await import('../utils/debug');
            debugLog('系统设置', '🔑 已生成新的安全 JWT Secret');
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
        const { debugLog } = await import('../utils/debug');
        debugLog('系统设置', '系统设置缓存已初始化');
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('系统设置', '初始化系统设置缓存失败:', error);
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
        const maxAttachmentSize = parseInt(getRequiredSetting('max_attachment_size'));
        const cookieMaxAge = parseInt(getRequiredSetting('cookie_max_age'));

        // 可选配置项
        const debugMode = parseInt(getOptionalSetting('debug_mode', String(SYSTEM_DEFAULTS.DEBUG_MODE))) === 1;
        const apiRateLimit = parseInt(getOptionalSetting('api_rate_limit', String(SYSTEM_DEFAULTS.API_RATE_LIMIT))) === 1;
        const apiRateLimitMaxRequests = parseInt(getOptionalSetting('api_rate_limit_max_requests', String(SYSTEM_DEFAULTS.API_RATE_LIMIT_MAX_REQUESTS)));

        // 邮件和附件保留天数
        const mailRetentionDays = parseInt(getRequiredSetting('mail_retention_days'));
        const attachmentRetentionDays = parseInt(getOptionalSetting('attachment_retention_days', String(mailRetentionDays)));

        // 获取域名列表
        let domains: string[] = [];
        const domainsStr = systemSettingsCache.get('supported_domains');
        if (domainsStr) {
            try {
                domains = JSON.parse(domainsStr);
            } catch (error) {
                const { errorLog } = await import('../utils/debug');
                errorLog('系统设置', '解析域名配置失败:', error);
            }
        }

        // 如果没有配置多域名，尝试单个域名（兼容旧数据）
        if (domains.length === 0) {
            const oldDomainsStr = systemSettingsCache.get('domains');
            if (oldDomainsStr) {
                try {
                    domains = JSON.parse(oldDomainsStr);
                } catch (error) {
                    const { errorLog } = await import('../utils/debug');
                    errorLog('系统设置', '解析旧域名配置失败:', error);
                }
            }
        }

        // 如果还是没有，尝试单个域名（兼容旧数据）
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

        return {
            allow_registration: allowRegistration ? 1 : 0,
            mail_retention_days: mailRetentionDays,
            attachment_retention_days: attachmentRetentionDays,
            attachment_max_size: maxAttachmentSize,
            debug_mode: debugMode ? 1 : 0,
            supported_domains: domains, // 必需字段
            cookie_max_age: cookieMaxAge,
            jwt_secret: maskedJWTSecret, // 显示前后各四位
            api_rate_limit: apiRateLimit ? 1 : 0,
            api_rate_limit_max_requests: apiRateLimitMaxRequests
        };
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('系统设置', '获取系统配置失败:', error);
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

    if (config.mail_retention_days !== undefined) {
        updates.push({ key: 'mail_retention_days', value: config.mail_retention_days.toString() });
    }

    if (config.attachment_retention_days !== undefined) {
        updates.push({ key: 'attachment_retention_days', value: config.attachment_retention_days.toString() });
    }

    if (config.attachment_max_size !== undefined) {
        updates.push({ key: 'max_attachment_size', value: config.attachment_max_size.toString() });
    }

    if (config.debug_mode !== undefined) {
        updates.push({ key: 'debug_mode', value: config.debug_mode.toString() });
    }

    if (config.api_rate_limit !== undefined) {
        updates.push({ key: 'api_rate_limit', value: config.api_rate_limit.toString() });
    }

    if (config.api_rate_limit_max_requests !== undefined) {
        updates.push({ key: 'api_rate_limit_max_requests', value: config.api_rate_limit_max_requests.toString() });
    }

    // 更新域名列表
    if (config.supported_domains !== undefined) {
        if (Array.isArray(config.supported_domains) && config.supported_domains.length > 0) {
            updates.push({ key: 'supported_domains', value: JSON.stringify(config.supported_domains) });
        }
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
            const { infoLog } = await import('../utils/debug');
            infoLog('系统设置', '🔑 自动生成新的 JWT 密钥');
        } else {
            // 非空则使用提供的值
            updates.push({ key: 'jwt_secret', value: config.jwt_secret });
            const { infoLog } = await import('../utils/debug');
            infoLog('系统设置', '🔑 使用提供的 JWT 密钥');
        }
    }

    // 默认 Webhook 配置

    // 批量更新
    for (const update of updates) {
        await setSystemSetting(db, update.key, update.value);
    }

    // 刷新系统设置缓存，确保后续读取使用最新值
    await refreshSystemSettings(db);
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
        const { debugLog } = await import('../utils/debug');
        debugLog('系统设置', '⚠️ JWT Secret 不存在或无效，生成新的密钥...');

        // 生成新的密钥
        jwtSecret = generateJWTSecret();

        // 保存到数据库和缓存
        await db.prepare(`
            INSERT OR REPLACE INTO system_settings (key, value, description, updated_at)
            VALUES ('jwt_secret', ?, 'JWT签名密钥（自动生成）', CURRENT_TIMESTAMP)
        `).bind(jwtSecret).run();

        systemSettingsCache.set('jwt_secret', jwtSecret);
        const { infoLog } = await import('../utils/debug');
        infoLog('系统设置', '✅ 新的 JWT Secret 已生成并保存');
    }

    return jwtSecret;
}

/**
 * 获取主域名（从数据库读取）
 */
/**
 * 获取主域名（使用 domains[0]）
 * @deprecated 直接使用 domains[0] 即可
 */
export async function getPrimaryDomain(db: D1Database): Promise<string> {
    await initializeSystemSettings(db);

    // 获取域名列表（优先使用 supported_domains，兼容旧数据 domains）
    const domainsStr = systemSettingsCache.get('supported_domains') || systemSettingsCache.get('domains');
    if (domainsStr) {
        try {
            const domains = JSON.parse(domainsStr);
            if (Array.isArray(domains) && domains.length > 0) {
                return domains[0];
            }
        } catch (error) {
            const { errorLog } = await import('../utils/debug');
            errorLog('系统设置', '解析域名列表失败:', error);
        }
    }

    // 尝试单个域名配置（兼容旧数据）
    const singleDomain = systemSettingsCache.get('domain');
    if (singleDomain) {
        return singleDomain;
    }

    throw new Error('未找到任何可用域名配置');
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

    // 查找匹配的域名（使用 supported_domains）
    const domains = config.supported_domains || [];
    const matchedDomain = domains.find(domain =>
        domain.toLowerCase() === emailDomain
    );

    return matchedDomain || null;
}
