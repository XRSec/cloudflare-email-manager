/**
 * 系统配置常量和默认值
 * 注意：这些是系统初始化时的默认值，运行时应从数据库获取
 */

/**
 * 系统初始化默认配置
 * 这些值仅在系统首次初始化时使用
 */
export const SYSTEM_DEFAULTS = {
    // 用户相关
    ALLOW_REGISTRATION: false,
    
    // 邮件相关
    CLEANUP_DAYS: 7,                        // 邮件自动清理天数
    MAX_ATTACHMENT_SIZE: 52428800,          // 50MB
    
    // 认证相关
    COOKIE_MAX_AGE: 604800,                 // 7天（秒）
    JWT_EXPIRY: 86400,                      // 24小时（秒）
    
    // 域名相关
    PRIMARY_DOMAIN: '',                     // 必须配置，无默认值
    DOMAINS: [] as string[],                // 必须配置，无默认值
    
    // 管理员
    ADMIN_EMAIL: '',                        // 可选
    
    // 系统
    DEBUG_MODE: false,
    AUTO_APPROVE_MAILBOX: true,              // 自动审核邮箱申请
    
    // 分页
    DEFAULT_PAGE_SIZE: 20,
    MAX_PAGE_SIZE: 100,
    DEFAULT_PAGE: 1,
} as const;

/**
 * 配置验证规则
 */
export const CONFIG_VALIDATION = {
    CLEANUP_DAYS: {
        min: 1,
        max: 365,
        error: '清理天数必须在 1-365 之间'
    },
    MAX_ATTACHMENT_SIZE: {
        min: 1048576,      // 1MB
        max: 104857600,    // 100MB
        error: '附件大小必须在 1MB-100MB 之间'
    },
    COOKIE_MAX_AGE: {
        min: 3600,         // 1小时
        max: 2592000,      // 30天
        error: 'Cookie 过期时间必须在 1小时-30天之间'
    },
    PASSWORD_LENGTH: {
        min: 6,
        max: 128,
        error: '密码长度必须在 6-128 个字符之间'
    },
    PAGE: {
        min: 1,
        max: 10000,
        error: '页码必须在 1-10000 之间'
    },
    PAGE_SIZE: {
        min: 1,
        max: 100,
        error: '每页数量必须在 1-100 之间'
    }
} as const;

/**
 * 必需的配置项列表
 * 这些配置项必须在系统运行前设置
 */
export const REQUIRED_CONFIGS = [
    'allow_registration',
    'cleanup_days',
    'max_attachment_size',
    'cookie_max_age',
    'jwt_secret',
    'domains'  // 至少需要一个域名
] as const;

/**
 * 可选的配置项列表
 */
export const OPTIONAL_CONFIGS = [
    'admin_email',
    'debug_mode',
    'primary_domain'  // 如果不设置，使用 domains[0]
] as const;

/**
 * 验证配置值
 */
export function validateConfigValue(key: string, value: any): { valid: boolean; error?: string } {
    switch (key) {
        case 'cleanup_days':
            const days = parseInt(value);
            if (isNaN(days) || days < CONFIG_VALIDATION.CLEANUP_DAYS.min || days > CONFIG_VALIDATION.CLEANUP_DAYS.max) {
                return { valid: false, error: CONFIG_VALIDATION.CLEANUP_DAYS.error };
            }
            break;
            
        case 'max_attachment_size':
            const size = parseInt(value);
            if (isNaN(size) || size < CONFIG_VALIDATION.MAX_ATTACHMENT_SIZE.min || size > CONFIG_VALIDATION.MAX_ATTACHMENT_SIZE.max) {
                return { valid: false, error: CONFIG_VALIDATION.MAX_ATTACHMENT_SIZE.error };
            }
            break;
            
        case 'cookie_max_age':
            const age = parseInt(value);
            if (isNaN(age) || age < CONFIG_VALIDATION.COOKIE_MAX_AGE.min || age > CONFIG_VALIDATION.COOKIE_MAX_AGE.max) {
                return { valid: false, error: CONFIG_VALIDATION.COOKIE_MAX_AGE.error };
            }
            break;
            
        case 'allow_registration':
        case 'debug_mode':
            if (value !== 'true' && value !== 'false') {
                return { valid: false, error: `${key} 必须是 true 或 false` };
            }
            break;
            
        case 'domains':
            try {
                const domains = JSON.parse(value);
                if (!Array.isArray(domains) || domains.length === 0) {
                    return { valid: false, error: '域名列表必须是非空数组' };
                }
                for (const domain of domains) {
                    if (typeof domain !== 'string' || !domain.includes('.')) {
                        return { valid: false, error: '域名格式无效' };
                    }
                }
            } catch (e) {
                return { valid: false, error: '域名列表必须是有效的 JSON 数组' };
            }
            break;
            
        case 'jwt_secret':
            if (!value || value.length < 32) {
                return { valid: false, error: 'JWT Secret 长度至少需要 32 个字符' };
            }
            break;
    }
    
    return { valid: true };
}

/**
 * 获取分页参数
 */
export function getPaginationParams(query: any): { page: number; limit: number } {
    let page = parseInt(query.page);
    let limit = parseInt(query.limit);
    
    // 验证页码
    if (isNaN(page) || page < CONFIG_VALIDATION.PAGE.min) {
        page = SYSTEM_DEFAULTS.DEFAULT_PAGE;
    } else if (page > CONFIG_VALIDATION.PAGE.max) {
        page = CONFIG_VALIDATION.PAGE.max;
    }
    
    // 验证每页数量
    if (isNaN(limit) || limit < CONFIG_VALIDATION.PAGE_SIZE.min) {
        limit = SYSTEM_DEFAULTS.DEFAULT_PAGE_SIZE;
    } else if (limit > CONFIG_VALIDATION.PAGE_SIZE.max) {
        limit = CONFIG_VALIDATION.PAGE_SIZE.max;
    }
    
    return { page, limit };
}

/**
 * 验证密码强度
 */
export function validatePassword(password: string): { valid: boolean; error?: string } {
    if (!password) {
        return { valid: false, error: '密码不能为空' };
    }
    
    if (password.length < CONFIG_VALIDATION.PASSWORD_LENGTH.min) {
        return { valid: false, error: `密码长度至少需要 ${CONFIG_VALIDATION.PASSWORD_LENGTH.min} 个字符` };
    }
    
    if (password.length > CONFIG_VALIDATION.PASSWORD_LENGTH.max) {
        return { valid: false, error: `密码长度不能超过 ${CONFIG_VALIDATION.PASSWORD_LENGTH.max} 个字符` };
    }
    
    return { valid: true };
}