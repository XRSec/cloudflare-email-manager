/**
 * 共享常量定义
 * 前后端通用的常量
 */

/**
 * 系统配置常量
 */
export const SYSTEM_CONFIG = {
    // 调试模式
    DEBUG_MODE: 'debug_mode',

    // 用户注册
    ALLOW_REGISTRATION: 'allow_registration',

    // 邮件配置
    MAX_ATTACHMENT_SIZE: 'max_attachment_size',
    DOMAINS: 'domains',

    // 默认值
    DEFAULT_MAX_ATTACHMENT_SIZE: 50 * 1024 * 1024, // 50MB
    DEFAULT_DOMAINS: ['example.com']
} as const;

/**
 * 用户类型
 */
export const USER_TYPES = {
    USER: 'user',
    ADMIN: 'admin'
} as const;

/**
 * 邮件状态
 */
export const EMAIL_STATUS = {
    RECEIVED: 'received',
    PROCESSED: 'processed',
    FORWARDED: 'forwarded',
    FAILED: 'failed'
} as const;

export const WEBHOOK_STATUS = {
    SUCCESS: 0,
    FAILED: 1
} as const;

/**
 * 转发规则类型
 */
export const FORWARD_RULE_TYPES = {
    EMAIL: 'email',
    WEBHOOK: 'webhook'
} as const;

/**
 * API端点
 */
export const API_ENDPOINTS = {
    // 认证
    LOGIN: '/api/auth/login',
    LOGOUT: '/api/auth/logout',
    REGISTER: '/api/auth/register',

    // 用户
    USER_PROFILE: '/api/user/profile',
    USER_UPDATE: '/api/user/update',

    // 邮件
    EMAILS: '/api/emails',
    EMAIL_DETAIL: '/api/emails/:id',
    EMAIL_DELETE: '/api/emails/:id',
    EMAIL_ATTACHMENT: '/api/emails/:id/attachments/:attachmentId',

    // 系统
    SYSTEM_CONFIG: '/api/system/config',
    SYSTEM_UPDATE: '/api/system/update',

    // 管理员
    ADMIN_USERS: '/api/admin/users',
    ADMIN_RULES: '/api/admin/rules',
    ADMIN_EMAILS: '/api/admin/emails',
    ADMIN_SETTINGS: '/api/admin/settings',

    // 调试
    DEBUG_SIMULATE: '/api/debug/simulate-email',
    DEBUG_LOGS: '/api/debug/logs'
} as const;

/**
 * HTTP状态码
 */
export const HTTP_STATUS = {
    OK: 200,
    CREATED: 201,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    INTERNAL_SERVER_ERROR: 500
} as const;

/**
 * 错误消息
 */
export const ERROR_MESSAGES = {
    // 通用错误
    INTERNAL_ERROR: '内部服务器错误',
    INVALID_REQUEST: '无效的请求',
    UNAUTHORIZED: '未授权访问',
    FORBIDDEN: '禁止访问',
    NOT_FOUND: '资源不存在',

    // 认证错误
    INVALID_CREDENTIALS: '用户名或密码错误',
    TOKEN_EXPIRED: '登录已过期',
    TOKEN_INVALID: '无效的令牌',

    // 用户错误
    USER_NOT_FOUND: '用户不存在',
    USER_ALREADY_EXISTS: '用户已存在',
    INVALID_EMAIL: '无效的邮箱地址',
    WEAK_PASSWORD: '密码强度不够',

    // 邮件错误
    EMAIL_NOT_FOUND: '邮件不存在',
    EMAIL_SEND_FAILED: '邮件发送失败',
    ATTACHMENT_TOO_LARGE: '附件过大',
    INVALID_ATTACHMENT: '无效的附件',

    // 系统错误
    CONFIG_UPDATE_FAILED: '配置更新失败',
    DATABASE_ERROR: '数据库错误',
    FILE_UPLOAD_FAILED: '文件上传失败'
} as const;

/**
 * 成功消息
 */
export const SUCCESS_MESSAGES = {
    // 认证
    LOGIN_SUCCESS: '登录成功',
    LOGOUT_SUCCESS: '退出成功',
    REGISTER_SUCCESS: '注册成功',

    // 用户
    PROFILE_UPDATED: '个人资料已更新',
    PASSWORD_CHANGED: '密码已修改',

    // 邮件
    EMAIL_DELETED: '邮件已删除',
    EMAIL_FORWARDED: '邮件已转发',

    // 系统
    CONFIG_UPDATED: '配置已更新',
    SETTINGS_SAVED: '设置已保存'
} as const;

/**
 * 前端路由
 */
export const VUE_ROUTES = {
    LOGIN: 'login',
    EMAILS: 'emails',
    SETTINGS: 'settings',
    DEBUG: 'debug',
    MAILBOXES: 'mailboxes',
    MAILBOX_APPLICATIONS: 'mailbox-applications',
    ADMIN_USERS: 'admin-users',
    ADMIN_RULES: 'admin-rules',
    ADMIN_EMAILS: 'admin-emails',
    ADMIN_SETTINGS: 'admin-settings',
    ADMIN_MAILBOXES: 'admin-mailboxes',
    ADMIN_MAILBOX_APPLICATIONS: 'admin-mailbox-applications'
} as const;

/**
 * 本地存储键
 */
export const STORAGE_KEYS = {
    AUTH_TOKEN: 'auth_token',
    USER_INFO: 'user_info',
    SYSTEM_CONFIG: 'system_config',
    DEBUG_MODE: 'debug_mode',
    SIDEBAR_STATE: 'sidebar_state'
} as const;

/**
 * 分页配置
 */
export const PAGINATION = {
    DEFAULT_PAGE_SIZE: 20,
    MAX_PAGE_SIZE: 100,
    DEFAULT_PAGE: 1
} as const;

/**
 * 文件类型
 */
export const FILE_TYPES = {
    IMAGE: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
    DOCUMENT: ['pdf', 'doc', 'docx', 'txt', 'rtf'],
    ARCHIVE: ['zip', 'rar', '7z', 'tar', 'gz'],
    AUDIO: ['mp3', 'wav', 'ogg', 'm4a'],
    VIDEO: ['mp4', 'avi', 'mov', 'wmv', 'flv']
} as const;

/**
 * 正则表达式
 */
export const REGEX_PATTERNS = {
    EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/,
    USERNAME: /^[a-zA-Z0-9_]{3,20}$/,
    DOMAIN: /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
    URL: /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/
} as const;

/**
 * 时间格式
 */
export const TIME_FORMATS = {
    DATETIME: 'YYYY-MM-DD HH:mm:ss',
    DATE: 'YYYY-MM-DD',
    TIME: 'HH:mm:ss',
    ISO: 'YYYY-MM-DDTHH:mm:ss.sssZ'
} as const;

/**
 * 主题配置
 */
export const THEMES = {
    LIGHT: 'light',
    DARK: 'dark',
    AUTO: 'auto'
} as const;

/**
 * 语言配置
 */
export const LANGUAGES = {
    ZH_CN: 'zh-CN',
    EN_US: 'en-US'
} as const;
