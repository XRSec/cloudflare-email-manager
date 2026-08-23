/**
 * 项目类型定义
 */

// Cloudflare Workers 类型定义
// 使用更简洁的导入方式
export type {
    ExecutionContext,
    ScheduledEvent,
    D1Database,
    R2Bucket,
    Fetcher,
    SendEmail
} from '@cloudflare/workers-types';

// 环境变量接口
export interface Env {
    DB: D1Database;
    R2: R2Bucket;
    ASSETS?: Fetcher; // 静态资源绑定(本地 Vite 开发时不绑定)
    EMAIL?: SendEmail; // Cloudflare Email Service 发信绑定
}

// 用户接口
export interface User {
    id: number;
    username: string;
    password: string;
    status: 1 | 2 | 3; // 1=激活, 2=停用, 3=删除
    deleted_at?: string;
    created_at?: string;
    updated_at?: string;
}

// 邮件接口
// 优化后的结构：只存储必要信息和概览字段，详细信息从 email:{id}:meta.json 读取
//
// ID 字段说明：
// - id: 邮件在数据库中的主键，使用 crypto.randomUUID() 生成的 UUID
//       格式如 "550e8400-e29b-41d4-a716-446655440000"（标准 UUID v4 格式）
//       与 meta.json.id 相同，R2 文件路径为 email:{id}.eml 和 email:{id}:meta.json
// 注意：
// 1. emailId 使用 crypto.randomUUID() 生成，不再使用 Message-ID 的哈希值
// 2. 原始的 Message-ID（来自邮件头）保存在 meta.json.headers['message-id'] 中，仅用于元数据保存
export interface Email {
    id: string; // 邮件ID（数据库主键），使用 crypto.randomUUID() 生成的 UUID
    subject: string | null; // 主题
    from_address: string | null; // 发件人
    to_address: string | null; // 收件人
    content: string | null; // 内容概览/预览（用于快速查看，完整内容在 R2）
    is_read: number;
    attachment_count: number; // 附件数量（0表示无附件）
    message_id: string | null; // 原始邮件头中的 Message-ID（从 message.raw 提取）
    headers_json: string | null; // 完整的邮件头信息（JSON 格式，从 message.raw 提取）
    size_bytes: number | null; // 剔除附件后的邮件大小（字节）
    date: string | null; // 邮件日期（从 headers 提取）
    reply_to: string | null; // 回复地址（从 headers 提取）
    cc: string | null; // 抄送地址（从 headers 提取）
    bcc: string | null; // 密送地址（从 headers 提取）
    content_type: string | null; // 邮件内容类型（从 headers 提取）
    folder?: 'inbox' | 'sent'; // 邮件归档：收件箱或已发送
    resend_email_id?: string | null; // Resend 投递 ID
    received_at: string;
    created_at?: string;
    updated_at?: string;
}

// 附件接口
export interface Attachment {
    id: string; // 附件ID（数据库主键），使用 crypto.randomUUID() 生成的 UUID
    email_id: string; // 邮件ID
    filename: string;
    content_type: string;
    size_bytes: number;
    r2_key: string;
    content_id?: string | null; // Content-ID（用于内嵌图片，如 cid:xxx）
    deleted_at?: string | null;
    created_at?: string;
    updated_at?: string;
}


// 系统设置接口
export interface SystemSetting {
    key: string;
    value: string;
    description?: string;
    created_at?: string;
    updated_at?: string;
}

// 转发日志接口
export interface ForwardLog {
    id: number;
    email_id: string; // 改为 string 类型，与 Email.id 保持一致
    webhook_url: string;
    status: 0 | 1; // 0=成功, 1=失败
    response_code?: number;
    error_message?: string;
    delivery_from_address?: string | null;
    delivery_to_address?: string | null;
    sent_at: string;
    created_at?: string;
    updated_at?: string;
}

// JWT 载荷接口
export interface JWTPayload {
    user_id: number;
    username: string;
    iat: number;
    exp: number;
}

// API 响应接口
export interface ApiResponse<T = any> {
    success: boolean;
    message?: string;
    data?: T;
    error?: string;
}

// 分页参数接口
export interface PaginationParams {
    page?: number;
    limit?: number;
    search?: string;
    sort?: string;
    order?: 'asc' | 'desc';
}

export interface EmailQueryParams extends PaginationParams {
    folder?: 'inbox' | 'sent';
    recipient_domain?: string;
    recipient_mailbox?: string;
    sender_mailbox?: string;
    recipient?: string;
    sender?: string;
    subject?: string;
    start_date?: string;
    end_date?: string;
    has_attachments?: boolean;
    status?: string;
}

// 用户设置更新接口
export interface UserSettingsUpdate {
    username?: string;
    password?: string;
    password_confirm?: string; // 前端用于二次验证，后端不处理
}

// 系统配置接口
export interface SystemConfig {
    debug_mode: number; // 1=开启, 0=关闭
    allow_registration: number; // 1=是, 0=否
    attachment_retention_days: number; // 附件保留天数
    attachment_max_size: number;
    // 其他配置字段
    cookie_max_age?: number;
    jwt_secret?: string;
    timezone?: string; // IANA 时区,例如 Asia/Shanghai
    // 默认Webhook配置
    // 已支持的邮箱域名列表
    supported_emails?: string[];
}

// 扩展 Hono 上下文类型
declare module 'hono' {
    interface ContextVariableMap {
        jwtPayload: JWTPayload;
    }
}
