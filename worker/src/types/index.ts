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
    KVNamespace,
    Fetcher
} from '@cloudflare/workers-types';

// 环境变量接口
export interface Env {
    DB: D1Database;
    R2: R2Bucket;
    KV: KVNamespace; // Workers KV 存储
    ASSETS: Fetcher; // 静态资源绑定
}

// 用户接口
export interface User {
    id: number;
    username: string;
    password: string;
    user_type: 0 | 1;
    status: 1 | 2 | 3; // 1=激活, 2=停用, 3=删除
    deleted_at?: string;
    webhook_url?: string;
    webhook_secret?: string;
    created_at?: string;
    updated_at?: string;
}

// 邮箱接口
export interface Mailbox {
    id: number;
    owner_id: number;
    address: string;
    status: 1 | 2 | 3; // 1=激活, 2=停用, 3=删除
    user_id?: number; // 兼容字段，等同于owner_id
    is_default?: number; // 是否为默认邮箱
    deleted_at?: string;
    created_at?: string;
    updated_at?: string;
}

// 邮箱接口（包含用户信息）
export interface MailboxWithUser extends Mailbox {
    owner_username: string;
}

// 邮箱历史记录接口
export interface MailboxHistory {
    id: number;
    mailbox_id: number;
    user_id: number;              // 操作人用户ID
    owner_id: number;             // 邮箱所有者ID
    action_type: 1 | 2 | 3;       // 1=创建, 2=删除, 3=停用
    created_at: string;
}

// 邮箱申请接口
export interface MailboxApplication {
    id: number;
    user_id: number;
    email_address: string;
    status: 0 | 1 | 2; // 0=待审核, 1=已批准, 2=已拒绝
    reason?: string;
    admin_comment?: string;
    applied_at: string;
    processed_at?: string;
    processed_by?: number;
    created_at?: string;
    updated_at?: string;
}

// 邮件接口
export interface Email {
    id: string;
    message_id: string;
    user_id: number;
    sender_email: string;
    recipient_email: string;
    subject?: string;
    content?: string;
    content_type: 'text' | 'html' | 'markdown';
    raw_content?: string; // 修复字段名，与数据库一致
    reply_to?: string;
    cc?: string;
    bcc?: string;
    is_read: number;
    has_attachments: number;
    received_at: string;
    created_at?: string;
    updated_at?: string;
}

// 附件接口
export interface Attachment {
    id: number;
    email_id: string;
    filename: string;
    content_type: string;
    size_bytes: number;
    r2_key: string;
    created_at?: string;
    updated_at?: string;
}

// 转发规则接口
export interface ForwardRule {
    id: number;
    rule_name: string;
    sender_filter?: string;
    keyword_filter?: string;
    recipient_filter?: string;
    webhook_url: string;
    webhook_secret?: string;
    webhook_type: 'dingtalk' | 'feishu' | 'custom';
    enabled: number;
    created_at?: string;
    updated_at?: string;
}

// 用户Webhook配置接口
export interface UserWebhook {
    id: number;
    user_id: number;
    webhook_name: string;
    webhook_url: string;
    webhook_secret?: string;
    webhook_type: 'dingtalk' | 'feishu' | 'custom';
    enabled: number;
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
    email_id: number;
    rule_id?: number;
    webhook_url: string;
    status: 0 | 1; // 0=成功, 1=失败
    response_code?: number;
    error_message?: string;
    sent_at: string;
    created_at?: string;
    updated_at?: string;
}

// JWT 载荷接口
export interface JWTPayload {
    user_id: number;
    username: string;
    user_type: 0 | 1;
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

// 邮件查询参数接口
export interface EmailQueryParams extends PaginationParams {
    sender?: string;
    subject?: string;
    start_date?: string;
    end_date?: string;
    has_attachments?: boolean;
    status?: string;
    scope?: string;
}

// 用户设置更新接口
export interface UserSettingsUpdate {
    password?: string;
    webhook_url?: string;
    webhook_secret?: string;
}

// 系统配置接口
export interface SystemConfig {
    debug_mode: number; // 1=开启, 0=关闭
    allow_registration: number; // 1=是, 0=否
    auto_approve_mailbox: number; // 1=是, 0=否
    supported_domains: string[];
    mail_retention_days: number;
    attachment_max_size: number;
    allow_user_send?: number; // 1=是, 0=否
    max_mailboxes_per_user?: number;
    storage_provider?: 'r2' | 's3' | 'local';
    // 其他配置字段
    cleanup_days?: number;
    max_attachment_size?: number;
    cookie_max_age?: number;
    jwt_secret?: string;
    admin_email?: string;
    primary_domain?: string;
    domains?: string[];
}

// 扩展 Hono 上下文类型
declare module 'hono' {
    interface ContextVariableMap {
        jwtPayload: JWTPayload;
    }
}
