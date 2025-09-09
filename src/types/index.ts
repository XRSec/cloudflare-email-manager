/**
 * 项目类型定义
 */

// Cloudflare Workers 类型导入
export type ExecutionContext = import('@cloudflare/workers-types').ExecutionContext;
export type ScheduledEvent = import('@cloudflare/workers-types').ScheduledEvent;
export type D1Database = import('@cloudflare/workers-types').D1Database;
export type R2Bucket = import('@cloudflare/workers-types').R2Bucket;
export type KVNamespace = import('@cloudflare/workers-types').KVNamespace;

// 环境变量接口
export interface Env {
    DB: D1Database;
    R2: R2Bucket;
    KV: KVNamespace;
    DOMAIN: string;
    JWT_SECRET: string;
    cem_debug?: string;
}

// 用户接口
export interface User {
    id: number;
    email_prefix: string;
    email_password: string;
    user_type: 'admin' | 'user';
    webhook_url?: string;
    webhook_secret?: string;
    created_at?: string;
    updated_at?: string;
}

// 邮件接口
export interface Email {
    id: number;
    message_id: string;
    user_id: number;
    sender_email: string;
    recipient_email: string;
    subject?: string;
    text_content?: string;
    html_content?: string;
    raw_email?: string;
    has_attachments: number;
    received_at: string;
    created_at?: string;
    updated_at?: string;
}

// 附件接口
export interface Attachment {
    id: number;
    email_id: number;
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
    status: 'success' | 'failed';
    response_code?: number;
    error_message?: string;
    sent_at: string;
    created_at?: string;
    updated_at?: string;
}

// JWT 载荷接口
export interface JWTPayload {
    user_id: number;
    email_prefix: string;
    user_type: 'admin' | 'user';
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
}

// 用户设置更新接口
export interface UserSettingsUpdate {
    email_password?: string;
    webhook_url?: string;
    webhook_secret?: string;
}

// 系统配置接口
export interface SystemConfig {
    allow_registration: boolean;
    cleanup_days: number;
    max_attachment_size: number;
    debug_mode: boolean;
    domains: string[];
    cookie_max_age: number;
    jwt_secret?: string;
    admin_email?: string;
    primary_domain?: string;
}

// 扩展 Hono 上下文类型
declare module 'hono' {
    interface ContextVariableMap {
        jwtPayload: JWTPayload;
    }
}
