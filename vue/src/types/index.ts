// 全局类型定义
export interface UserProfile {
    id: number
    username: string
    email: string
    user_type: 0 | 1
    status?: number
    created_at: string
    updated_at: string
    settings?: UserSettings
}

export interface UserSettings {
    webhook_url?: string | null
    webhook_secret?: string | null
}

export interface UserSettingsUpdate {
    password?: string
    webhook_url?: string
    webhook_secret?: string
}

export interface LoginRequest {
    username: string
    password: string
}

export interface LoginResponse {
    success: boolean
    message?: string
    data?: {
        token: string
        user: UserProfile
    }
    error?: string
}

export interface ApiResponse<T = any> {
    success: boolean
    data?: T
    message?: string
    error?: string
}

export interface SystemHealth {
    success: boolean
    data?: {
        health: {
            status: number
            timestamp: string
            services: {
                database: {
                    status: number
                    latency_ms: number
                }
                storage: {
                    status: number
                    provider: number
                }
                kv: {
                    status: number
                    provider: number
                }
            }
            config: {
                allow_registration: number
                debug_mode: number
            }
            version: number
            uptime: number
            total_latency_ms: number
        }
    }
    error?: string
}

export interface RegistrationStatus {
    success: boolean
    data?: {
        allow_registration: number
    }
    error?: string
}

// 应用阶段类型
export type AppStage = 'initial-loading' | 'auth-check' | 'login' | 'main-preload' | 'main'

// 转发规则相关类型
export interface ForwardRuleWebhook {
    id?: number
    rule_id?: number
    webhook_url: string
    webhook_secret?: string
    webhook_type: 'dingtalk' | 'feishu' | 'bark' | 'custom'
    custom_message?: string // 自定义消息模板，支持变量：{{from}}, {{to}}, {{subject}}, {{content}}, {{received_at}}
    enabled: number
    created_at?: string
    updated_at?: string
}

export interface ForwardRule {
    id: number
    rule_name: string
    sender_filter?: string
    keyword_filter?: string
    recipient_filter?: string
    exact_match?: number // 是否精确匹配（0=包含匹配，1=精确匹配）
    webhook_url?: string // 保留字段以兼容旧数据
    webhook_secret?: string // 保留字段以兼容旧数据
    webhook_type?: 'dingtalk' | 'feishu' | 'bark' | 'custom' // 保留字段以兼容旧数据
    enabled: number
    created_at?: string
    updated_at?: string
    webhooks?: ForwardRuleWebhook[] // 新字段：规则关联的多个 webhook
}

export interface ForwardRuleInput {
    rule_name: string
    sender_filter?: string
    keyword_filter?: string
    recipient_filter?: string
    exact_match?: number // 是否精确匹配（0=包含匹配，1=精确匹配）
    enabled?: number
    webhooks?: ForwardRuleWebhook[]
}

// 系统配置类型
export interface SystemConfig {
    debug_mode?: number
    allow_registration?: number
    supported_domains?: string[]
    mail_retention_days?: number
    attachment_retention_days?: number
    attachment_max_size?: number
    cookie_max_age?: number
    jwt_secret?: string
    api_rate_limit?: number
    api_rate_limit_max_requests?: number
}

// 全局窗口类型扩展
declare global {
    interface Window {
        showGlobalLoading: (text?: string) => void
        hideGlobalLoading: () => void
        CEM_CONFIG?: {
            allow_registration: number
            debug_mode: number
            supported_domains: string[]
            attachment_max_size: number
            api_base_url: string
            version: string
            build_time: string
        }
        ConfigManager?: {
            isRegistrationAllowed(): boolean
            isDebugMode(): boolean
            getSupportedDomains(): string[]
            getMaxAttachmentSize(): number
        }
    }
}
