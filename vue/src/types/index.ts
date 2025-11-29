// 全局类型定义
export interface UserProfile {
    id: number
    username: string
    status?: number
    created_at: string
    updated_at: string
    settings?: UserSettings
}

export interface UserSettings {
    // 单管理员模式，webhook 配置在系统设置中
}

export interface UserSettingsUpdate {
    password?: string
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

// 系统配置类型
export interface SystemConfig {
    debug_mode?: number
    allow_registration?: number
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
            attachment_max_size: number
            api_base_url: string
            version: string
            build_time: string
        }
        ConfigManager?: {
            isRegistrationAllowed(): boolean
            isDebugMode(): boolean
            getMaxAttachmentSize(): number
        }
    }
}
