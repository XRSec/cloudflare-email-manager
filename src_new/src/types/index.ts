/**
 * Vue 3 版本的项目类型定义
 */

// 用户接口
export interface User {
  id: number
  email_prefix: string
  email_password: string
  user_type: 'admin' | 'user'
  webhook_url?: string
  webhook_secret?: string
  created_at?: string
  updated_at?: string
}

// 邮件接口
export interface Email {
  id: number
  message_id: string
  user_id: number
  sender_email: string
  recipient_email: string
  subject?: string
  text_content?: string
  html_content?: string
  raw_email?: string
  has_attachments: number
  received_at: string
  created_at?: string
  updated_at?: string
  attachments?: Attachment[]
}

// 附件接口
export interface Attachment {
  id: number
  email_id: number
  filename: string
  content_type: string
  size_bytes: number
  r2_key: string
  created_at?: string
  updated_at?: string
}

// 转发规则接口
export interface ForwardRule {
  id: number
  rule_name: string
  sender_filter?: string
  keyword_filter?: string
  recipient_filter?: string
  webhook_url: string
  webhook_secret?: string
  webhook_type: 'dingtalk' | 'feishu' | 'custom'
  enabled: boolean
  created_at?: string
  updated_at?: string
}

// 系统设置接口
export interface SystemSetting {
  key: string
  value: string
  description?: string
  created_at?: string
  updated_at?: string
}

// 系统配置接口
export interface SystemConfig {
  allow_registration: boolean
  cleanup_days: number
  max_attachment_size: number
  debug_mode: boolean
  domains: string[]
  cookie_max_age: number
  jwt_secret?: string
  admin_email?: string
  primary_domain?: string
}

// JWT 载荷接口
export interface JWTPayload {
  user_id: number
  email_prefix: string
  user_type: 'admin' | 'user'
  iat: number
  exp: number
}

// API 响应接口
export interface ApiResponse<T = any> {
  success: boolean
  message?: string
  data?: T
  error?: string
}

// 分页参数接口
export interface PaginationParams {
  page?: number
  limit?: number
  search?: string
  sort?: string
  order?: 'asc' | 'desc'
}

// 邮件查询参数接口
export interface EmailQueryParams extends PaginationParams {
  sender?: string
  subject?: string
  start_date?: string
  end_date?: string
  has_attachments?: boolean
}

// 用户设置更新接口
export interface UserSettingsUpdate {
  email_password?: string
  webhook_url?: string
  webhook_secret?: string
}

// 登录表单接口
export interface LoginForm {
  email_prefix: string
  email_password: string
}

// 注册表单接口
export interface RegisterForm {
  email_password: string
}

// 路由名称枚举
export enum RouteNames {
  LOGIN = 'Login',
  DASHBOARD = 'Dashboard',
  EMAILS = 'Emails',
  SETTINGS = 'Settings',
  ADMIN_USERS = 'AdminUsers',
  ADMIN_RULES = 'AdminRules',
  ADMIN_EMAILS = 'AdminEmails',
  ADMIN_SETTINGS = 'AdminSettings',
  DEBUG = 'Debug'
}

// 消息类型枚举
export enum MessageType {
  SUCCESS = 'success',
  ERROR = 'error',
  INFO = 'info',
  WARNING = 'warning'
}

// 用户状态接口
export interface UserState {
  currentUser: User | null
  isAuthenticated: boolean
  token: string | null
}

// 系统状态接口
export interface SystemState {
  config: SystemConfig | null
  loading: boolean
  error: string | null
}

// 邮件状态接口
export interface EmailState {
  emails: Email[]
  currentEmail: Email | null
  loading: boolean
  pagination: {
    page: number
    limit: number
    total: number
  }
}

// 模拟邮件表单接口（调试用）
export interface SimulateEmailForm {
  from: string
  to: string
  subject: string
  text: string
  html?: string
}