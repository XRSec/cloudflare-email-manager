-- 新的数据库结构设计，针对用户需求重新设计
-- 支持管理员、普通用户、邮件转发、附件存储等功能

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_prefix TEXT UNIQUE NOT NULL,  -- 随机生成的邮件前缀，固定不可修改
    email_password TEXT NOT NULL,       -- 用户邮件密码
    user_type TEXT DEFAULT 'user',     -- 用户类型：admin/user
    webhook_url TEXT,                   -- 用户的webhook地址
    webhook_secret TEXT,                -- webhook签名密钥
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email_prefix ON users(email_prefix);
CREATE INDEX IF NOT EXISTS idx_users_user_type ON users(user_type);

-- 邮件表
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT UNIQUE NOT NULL,    -- 邮件唯一标识
    user_id INTEGER NOT NULL,           -- 关联用户ID
    sender_email TEXT NOT NULL,         -- 发件人邮箱
    recipient_email TEXT NOT NULL,      -- 收件人邮箱（完整邮箱地址）
    subject TEXT,                       -- 邮件主题
    text_content TEXT,                  -- 纯文本内容
    html_content TEXT,                  -- HTML内容
    raw_email TEXT,                     -- 原始邮件内容
    has_attachments INTEGER DEFAULT 0,  -- 是否有附件
    received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_emails_user_id ON emails(user_id);
CREATE INDEX IF NOT EXISTS idx_emails_message_id ON emails(message_id);
CREATE INDEX IF NOT EXISTS idx_emails_sender_email ON emails(sender_email);
CREATE INDEX IF NOT EXISTS idx_emails_received_at ON emails(received_at);

-- 附件表
CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL,          -- 关联邮件ID
    filename TEXT NOT NULL,             -- 附件文件名
    content_type TEXT,                  -- 文件类型
    size_bytes INTEGER NOT NULL,       -- 文件大小（字节）
    r2_key TEXT NOT NULL,               -- R2存储的key
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attachments_email_id ON attachments(email_id);
CREATE INDEX IF NOT EXISTS idx_attachments_r2_key ON attachments(r2_key);

-- 转发规则表（管理员配置）
CREATE TABLE IF NOT EXISTS forward_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,            -- 规则名称
    sender_filter TEXT,                 -- 发件人过滤器（可以是邮箱或域名）
    keyword_filter TEXT,               -- 关键字过滤器
    recipient_filter TEXT,             -- 收件人过滤器
    webhook_url TEXT NOT NULL,          -- 转发的webhook地址
    webhook_secret TEXT,                -- webhook签名密钥
    webhook_type TEXT DEFAULT 'custom', -- webhook类型：dingtalk/feishu/custom
    enabled INTEGER DEFAULT 1,         -- 是否启用
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_forward_rules_enabled ON forward_rules(enabled);

-- 系统配置表
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    description TEXT,                   -- 配置项描述
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 插入默认系统配置
INSERT OR IGNORE INTO system_settings (key, value, description) VALUES
('allow_registration', 'true', '是否允许用户自由注册'),
('cleanup_days', '7', '邮件自动清理天数'),
('max_attachment_size', '52428800', '最大附件大小（50MB）'),
('domain', 'example.com', '邮件域名'),
('admin_email', '', '管理员邮箱');

-- 邮件转发日志表（记录转发历史）
CREATE TABLE IF NOT EXISTS forward_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL,          -- 关联邮件ID
    rule_id INTEGER,                    -- 关联规则ID（可为空，用户个人webhook）
    webhook_url TEXT NOT NULL,          -- 转发的webhook地址
    status TEXT NOT NULL,               -- 转发状态：success/failed
    response_code INTEGER,              -- HTTP响应码
    error_message TEXT,                 -- 错误信息
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE,
    FOREIGN KEY (rule_id) REFERENCES forward_rules(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_forward_logs_email_id ON forward_logs(email_id);
CREATE INDEX IF NOT EXISTS idx_forward_logs_status ON forward_logs(status);
CREATE INDEX IF NOT EXISTS idx_forward_logs_sent_at ON forward_logs(sent_at);