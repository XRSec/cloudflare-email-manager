-- =====================================================
-- 完整的数据库初始化脚本
-- 会先删除所有表，然后重新创建
-- 使用方法: wrangler d1 execute cem-db --file=db/schema.sql
-- =====================================================

-- ===================
-- 删除所有现有表（保留 sqlite_sequence 和 sqlite_master 系统表）
-- ===================
DROP TABLE IF EXISTS forward_logs;
DROP TABLE IF EXISTS attachments;
DROP TABLE IF EXISTS emails;
DROP TABLE IF EXISTS mailbox_applications;
DROP TABLE IF EXISTS mailboxes;
DROP TABLE IF EXISTS forward_rules;
DROP TABLE IF EXISTS system_settings;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS _cf_METADATA;

-- ===================
-- 重置自增序列
-- ===================
DELETE FROM sqlite_sequence WHERE name IN ('users', 'emails', 'attachments', 'forward_rules', 'forward_logs', 'mailboxes', 'mailbox_applications');

-- ===================
-- 用户表
-- ===================
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_prefix TEXT UNIQUE NOT NULL,  -- 随机生成的邮件前缀，固定不可修改
    email_password TEXT NOT NULL,       -- 用户邮件密码
    user_type TEXT DEFAULT 'user' CHECK(user_type IN ('admin','user')), -- 用户类型：admin/user
    webhook_url TEXT,                   -- 用户的webhook地址
    webhook_secret TEXT,                -- webhook签名密钥
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email_prefix ON users(email_prefix);
CREATE INDEX idx_users_user_type ON users(user_type);

-- ===================
-- 邮箱表
-- ===================
CREATE TABLE mailboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,               -- 关联用户ID
    email_address TEXT UNIQUE NOT NULL,     -- 完整邮箱地址
    is_default INTEGER DEFAULT 0 CHECK(is_default IN (0,1)), -- 是否为默认邮箱
    is_active INTEGER DEFAULT 1 CHECK(is_active IN (0,1)),   -- 是否启用
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_mailboxes_user_id ON mailboxes(user_id);
CREATE INDEX idx_mailboxes_email_address ON mailboxes(email_address);
CREATE INDEX idx_mailboxes_is_active ON mailboxes(is_active);

-- ===================
-- 邮箱申请表
-- ===================
CREATE TABLE mailbox_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,               -- 申请用户ID
    email_address TEXT NOT NULL,            -- 申请的邮箱地址
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')), -- 申请状态
    reason TEXT,                            -- 申请理由
    admin_comment TEXT,                     -- 管理员备注
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    processed_at DATETIME,                  -- 处理时间
    processed_by INTEGER,                   -- 处理人（管理员ID）
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (processed_by) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(user_id, email_address) -- 同一用户不能重复申请同一邮箱
);

CREATE INDEX idx_mailbox_applications_user_id ON mailbox_applications(user_id);
CREATE INDEX idx_mailbox_applications_status ON mailbox_applications(status);
CREATE INDEX idx_mailbox_applications_applied_at ON mailbox_applications(applied_at);

-- ===================
-- 邮件表
-- ===================
CREATE TABLE emails (
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
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_emails_user_id ON emails(user_id);
CREATE INDEX idx_emails_message_id ON emails(message_id);
CREATE INDEX idx_emails_sender_email ON emails(sender_email);
CREATE INDEX idx_emails_received_at ON emails(received_at);

-- ===================
-- 附件表
-- ===================
CREATE TABLE attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL,          -- 关联邮件ID
    filename TEXT NOT NULL,             -- 附件文件名
    content_type TEXT,                  -- 文件类型
    size_bytes INTEGER NOT NULL,        -- 文件大小（字节）
    r2_key TEXT NOT NULL,               -- R2存储的key
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE INDEX idx_attachments_email_id ON attachments(email_id);
CREATE INDEX idx_attachments_r2_key ON attachments(r2_key);

-- ===================
-- 转发规则表
-- ===================
CREATE TABLE forward_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,            -- 规则名称
    sender_filter TEXT,                 -- 发件人过滤器（可以是邮箱或域名）
    keyword_filter TEXT,                -- 关键字过滤器
    recipient_filter TEXT,              -- 收件人过滤器
    webhook_url TEXT NOT NULL,          -- 转发的webhook地址
    webhook_secret TEXT,                -- webhook签名密钥
    webhook_type TEXT DEFAULT 'custom', -- webhook类型：dingtalk/feishu/custom
    enabled INTEGER DEFAULT 1 CHECK(enabled IN (0,1)), -- 是否启用
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_forward_rules_enabled ON forward_rules(enabled);

-- ===================
-- 系统配置表
-- ===================
CREATE TABLE system_settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    description TEXT,                   -- 配置项描述
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ===================
-- 转发日志表
-- ===================
CREATE TABLE forward_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL,          -- 关联邮件ID
    rule_id INTEGER,                    -- 关联规则ID（可为空，用户个人webhook）
    webhook_url TEXT NOT NULL,          -- 转发的webhook地址
    status TEXT NOT NULL CHECK(status IN ('success','failed')), -- 转发状态：success/failed
    response_code INTEGER,              -- HTTP响应码
    error_message TEXT,                 -- 错误信息
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE,
    FOREIGN KEY (rule_id) REFERENCES forward_rules(id) ON DELETE SET NULL
);

CREATE INDEX idx_forward_logs_email_id ON forward_logs(email_id);
CREATE INDEX idx_forward_logs_status ON forward_logs(status);
CREATE INDEX idx_forward_logs_sent_at ON forward_logs(sent_at);

-- ===================
-- 触发器（自动更新 updated_at）
-- ===================
CREATE TRIGGER update_users_updated_at
    AFTER UPDATE ON users
    FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_emails_updated_at
    AFTER UPDATE ON emails
    FOR EACH ROW
BEGIN
    UPDATE emails SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_attachments_updated_at
    AFTER UPDATE ON attachments
    FOR EACH ROW
BEGIN
    UPDATE attachments SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_forward_rules_updated_at
    AFTER UPDATE ON forward_rules
    FOR EACH ROW
BEGIN
    UPDATE forward_rules SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_system_settings_updated_at
    AFTER UPDATE ON system_settings
    FOR EACH ROW
BEGIN
    UPDATE system_settings SET updated_at = CURRENT_TIMESTAMP WHERE key = NEW.key;
END;

CREATE TRIGGER update_forward_logs_updated_at
    AFTER UPDATE ON forward_logs
    FOR EACH ROW
BEGIN
    UPDATE forward_logs SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_mailboxes_updated_at
    AFTER UPDATE ON mailboxes
    FOR EACH ROW
BEGIN
    UPDATE mailboxes SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_mailbox_applications_updated_at
    AFTER UPDATE ON mailbox_applications
    FOR EACH ROW
BEGIN
    UPDATE mailbox_applications SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- ===================
-- 初始化默认数据
-- ===================

-- 插入默认系统配置
INSERT INTO system_settings (key, value, description) VALUES
    ('allow_registration', 'false', '是否允许用户自由注册'),
    ('cleanup_days', '7', '邮件自动清理天数'),
    ('max_attachment_size', '52428800', '最大附件大小（50MB）'),
    ('domain', 'example.com', '邮件域名'),
    ('admin_email', '', '管理员邮箱'),
    -- JWT secret 将在首次运行时自动生成
    ('primary_domain', 'example.com', '主域名'),
    ('cookie_max_age', '604800', 'Cookie过期时间（秒）'),
    ('debug_mode', 'false', '调试模式开关'),
    ('domains', '["example.com"]', '支持的域名列表（JSON格式）'),
    ('auto_approve_mailbox', 'false', '是否自动批准邮箱申请'),
    ('reserved_mailboxes', '["admin","administrator","root","postmaster","abuse","noreply","no-reply","support","info","contact","webmaster","mail","email","help","security","privacy","legal","billing","sales","marketing","news","newsletter","updates","alerts","notifications"]', '保留邮箱列表（JSON格式）'),
    ('max_mailboxes_per_user', '5', '每个用户最大邮箱数量');

-- 插入默认管理员账号（密码: 123456）
INSERT INTO users (email_prefix, email_password, user_type) VALUES 
    ('admin', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'admin');

-- 插入默认管理员邮箱
INSERT INTO mailboxes (user_id, email_address, is_default, is_active) VALUES 
    (1, 'admin@example.com', 1, 1);

-- ===================
-- 重置自增序列到正确的值
-- SQLite 的 sqlite_sequence 表会在使用 AUTOINCREMENT 时自动创建和管理
-- 我们只需要确保删除旧记录，新的会自动生成
-- ===================
-- 注意：sqlite_sequence 会在第一次插入带 AUTOINCREMENT 的表时自动更新
-- 不需要手动插入，SQLite 会自动管理

-- =====================================================
-- 初始化完成
-- =====================================================