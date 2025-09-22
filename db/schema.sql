-- =====================================================
-- 完整的数据库初始化脚本
-- 会先删除所有表，然后重新创建
-- 使用方法: node db/db_init.js
-- 如果有新增，需要注意一下排序，避免初始化的时候 外键约束 报错
-- =====================================================

-- ===================
-- 基础表（无外键依赖）
-- ===================

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL CHECK(LENGTH(username) >= 3 AND LENGTH(username) <= 50), -- 用户名，3-50字符
    password TEXT NOT NULL CHECK(LENGTH(password) >= 6), -- 用户密码，至少6位
    user_type INTEGER DEFAULT 0 CHECK(user_type IN (0,1)), -- 用户类型：0=普通用户, 1=管理员
    status INTEGER DEFAULT 1 CHECK(status IN (1,2,3)), -- 用户状态：1=激活, 2=停用, 3=删除
    deleted_at DATETIME,                -- 删除时间（软删除）
    webhook_url TEXT CHECK(webhook_url IS NULL OR webhook_url LIKE 'http%'), -- webhook地址必须是有效URL
    webhook_secret TEXT,                -- webhook签名密钥
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_user_type ON users(user_type);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

-- 系统配置表
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 转发规则表
CREATE TABLE IF NOT EXISTS forward_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    sender_filter TEXT,
    keyword_filter TEXT,
    recipient_filter TEXT,
    webhook_url TEXT NOT NULL,
    webhook_secret TEXT,
    webhook_type TEXT DEFAULT 'custom',
    enabled INTEGER DEFAULT 1 CHECK(enabled IN (0,1)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_forward_rules_enabled ON forward_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_forward_rules_webhook_type ON forward_rules(webhook_type);

-- 邮件表
CREATE TABLE IF NOT EXISTS emails (
    id TEXT PRIMARY KEY,
    message_id TEXT,
    user_id INTEGER, -- 添加用户ID字段
    subject TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    sender_email TEXT, -- 添加发送者邮箱字段
    recipient_email TEXT, -- 添加接收者邮箱字段
    reply_to TEXT,
    cc TEXT,
    bcc TEXT,
    content_type TEXT DEFAULT 'text/plain',
    content TEXT,
    raw_content TEXT,
    is_read INTEGER DEFAULT 0 CHECK(is_read IN (0,1)),
    has_attachments INTEGER DEFAULT 0 CHECK(has_attachments IN (0,1)),
    size_bytes INTEGER DEFAULT 0,
    received_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- 添加接收时间字段
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_emails_from_address ON emails(from_address);
CREATE INDEX IF NOT EXISTS idx_emails_to_address ON emails(to_address);
CREATE INDEX IF NOT EXISTS idx_emails_subject ON emails(subject);
CREATE INDEX IF NOT EXISTS idx_emails_is_read ON emails(is_read);
CREATE INDEX IF NOT EXISTS idx_emails_user_id ON emails(user_id);
CREATE INDEX IF NOT EXISTS idx_emails_sender_email ON emails(sender_email);
CREATE INDEX IF NOT EXISTS idx_emails_recipient_email ON emails(recipient_email);
CREATE INDEX IF NOT EXISTS idx_emails_received_at ON emails(received_at);
CREATE INDEX IF NOT EXISTS idx_emails_created_at ON emails(created_at);

-- ===================
-- 依赖 users 的表
-- ===================

-- 邮箱表
CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,               -- 邮箱所有者ID
    address TEXT UNIQUE NOT NULL CHECK(address LIKE '%@%'), -- 邮箱地址
    status INTEGER DEFAULT 1 CHECK(status IN (1,2,3)), -- 邮箱状态：1=激活, 2=停用, 3=删除
    deleted_at DATETIME,                     -- 删除时间（软删除）
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mailboxes_owner_id ON mailboxes(owner_id);
CREATE INDEX IF NOT EXISTS idx_mailboxes_address ON mailboxes(address);
CREATE INDEX IF NOT EXISTS idx_mailboxes_status ON mailboxes(status);

-- 邮箱申请表
CREATE TABLE IF NOT EXISTS mailbox_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,               -- 申请用户ID
    requested_address TEXT NOT NULL CHECK(requested_address LIKE '%@%'), -- 申请的邮箱地址
    reason TEXT,                            -- 申请理由
    status INTEGER DEFAULT 0 CHECK(status IN (0,1,2)), -- 申请状态：0=待审核, 1=已批准, 2=已拒绝
    admin_comment TEXT,                     -- 管理员备注
    processed_by INTEGER,                   -- 处理人ID
    processed_at DATETIME,                  -- 处理时间
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (processed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_mailbox_applications_user_id ON mailbox_applications(user_id);
CREATE INDEX IF NOT EXISTS idx_mailbox_applications_status ON mailbox_applications(status);
CREATE INDEX IF NOT EXISTS idx_mailbox_applications_processed_at ON mailbox_applications(processed_at);
CREATE INDEX IF NOT EXISTS idx_mailbox_applications_requested_address ON mailbox_applications(requested_address);

-- 安全审计表
CREATE TABLE IF NOT EXISTS security_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,           -- 用户ID（必须，只记录有有效身份的用户）
    action_type INTEGER NOT NULL,       -- 操作类型：1=权限拒绝, 2=可疑操作
    resource_type INTEGER,              -- 资源类型：0=mailbox, 1=email, 2=user, 3=system
    resource_id INTEGER,                -- 资源ID
    request_ip TEXT,                    -- 请求IP
    user_agent TEXT,                    -- 用户代理
    attack_type INTEGER,                -- 攻击类型：1=权限拒绝, 2=可疑活动, 3=频率限制
    description TEXT,                   -- 描述信息
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_security_audit_user_id ON security_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_security_audit_action_type ON security_audit(action_type);
CREATE INDEX IF NOT EXISTS idx_security_audit_attack_type ON security_audit(attack_type);
CREATE INDEX IF NOT EXISTS idx_security_audit_created_at ON security_audit(created_at);
CREATE INDEX IF NOT EXISTS idx_security_audit_request_ip ON security_audit(request_ip);

-- 用户Webhook配置表
CREATE TABLE IF NOT EXISTS user_webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,               -- 用户ID
    webhook_name TEXT NOT NULL,             -- Webhook名称
    webhook_url TEXT NOT NULL,              -- Webhook URL
    webhook_secret TEXT,                    -- Webhook密钥
    webhook_type TEXT DEFAULT 'custom',     -- Webhook类型
    enabled INTEGER DEFAULT 1 CHECK(enabled IN (0,1)), -- 是否启用
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_webhooks_user_id ON user_webhooks(user_id);
CREATE INDEX IF NOT EXISTS idx_user_webhooks_enabled ON user_webhooks(enabled);
CREATE INDEX IF NOT EXISTS idx_user_webhooks_webhook_type ON user_webhooks(webhook_type);

-- ===================
-- 依赖多个表的表
-- ===================

-- 邮箱历史记录表
CREATE TABLE IF NOT EXISTS mailbox_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL,            -- 邮箱ID
    user_id INTEGER NOT NULL,               -- 操作用户ID
    owner_id INTEGER NOT NULL,              -- 邮箱所有者ID
    action_type INTEGER NOT NULL CHECK(action_type IN (1,2,3)), -- 操作类型：1=创建, 2=修改, 3=删除
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mailbox_history_mailbox_id ON mailbox_history(mailbox_id);
CREATE INDEX IF NOT EXISTS idx_mailbox_history_user_id ON mailbox_history(user_id);
CREATE INDEX IF NOT EXISTS idx_mailbox_history_owner_id ON mailbox_history(owner_id);
CREATE INDEX IF NOT EXISTS idx_mailbox_history_action_type ON mailbox_history(action_type);
CREATE INDEX IF NOT EXISTS idx_mailbox_history_created_at ON mailbox_history(created_at);

-- 附件表
CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    email_id TEXT NOT NULL,                 -- 邮件ID
    filename TEXT NOT NULL,                 -- 文件名
    content_type TEXT,                      -- 内容类型
    size_bytes INTEGER DEFAULT 0,           -- 文件大小（字节）
    r2_key TEXT NOT NULL,                   -- R2存储键
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attachments_email_id ON attachments(email_id);
CREATE INDEX IF NOT EXISTS idx_attachments_r2_key ON attachments(r2_key);
CREATE INDEX IF NOT EXISTS idx_attachments_content_type ON attachments(content_type);

-- 转发日志表
CREATE TABLE IF NOT EXISTS forward_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id TEXT NOT NULL,                 -- 邮件ID
    rule_id INTEGER,                        -- 转发规则ID
    webhook_url TEXT NOT NULL,              -- Webhook URL
    status INTEGER NOT NULL CHECK(status IN (0,1)), -- 转发状态：0=成功, 1=失败
    response_code INTEGER,                  -- 响应码
    error_message TEXT,                     -- 错误信息
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- 发送时间
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE,
    FOREIGN KEY (rule_id) REFERENCES forward_rules(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_forward_logs_email_id ON forward_logs(email_id);
CREATE INDEX IF NOT EXISTS idx_forward_logs_status ON forward_logs(status);
CREATE INDEX IF NOT EXISTS idx_forward_logs_sent_at ON forward_logs(sent_at);

-- ===================
-- 触发器（自动更新 updated_at）
-- ===================
CREATE TRIGGER update_users_updated_at
    AFTER UPDATE ON users
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_mailboxes_updated_at
    AFTER UPDATE ON mailboxes
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE mailboxes SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_mailbox_applications_updated_at
    AFTER UPDATE ON mailbox_applications
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE mailbox_applications SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_emails_updated_at
    AFTER UPDATE ON emails
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE emails SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_attachments_updated_at
    AFTER UPDATE ON attachments
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE attachments SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_forward_rules_updated_at
    AFTER UPDATE ON forward_rules
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE forward_rules SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_user_webhooks_updated_at
    AFTER UPDATE ON user_webhooks
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE user_webhooks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_system_settings_updated_at
    AFTER UPDATE ON system_settings
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE system_settings SET updated_at = CURRENT_TIMESTAMP WHERE key = NEW.key;
END;

CREATE TRIGGER update_forward_logs_updated_at
    AFTER UPDATE ON forward_logs
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE forward_logs SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- ===================
-- 初始化默认数据
-- ===================

-- 插入默认系统配置
INSERT OR IGNORE INTO system_settings (key, value, description) VALUES
('allow_registration', '0', '是否允许用户自由注册 (1=是, 0=否)'),
('cleanup_days', '7', '邮件自动清理天数'),
('max_attachment_size', '52428800', '最大附件大小（50MB）'),
('domain', 'example.com', '邮件域名'),
('admin_email', 'admin@example.com', '管理员邮箱'),
('primary_domain', 'example.com', '主域名'),
('cookie_max_age', '604800', 'Cookie过期时间（秒）'),
('debug_mode', '0', '调试模式开关 (1=开启, 0=关闭)'),
('domains', '["example.com"]', '支持的域名列表（JSON格式）'),
('auto_approve_mailbox', '0', '是否自动批准邮箱申请 (1=是, 0=否)'),
('reserved_mailboxes', '["admin","administrator","root","postmaster","abuse","noreply","no-reply","support","info","contact","webmaster","mail","email","help","security","privacy","legal","billing","sales","marketing","news","newsletter","updates","alerts","notifications"]', '保留邮箱列表（JSON格式）'),
('max_mailboxes_per_user', '5', '每个用户最大邮箱数量');

-- 插入默认管理员用户（密码：123456，已哈希）
INSERT OR IGNORE INTO users (username, password, user_type, status) VALUES
('admin', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 1, 1);

-- 插入默认测试用户（密码：123456，已哈希）
INSERT OR IGNORE INTO users (username, password, user_type, status) VALUES
('test', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 0, 1);

-- 为管理员创建默认邮箱
INSERT OR IGNORE INTO mailboxes (owner_id, address, status) VALUES
(1, 'admin@example.com', 1);

-- 为测试用户创建默认邮箱
INSERT OR IGNORE INTO mailboxes (owner_id, address, status) VALUES
(2, 'test@example.com', 1);

-- ===================
-- 注意：sqlite_sequence 会在第一次插入带 AUTOINCREMENT 的表时自动更新
-- 不需要手动插入，SQLite 会自动管理
-- ===================