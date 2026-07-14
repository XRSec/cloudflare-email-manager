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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

-- 系统配置表
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 变更信号表
-- 用于前端轮询判断哪些数据域需要失效缓存/刷新页面
CREATE TABLE IF NOT EXISTS change_signals (
    key TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT ''
);


-- 邮件表
-- 优化后的结构：所有基础数据从 message.raw 直接提取并存入数据库
--
-- ID 字段说明：
-- - id: 邮件在数据库中的主键，使用 crypto.randomUUID() 生成的 UUID
--       格式如 "550e8400-e29b-41d4-a716-446655440000"（标准 UUID v4 格式）
--       R2 文件路径为 email:{id}.eml（剔除附件后的完整原始邮件）
--
-- 注意：
-- 1. 所有基础数据从 message.raw 直接提取并存入数据库
-- 2. emailId 使用 crypto.randomUUID() 生成，不再使用 Message-ID 的哈希值
-- 3. 当前使用 TEXT 类型作为主键，UUID 保证 ID 的唯一性
CREATE TABLE IF NOT EXISTS emails (
    id TEXT PRIMARY KEY, -- 邮件ID（数据库主键），使用 crypto.randomUUID() 生成的 UUID
    subject TEXT, -- 主题
    from_address TEXT, -- 发件人
    to_address TEXT, -- 收件人
    content TEXT, -- 内容概览/预览（用于快速查看，完整内容在 R2）
    is_read INTEGER DEFAULT 0 CHECK(is_read IN (0,1)),
    attachment_count INTEGER DEFAULT 0, -- 附件数量（0表示无附件）
    message_id TEXT, -- 原始邮件头中的 Message-ID（从 message.raw 提取）
    headers_json TEXT, -- 完整的邮件头信息（JSON 格式，包含 DKIM、SPF 等，从 message.raw 提取）
    size_bytes INTEGER, -- 剔除附件后的邮件大小（字节）
    date TEXT, -- 邮件日期（从 headers 提取）
    reply_to TEXT, -- 回复地址（从 headers 提取）
    cc TEXT, -- 抄送地址（从 headers 提取）
    bcc TEXT, -- 密送地址（从 headers 提取）
    content_type TEXT, -- 邮件内容类型（从 headers 提取）
    folder TEXT DEFAULT 'inbox' CHECK(folder IN ('inbox','sent')), -- 邮件归档：inbox=收件箱，sent=已发送
    resend_email_id TEXT, -- Resend 投递 ID
    received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
-- 注意：以下信息从 message.raw 直接提取并存入数据库，不再使用 .meta.json：
-- - message_id: 原始邮件头中的 Message-ID
-- - headers_json: 完整的 headers（JSON 格式）
-- - size_bytes: 剔除附件后的大小
-- - date/reply_to/cc/bcc/content_type: 从 headers 提取

CREATE INDEX IF NOT EXISTS idx_emails_from_address ON emails(from_address);
CREATE INDEX IF NOT EXISTS idx_emails_to_address ON emails(to_address);
CREATE INDEX IF NOT EXISTS idx_emails_subject ON emails(subject);
CREATE INDEX IF NOT EXISTS idx_emails_is_read ON emails(is_read);
CREATE INDEX IF NOT EXISTS idx_emails_received_at ON emails(received_at);
CREATE INDEX IF NOT EXISTS idx_emails_created_at ON emails(created_at);
CREATE INDEX IF NOT EXISTS idx_emails_folder ON emails(folder);
CREATE INDEX IF NOT EXISTS idx_emails_resend_email_id ON emails(resend_email_id);

-- ===================
-- 依赖 users 的表
-- ===================

-- ===================
-- 依赖多个表的表
-- ===================

-- 附件表
CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,                   -- 附件ID，使用 crypto.randomUUID() 生成的 UUID
    email_id TEXT NOT NULL,                 -- 邮件ID
    filename TEXT NOT NULL,                 -- 文件名
    content_type TEXT,                      -- 内容类型
    size_bytes INTEGER DEFAULT 0,           -- 文件大小（字节）
    r2_key TEXT NOT NULL,                   -- R2存储键
    content_id TEXT,                        -- Content-ID（用于内嵌图片，如 cid:xxx）
    deleted_at DATETIME,                    -- 附件文件清理时间（记录保留，文件不可下载）
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
    webhook_url TEXT NOT NULL,              -- Webhook URL
    status INTEGER NOT NULL CHECK(status IN (0,1)), -- 转发状态：0=成功, 1=失败
    response_code INTEGER,                  -- 响应码
    error_message TEXT,                     -- 错误信息
    delivery_from_address TEXT,             -- 实际转发发件人
    delivery_to_address TEXT,               -- 实际转发收件人
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- 发送时间
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_forward_logs_email_id ON forward_logs(email_id);
CREATE INDEX IF NOT EXISTS idx_forward_logs_status ON forward_logs(status);
CREATE INDEX IF NOT EXISTS idx_forward_logs_sent_at ON forward_logs(sent_at);

-- 消息路由规则表
CREATE TABLE IF NOT EXISTS routing_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL CHECK(category IN ('channel','mail_channel','webhook','email_forward')), -- channel=Webhook通道, mail_channel=邮件通道, webhook=Webhook规则, email_forward=邮件转发
    name TEXT NOT NULL,
    enabled INTEGER DEFAULT 0 CHECK(enabled IN (0,1)), -- 默认未启用
    match_mode TEXT NOT NULL DEFAULT 'all' CHECK(match_mode IN ('all','any')),
    sender_pattern TEXT DEFAULT '',
    recipient_pattern TEXT DEFAULT '',
    subject_pattern TEXT DEFAULT '',
    content_pattern TEXT DEFAULT '',
    target_channel_ids TEXT DEFAULT '[]', -- Webhook通道ID列表（JSON数组）
    target_email TEXT DEFAULT '', -- 邮件转发目标邮箱
    target_from_address TEXT DEFAULT '', -- CF/Resend 转发发件人
    target_forward_type TEXT DEFAULT 'internal' CHECK(target_forward_type IN ('internal','cf','resend')), -- 邮件转发方式
    is_default INTEGER DEFAULT 0 CHECK(is_default IN (0,1)), -- 是否默认规则
    default_mode TEXT CHECK(default_mode IS NULL OR default_mode IN ('always','unmatched')), -- 默认规则模式
    channel_type TEXT CHECK(channel_type IS NULL OR channel_type IN ('dingtalk','feishu','bark','resend')), -- 通道类型
    channel_url TEXT DEFAULT '', -- Webhook URL 或邮件通道发件域名
    channel_secret TEXT DEFAULT '', -- Webhook 密钥或邮件通道 API Key
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_routing_rules_category ON routing_rules(category);
CREATE INDEX IF NOT EXISTS idx_routing_rules_enabled ON routing_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_routing_rules_is_default ON routing_rules(is_default);
CREATE INDEX IF NOT EXISTS idx_routing_rules_created_at ON routing_rules(created_at);

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

CREATE TRIGGER update_routing_rules_updated_at
    AFTER UPDATE ON routing_rules
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE routing_rules SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- ===================
-- 初始化默认数据
-- ===================

-- 插入默认系统配置
INSERT OR IGNORE INTO system_settings (key, value, description) VALUES
('allow_registration', '0', '是否允许用户自由注册 (1=是, 0=否)'),
('attachment_retention_days', '365', '附件保留天数'),
('max_attachment_size', '52428800', '最大附件大小（50MB）'),
('cookie_max_age', '172800', 'Cookie过期时间（秒，48小时）'),
('debug_mode', '0', '调试模式开关 (1=开启, 0=关闭)'),
('api_rate_limit', '0', 'API访问频率限制开关 (1=启用, 0=禁用)'),
('api_rate_limit_max_requests', '100', '每分钟最大请求数（10-10000）'),
('timezone', 'Asia/Shanghai', '系统显示时区（IANA时区）'),
('supported_emails', '["example.com", "example.dev"]', '已支持的邮箱域名列表（JSON数组）');

-- 插入默认管理员用户（密码：123456，已哈希）
INSERT OR IGNORE INTO users (username, password, user_type, status) VALUES
('admin', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 1, 1);

-- 插入默认消息路由示例规则（默认未启用）
INSERT OR IGNORE INTO routing_rules (
    id,
    category,
    name,
    enabled,
    match_mode,
    sender_pattern,
    recipient_pattern,
    subject_pattern,
    content_pattern,
    target_channel_ids,
    target_email,
    target_from_address,
    target_forward_type,
    is_default,
    default_mode,
    channel_type,
    channel_url,
    channel_secret
) VALUES
(1, 'webhook', '账单邮件推送到财务群', 0, 'all', 'billing@', '', '账单', '', '[1001]', '', '', 'internal', 0, NULL, NULL, '', ''),
(2, 'webhook', '登录验证码走 Bark', 0, 'any', '', '', '验证码', 'login code', '[1002]', '', '', 'internal', 0, NULL, NULL, '', ''),
(3, 'webhook', '默认 Webhook 规则', 0, 'all', '', '', '', '', '[1001]', '', '', 'internal', 1, 'unmatched', NULL, '', ''),
(11, 'email_forward', 'GitHub 邮件归档到开发邮箱', 0, 'all', 'notifications@github.com', 'dev@', '', '', '[]', 'dev-archive@example.com', '', 'internal', 0, NULL, NULL, '', ''),
(12, 'email_forward', '账单类邮件转给财务', 0, 'any', 'billing@', '', 'invoice', 'payment', '[]', 'finance@example.com', '', 'internal', 0, NULL, NULL, '', ''),
(13, 'email_forward', '默认邮件转发规则', 0, 'all', '', '', '', '', '[]', 'archive@example.com', 'cem@example.com', 'internal', 1, 'unmatched', NULL, '', ''),
(1001, 'channel', '财务钉钉群', 1, 'all', '', '', '', '', '[]', '', '', 'internal', 0, NULL, 'dingtalk', 'https://oapi.dingtalk.com/robot/send?access_token=mock-finance', ''),
(1002, 'channel', '移动 Bark', 1, 'all', '', '', '', '', '[]', '', '', 'internal', 0, NULL, 'bark', 'https://api.day.app/mock-device-key/', ''),
(1003, 'channel', 'GitHub 飞书', 1, 'all', '', '', '', '', '[]', '', '', 'internal', 0, NULL, 'feishu', 'https://open.feishu.cn/open-apis/bot/v2/hook/mock-github', ''),
(1005, 'mail_channel', 'example.com', 0, 'all', '', '', '', '', '[]', '', '', 'internal', 0, NULL, 'resend', 'example.com', 're_NggwCemBr8UFABoVubisAhaubepWN05SB0');

-- ===================
-- 注意：sqlite_sequence 会在第一次插入带 AUTOINCREMENT 的表时自动更新
-- 不需要手动插入，SQLite 会自动管理
-- ===================
