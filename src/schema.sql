-- D1 数据库初始化建表脚本
-- 用户表：普通用户与管理员
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email_prefix TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','user')),
  webhook_url TEXT,
  webhook_platform TEXT CHECK(webhook_platform IN ('feishu','dingtalk')),
  webhook_signature_secret TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- 邮件表
CREATE TABLE IF NOT EXISTS emails (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  from_address TEXT,
  to_address TEXT,
  subject TEXT,
  text_body TEXT,
  html_body TEXT,
  message_id TEXT,
  received_at INTEGER NOT NULL,
  size_bytes INTEGER DEFAULT 0,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_emails_user_time ON emails(user_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_emails_size ON emails(size_bytes DESC);

-- 附件表
CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY,
  email_id TEXT NOT NULL,
  r2_key TEXT NOT NULL,
  file_name TEXT,
  content_type TEXT,
  size_bytes INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attachments_email ON attachments(email_id);

-- 转发规则表（管理员可配置，全局或按用户）
CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  owner_scope TEXT NOT NULL CHECK(owner_scope IN ('global','user')),
  owner_id TEXT, -- 当 owner_scope = 'user' 时为 users.id
  match_from TEXT, -- 发送者过滤
  match_keywords TEXT, -- 主题/正文包含关键字（逗号分隔）
  match_mime TEXT, -- 文件类型过滤（通配，逗号分隔）
  forward_platform TEXT NOT NULL CHECK(forward_platform IN ('feishu','dingtalk')),
  forward_url TEXT NOT NULL,
  forward_signature_secret TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- 系统设置表
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

