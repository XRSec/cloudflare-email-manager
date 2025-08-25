-- 邮件与附件、转发规则、配置表结构（D1 / SQLite 方言）

-- 邮件表
CREATE TABLE IF NOT EXISTS emails (
  id TEXT PRIMARY KEY,
  message_id TEXT,
  from_addr TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  subject TEXT,
  text TEXT,
  html TEXT,
  has_attachments INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_emails_created_at ON emails(created_at);
CREATE INDEX IF NOT EXISTS idx_emails_to_addr ON emails(to_addr);

-- 附件表
CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY,
  email_id TEXT NOT NULL,
  filename TEXT,
  content_type TEXT,
  size_bytes INTEGER,
  r2_key TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attachments_email ON attachments(email_id);
CREATE INDEX IF NOT EXISTS idx_attachments_size ON attachments(size_bytes);

-- 转发规则表
CREATE TABLE IF NOT EXISTS forward_rules (
  id TEXT PRIMARY KEY,
  source_addr TEXT NOT NULL,
  target_addr TEXT,
  fallback_webhook TEXT,
  fallback_platform TEXT, -- 可选：feishu | dingtalk | generic
  enabled INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_forward_source ON forward_rules(source_addr);

-- 配置表（键值对）
CREATE TABLE IF NOT EXISTS kv_config (
  k TEXT PRIMARY KEY,
  v TEXT
);

