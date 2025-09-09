-- =====================================================
-- 数据库修复脚本 - 添加缺失的 updated_at 列
-- 使用方法: wrangler d1 execute cem-db --file=db/fix_updated_at.sql
-- =====================================================

-- 检查并添加 users 表的 updated_at 列
ALTER TABLE users ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- 检查并添加 emails 表的 updated_at 列
ALTER TABLE emails ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- 检查并添加 attachments 表的 updated_at 列
ALTER TABLE attachments ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- 检查并添加 forward_rules 表的 updated_at 列
ALTER TABLE forward_rules ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- 检查并添加 system_settings 表的 updated_at 列
ALTER TABLE system_settings ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- 检查并添加 forward_logs 表的 updated_at 列
ALTER TABLE forward_logs ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- 更新所有现有记录的 updated_at 为当前时间
UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL;
UPDATE emails SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL;
UPDATE attachments SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL;
UPDATE forward_rules SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL;
UPDATE system_settings SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL;
UPDATE forward_logs SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL;

-- =====================================================
-- 修复完成
-- =====================================================