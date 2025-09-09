-- =====================================================
-- 精确修复脚本 - 只添加缺失的 updated_at 列
-- 基于实际数据库检查结果
-- 使用方法: wrangler d1 execute cem-db --file=db/fix_missing_updated_at.sql
-- =====================================================

-- 1. 为 emails 表添加 updated_at 列
ALTER TABLE emails ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- 2. 为 attachments 表添加 updated_at 列
ALTER TABLE attachments ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- 3. 为 forward_logs 表添加 updated_at 列
ALTER TABLE forward_logs ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- 4. 更新现有记录的 updated_at 为当前时间
UPDATE emails SET updated_at = created_at WHERE updated_at IS NULL;
UPDATE attachments SET updated_at = created_at WHERE updated_at IS NULL;
UPDATE forward_logs SET updated_at = sent_at WHERE updated_at IS NULL;

-- =====================================================
-- 修复完成！
-- =====================================================