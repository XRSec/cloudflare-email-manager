#!/bin/bash

# =====================================================
# 验证数据库修复脚本
# =====================================================

echo "======================================"
echo "验证数据库表的 updated_at 列"
echo "======================================"
echo ""

# 需要检查的表
tables=("emails" "attachments" "forward_logs")

echo "检查需要修复的表..."
echo ""

for table in "${tables[@]}"; do
    echo "📋 检查表: $table"
    result=$(wrangler d1 execute cem-db --command "PRAGMA table_info($table);" 2>&1 | grep -c "updated_at")
    
    if [ "$result" -gt 0 ]; then
        echo "✅ 表 $table 已包含 updated_at 列"
    else
        echo "❌ 表 $table 缺少 updated_at 列 - 需要修复"
    fi
    echo ""
done

echo "======================================"
echo "如果有缺失的列，请执行："
echo "wrangler d1 execute cem-db --file=db/fix_missing_updated_at.sql"
echo "======================================" 