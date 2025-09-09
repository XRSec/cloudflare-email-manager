#!/bin/bash

# =====================================================
# 数据库表结构检查脚本
# 用于检查所有表是否包含 updated_at 列
# =====================================================

echo "======================================"
echo "Cloudflare D1 数据库结构检查工具"
echo "======================================"
echo ""

# 定义数据库名称
DB_NAME="cem-db"

# 定义要检查的表
tables=("users" "emails" "attachments" "forward_rules" "system_settings" "forward_logs")

echo "开始检查数据库表结构..."
echo ""

# 检查每个表
for table in "${tables[@]}"; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📋 检查表: $table"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # 获取表的所有列信息
    echo "执行命令: wrangler d1 execute $DB_NAME --command \"PRAGMA table_info($table);\""
    echo ""
    
    result=$(wrangler d1 execute $DB_NAME --command "PRAGMA table_info($table);" 2>&1)
    
    if echo "$result" | grep -q "updated_at"; then
        echo "✅ 表 $table 包含 updated_at 列"
        echo "$result" | grep "updated_at"
    else
        echo "❌ 表 $table 缺少 updated_at 列或表不存在"
        echo "详细信息："
        echo "$result"
    fi
    
    echo ""
done

echo "======================================"
echo "检查完成！"
echo ""
echo "如果发现缺少 updated_at 列，请执行以下命令修复："
echo "wrangler d1 execute $DB_NAME --file=db/fix_updated_at.sql"
echo ""
echo "或者重新初始化数据库（会清空数据）："
echo "wrangler d1 execute $DB_NAME --file=db/schema.sql"
echo "======================================" 