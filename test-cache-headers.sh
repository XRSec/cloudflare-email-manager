#!/bin/bash

# 测试缓存头脚本
# 用法: ./test-cache-headers.sh <JWT_TOKEN> <EMAIL_ID> <ATTACHMENT_ID>

TOKEN=$1
EMAIL_ID=$2
ATTACHMENT_ID=$3

if [ -z "$TOKEN" ] || [ -z "$EMAIL_ID" ] || [ -z "$ATTACHMENT_ID" ]; then
    echo "用法: ./test-cache-headers.sh <JWT_TOKEN> <EMAIL_ID> <ATTACHMENT_ID>"
    echo ""
    echo "示例:"
    echo "./test-cache-headers.sh 'eyJ...' 'f167d374-5085-43dd-8edc-e0e521b9f9e2' '29e7b2e5-410f-420e-a1f5-1d078690cfae'"
    exit 1
fi

URL="http://localhost:8787/api/emails/${EMAIL_ID}/attachments/${ATTACHMENT_ID}"

echo "======================================"
echo "测试缓存头"
echo "======================================"
echo ""
echo "URL: $URL"
echo ""

echo "1️⃣  首次请求（应该返回 200 + 缓存头）:"
echo "--------------------------------------"
RESPONSE=$(curl -i -s -H "Authorization: Bearer $TOKEN" "$URL")
echo "$RESPONSE" | head -20
echo ""

# 提取 ETag
ETAG=$(echo "$RESPONSE" | grep -i "etag:" | cut -d' ' -f2- | tr -d '\r')

if [ -n "$ETAG" ]; then
    echo "✅ 找到 ETag: $ETAG"
    echo ""
    
    echo "2️⃣  第二次请求（带 If-None-Match，应该返回 304）:"
    echo "--------------------------------------"
    curl -i -s -H "Authorization: Bearer $TOKEN" -H "If-None-Match: $ETAG" "$URL" | head -20
    echo ""
else
    echo "❌ 没有找到 ETag！"
    echo ""
    echo "完整响应头:"
    echo "$RESPONSE" | sed '/^$/q'
    echo ""
fi

echo "======================================"
echo "检查项："
echo "======================================"
echo ""
echo "✅ 应该看到的响应头："
echo "  - ETag: \"...\"" 
echo "  - Cache-Control: public, max-age=31536000, immutable"
echo "  - Last-Modified: ..."
echo "  - Vary: Authorization"
echo ""
echo "✅ 第二次请求应该返回："
echo "  - HTTP/1.1 304 Not Modified"
echo ""

