#!/bin/bash

# 临时邮箱系统部署脚本
# 自动化部署到 Cloudflare Workers

set -e  # 遇到错误时停止执行

echo "🚀 开始部署临时邮箱系统..."

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查是否已安装 wrangler
if ! command -v wrangler &> /dev/null; then
    echo -e "${RED}❌ Wrangler CLI 未安装${NC}"
    echo "请运行: npm install -g wrangler"
    exit 1
fi

# 检查是否已登录
echo -e "${BLUE}🔐 检查 Cloudflare 登录状态...${NC}"
if ! wrangler whoami &> /dev/null; then
    echo -e "${YELLOW}⚠️  未登录 Cloudflare，正在启动登录流程...${NC}"
    wrangler login
fi

echo -e "${GREEN}✅ Cloudflare 登录状态正常${NC}"

# 读取配置
read -p "请输入您的域名 (例如: example.com): " DOMAIN
read -p "请输入环境 (development/production) [production]: " ENVIRONMENT
ENVIRONMENT=${ENVIRONMENT:-production}

# 验证域名格式
if [[ ! $DOMAIN =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
    echo -e "${RED}❌ 域名格式无效${NC}"
    exit 1
fi

echo -e "${BLUE}📋 部署配置:${NC}"
echo "  域名: $DOMAIN"
echo "  环境: $ENVIRONMENT"

# 生成 JWT 密钥
JWT_SECRET=$(openssl rand -base64 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || echo "$(date +%s)$(whoami)$(hostname)" | sha256sum | cut -d' ' -f1)

echo -e "${YELLOW}🔑 生成的 JWT 密钥: $JWT_SECRET${NC}"
echo -e "${YELLOW}⚠️  请保存此密钥，丢失后需要重新生成！${NC}"

# 检查必要文件
echo -e "${BLUE}📁 检查项目文件...${NC}"
required_files=(
    "wrangler.toml"
    "package.json"
    "new_db_schema.sql"
    "src/index.ts"
    "static/index.html"
)

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}❌ 缺少必要文件: $file${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✅ 项目文件检查完成${NC}"

# 安装依赖
echo -e "${BLUE}📦 安装项目依赖...${NC}"
npm install

# 创建 Cloudflare 资源
echo -e "${BLUE}☁️  创建 Cloudflare 资源...${NC}"
# 创建 D1 数据库
echo "创建 D1 数据库..."
DB_NAME="cem-db"
if [ "$ENVIRONMENT" = "development" ]; then
    DB_NAME="cem-db-dev"
fi

DB_OUTPUT=$(wrangler d1 create $DB_NAME 2>&1 || true)
if echo "$DB_OUTPUT" | grep -q "already exists"; then
    echo -e "${YELLOW}⚠️  数据库 $DB_NAME 已存在${NC}"
    DB_ID=$(wrangler d1 list | grep $DB_NAME | awk '{print $2}')
else
    DB_ID=$(echo "$DB_OUTPUT" | awk -F'database_id = "' '/database_id/ {split($2,a,"\""); print a[1]}')
    echo -e "${GREEN}✅ 数据库创建成功: $DB_ID${NC}"
fi

# 创建 R2 存储桶
echo "创建 R2 存储桶..."
BUCKET_NAME="cem-r2"
if [ "$ENVIRONMENT" = "development" ]; then
    BUCKET_NAME="cem-r2-dev"
fi

if wrangler r2 bucket create $BUCKET_NAME 2>&1 | grep -q "already exists"; then
    echo -e "${YELLOW}⚠️  存储桶 $BUCKET_NAME 已存在${NC}"
else
    echo -e "${GREEN}✅ 存储桶创建成功: $BUCKET_NAME${NC}"
fi

# 创建 KV 命名空间
echo "创建 KV 命名空间..."
KV_NAME="cem-kv"
if [ "$ENVIRONMENT" = "development" ]; then
    KV_NAME="cem-kv-dev"
fi

KV_OUTPUT=$(wrangler kv namespace create "$KV_NAME" 2>&1 || true)
if echo "$KV_OUTPUT" | grep -q "already exists"; then
    echo -e "${YELLOW}⚠️  KV 命名空间 $KV_NAME 已存在${NC}"
    KV_ID=$(wrangler kv namespace list | jq -r --arg NAME "$KV_NAME" '.[] | select(.title==$NAME) | .id')
else
    KV_ID=$(echo "$KV_OUTPUT" | awk -F'id = "' '/id = "/ {split($2,a,"\""); print a[1]}')
    echo -e "${GREEN}✅ KV 命名空间创建成功: $KV_ID${NC}"
fi

# 更新 wrangler.toml 配置
echo -e "${BLUE}⚙️  更新配置文件...${NC}"

# 备份原配置
cp wrangler.toml wrangler.toml.backup
# 使用 sed 更新配置 (跨平台兼容)
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    if [ "$ENVIRONMENT" = "production" ]; then
        sed -i '' "s|your-domain.com|$DOMAIN|g" wrangler.toml
        sed -i '' "s|your-jwt-secret-key|$JWT_SECRET|g" wrangler.toml
        sed -i '' "s|your-d1-database-id|$DB_ID|g" wrangler.toml
        sed -i '' "s|your-kv-namespace-id|$KV_ID|g" wrangler.toml
    else
        sed -i '' "s|your-dev-d1-database-id|$DB_ID|g" wrangler.toml
        sed -i '' "s|your-dev-kv-namespace-id|$KV_ID|g" wrangler.toml
    fi
else
    # Linux
    if [ "$ENVIRONMENT" = "production" ]; then
        sed -i "s|your-domain.com|$DOMAIN|g" wrangler.toml
        sed -i "s|your-jwt-secret-key|$JWT_SECRET|g" wrangler.toml
        sed -i "s|your-d1-database-id|$DB_ID|g" wrangler.toml
        sed -i "s|your-kv-namespace-id|$KV_ID|g" wrangler.toml
    else
        sed -i "s|your-dev-d1-database-id|$DB_ID|g" wrangler.toml
        sed -i "s|your-dev-kv-namespace-id|$KV_ID|g" wrangler.toml
    fi
fi

echo -e "${GREEN}✅ 配置文件更新完成${NC}"

# 初始化数据库
echo -e "${BLUE}🗄️  初始化数据库...${NC}"
wrangler d1 execute $DB_NAME --file=./new_db_schema.sql --env=$ENVIRONMENT || true

echo -e "${GREEN}✅ 数据库初始化完成${NC}"

# 创建管理员用户
echo -e "${BLUE}👤 创建管理员账户...${NC}"

read -p "请输入管理员邮箱前缀 (例如: admin): " ADMIN_PREFIX
read -s -p "请输入管理员密码: " ADMIN_PASSWORD
echo

# 生成密码哈希 (简单实现)
ADMIN_PASSWORD_HASH=$(echo -n "$ADMIN_PASSWORD" | sha256sum | cut -d' ' -f1)

# 插入管理员用户
wrangler d1 execute $DB_NAME --command="INSERT OR IGNORE INTO users (email_prefix, email_password, user_type) VALUES ('${ADMIN_PREFIX:-admin}', '$ADMIN_PASSWORD_HASH', 'admin')" --env=$ENVIRONMENT

echo -e "${GREEN}✅ 管理员账户创建完成${NC}"
echo -e "${YELLOW}📧 管理员邮箱: $ADMIN_PREFIX@$DOMAIN${NC}"

# 部署 Worker
echo -e "${BLUE}🚀 部署 Worker...${NC}"

if [ "$ENVIRONMENT" = "development" ]; then
    wrangler deploy --env development
else
    wrangler deploy --env production
fi

echo -e "${GREEN}✅ Worker 部署完成${NC}"

# 设置自定义域名
if [ "$ENVIRONMENT" = "production" ]; then
    echo -e "${BLUE}🌐 配置自定义域名...${NC}"
    
    read -p "是否要配置自定义域名? (y/n) [y]: " SETUP_DOMAIN
    SETUP_DOMAIN=${SETUP_DOMAIN:-y}
    
    if [[ $SETUP_DOMAIN =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}请在 Cloudflare 控制台中手动配置以下设置:${NC}"
        echo "1. 添加域名到 Cloudflare"
        echo "2. 在 Workers & Pages 中绑定自定义域名"
        echo "3. 在 Email Routing 中配置路由规则"
        echo "   规则: *@$DOMAIN → Send to Worker → cloudflare-email-manager"
    fi
fi

# 部署完成
echo -e "${GREEN}🎉 部署完成!${NC}"
echo
echo -e "${BLUE}📋 部署信息:${NC}"
echo "  域名: $DOMAIN"
echo "  环境: $ENVIRONMENT"
echo "  管理员: $ADMIN_PREFIX@$DOMAIN"
echo "  D1 数据库 ID: $DB_ID"
echo "  KV 命名空间 ID: $KV_ID"
echo "  R2 存储桶: $BUCKET_NAME"
echo
echo -e "${YELLOW}📝 重要提醒:${NC}"
echo "1. 请保存 JWT 密钥: $JWT_SECRET"
echo "2. 请在 Cloudflare 控制台配置邮件路由"
echo "3. 配置文件已备份为 wrangler.toml.backup"
echo "4. 管理员密码请妥善保管"
echo
echo -e "${GREEN}🌐 访问地址:${NC}"
if [ "$ENVIRONMENT" = "development" ]; then
    echo "  开发环境: http://localhost:8787"
    echo "  启动开发服务器: npm run dev"
else
    echo "  生产环境: https://$DOMAIN"
    echo "  Worker 地址: https://cloudflare-email-manager.your-subdomain.workers.dev"
fi
echo
echo -e "${BLUE}📚 更多信息请查看 README.md${NC}"

# 询问是否启动开发服务器
if [ "$ENVIRONMENT" = "development" ]; then
    read -p "是否启动开发服务器? (y/n) [y]: " START_DEV
    START_DEV=${START_DEV:-y}
    
    if [[ $START_DEV =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}🚀 启动开发服务器...${NC}"
        npm run dev
    fi
fi