#!/bin/bash

# 迁移脚本 - 将项目拆分为 Pages（前端）和 Workers（后端）

echo "🚀 开始迁移到 Cloudflare Pages + Workers 架构..."

# 1. 创建前端目录
echo "📁 创建前端目录..."
mkdir -p frontend/css
mkdir -p frontend/js

# 2. 提取 HTML
echo "📄 提取 HTML 文件..."
cp src/templates/index.html frontend/index.html

# 3. 提取 CSS（从 HTML 中提取 style 标签内容）
echo "🎨 提取 CSS..."
cat > frontend/css/styles.css << 'EOF'
/* 这里需要手动从 index.html 中提取 <style> 标签的内容 */
/* 临时占位符 */
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
EOF

# 4. 提取 JavaScript（从 HTML 中提取 script 标签内容）
echo "📜 提取 JavaScript..."
cat > frontend/js/app.js << 'EOF'
/* 这里需要手动从 index.html 中提取 <script> 标签的内容 */
/* 临时占位符 */
console.log('Frontend loaded');
EOF

# 5. 创建 Pages 配置
echo "⚙️ 创建 Pages 配置..."
cat > frontend/package.json << 'EOF'
{
  "name": "cem-frontend",
  "version": "1.0.0",
  "scripts": {
    "dev": "npx serve .",
    "build": "echo 'No build needed for static files'"
  }
}
EOF

# 6. 创建部署配置
echo "📝 创建部署配置..."
cat > frontend/.gitignore << 'EOF'
node_modules/
.DS_Store
EOF

# 7. 创建说明文档
cat > frontend/README.md << 'EOF'
# CEM 前端

这是临时邮箱管理系统的前端部分，使用 Cloudflare Pages 托管。

## 部署

```bash
# 首次部署
wrangler pages project create cem-frontend

# 部署更新
wrangler pages deploy . --project-name=cem-frontend
```

## 本地开发

```bash
npm run dev
# 访问 http://localhost:3000
```

## 配置

修改 `js/app.js` 中的 API 地址：
```javascript
const API_BASE = 'https://your-worker.workers.dev';
```
EOF

echo "✅ 迁移准备完成！"
echo ""
echo "📋 下一步操作："
echo "1. 手动提取 HTML 中的 <style> 内容到 frontend/css/styles.css"
echo "2. 手动提取 HTML 中的 <script> 内容到 frontend/js/app.js"
echo "3. 更新 frontend/index.html，引用外部 CSS 和 JS 文件"
echo "4. 在 frontend/js/app.js 中配置 API 地址"
echo "5. 部署前端: cd frontend && wrangler pages deploy ."
echo "6. 更新后端 CORS 设置，允许 Pages 域名访问"
echo ""
echo "详细说明请查看 DEPLOYMENT_STRATEGY.md"