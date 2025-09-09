# 部署策略 - HTML 与后端分离

## 🎯 目标
实现真正的前后端分离，HTML 作为独立文件而不是嵌入到 TypeScript 中。

## 📊 当前问题
- Cloudflare Workers 不支持静态文件服务
- HTML 必须编译成字符串嵌入到 Worker 代码中
- 文件体积大，维护困难

## ✅ 推荐方案：Cloudflare Pages + Workers

### 架构设计
```
┌─────────────────────────┐
│   Cloudflare Pages      │
│   (静态文件托管)         │
│   - index.html          │
│   - styles.css          │
│   - app.js              │
└───────────┬─────────────┘
            │ API 调用
            ↓
┌─────────────────────────┐
│   Cloudflare Workers    │
│   (API 后端)            │
│   - /api/*              │
│   - 邮件处理             │
│   - 数据库操作           │
└─────────────────────────┘
```

### 实施步骤

#### 1. 创建独立的前端项目
```bash
# 创建前端目录
mkdir frontend
cd frontend

# 移动静态文件
mv ../src/templates/index.html ./index.html
```

#### 2. 拆分 HTML 中的内联代码
创建独立的文件：
- `styles.css` - 所有样式
- `app.js` - 所有 JavaScript 代码
- `index.html` - 纯 HTML 结构

#### 3. 配置 Cloudflare Pages
```yaml
# .cloudflare/pages.json
{
  "build": {
    "command": "",
    "directory": "frontend"
  }
}
```

#### 4. 配置 Workers 为纯 API
修改 `src/main.ts`：
```typescript
// 移除 HTML 模板相关代码
// 只保留 API 路由

app.use('*', cors({
    origin: 'https://your-pages.pages.dev', // Pages 域名
    credentials: true
}));
```

#### 5. 部署流程
```bash
# 部署前端到 Pages
cd frontend
wrangler pages deploy .

# 部署后端到 Workers
cd ..
npm run deploy
```

## 🔄 备选方案：Workers Sites（已废弃）

Cloudflare 已经废弃了 Workers Sites，推荐使用 Pages。

## 💡 临时方案：Asset Bindings

如果必须使用单个 Worker，可以使用 Asset Bindings：

### wrangler.toml 配置
```toml
[site]
bucket = "./public"

[[rules]]
type = "Text"
globs = ["**/*.html", "**/*.css", "**/*.js"]
```

### 代码实现
```typescript
// 提供静态文件
app.get('/static/*', async (c) => {
    const path = c.req.path.replace('/static/', '');
    const asset = await c.env.ASSETS.fetch(new Request(`https://fake/${path}`));
    return asset;
});
```

## 🎯 最终推荐

### 短期方案（当前）
继续使用编译模板方式，但优化构建流程：
1. 保持 `src/templates/index.html` 作为源文件
2. 使用 `build-template.js` 自动编译
3. 通过 npm scripts 自动化

### 长期方案（推荐）
迁移到 Cloudflare Pages + Workers 架构：
1. **Pages**: 托管所有静态文件（HTML、CSS、JS、图片等）
2. **Workers**: 只处理 API 请求和邮件接收
3. **优势**:
   - 真正的前后端分离
   - 更好的缓存策略
   - 独立部署和版本控制
   - 支持 CDN 加速

## 📝 迁移计划

### 第一阶段：代码拆分
- [ ] 提取内联 CSS 到 `styles.css`
- [ ] 提取内联 JS 到 `app.js`
- [ ] 清理 HTML，只保留结构

### 第二阶段：项目重构
- [ ] 创建 `frontend/` 目录
- [ ] 配置构建工具（可选 Vite）
- [ ] 设置开发环境代理

### 第三阶段：部署迁移
- [ ] 创建 Cloudflare Pages 项目
- [ ] 配置自定义域名
- [ ] 更新 CORS 设置
- [ ] 测试和优化

## 🔧 开发环境配置

### 本地开发（分离模式）
```json
// package.json
{
  "scripts": {
    "dev:frontend": "vite serve frontend",
    "dev:backend": "wrangler dev",
    "dev": "concurrently \"npm:dev:*\""
  }
}
```

### Vite 配置（可选）
```javascript
// frontend/vite.config.js
export default {
  server: {
    proxy: {
      '/api': 'http://localhost:8787'
    }
  }
}
```

## 📊 对比

| 方案 | 优点 | 缺点 |
|------|------|------|
| **当前（编译模板）** | 简单、单一部署 | 文件大、维护难 |
| **Pages + Workers** | 真正分离、性能好 | 需要两个项目 |
| **Asset Bindings** | 单一项目、支持静态文件 | 配置复杂、性能一般 |

## 🎯 结论

**推荐采用 Cloudflare Pages + Workers 方案**，实现真正的前后端分离。这是 Cloudflare 官方推荐的最佳实践。

---

**更新时间**: 2025年1月
**作者**: AI Assistant