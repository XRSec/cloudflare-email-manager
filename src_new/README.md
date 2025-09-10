# 临时邮箱管理系统 - Vue 3 版本

基于 Cloudflare Workers + D1 + R2 的临时邮箱管理系统，使用 Vue 3 + TypeScript 重构的前端版本。

## 🚀 特性

- ⚡ **Vue 3 + TypeScript**: 现代化的前端技术栈
- 🎨 **响应式设计**: 完美支持桌面和移动端
- 📦 **Pinia 状态管理**: 类型安全的状态管理方案
- 🛣️ **Vue Router**: 单页应用路由管理
- 🔧 **Vite 构建**: 快速的开发和构建体验
- ☁️ **Cloudflare 集成**: 无缝部署到 Cloudflare Workers

## 📋 功能对比

### 原版功能
- ✅ 邮件接收和存储
- ✅ 附件支持 (最大 50MB)
- ✅ 用户认证和授权
- ✅ 管理员功能
- ✅ Webhook 转发
- ✅ 自动清理
- ✅ 调试工具

### Vue 3 版本新增
- 🎯 **组件化架构**: 可维护的组件化设计
- 🔄 **响应式状态**: 实时数据更新
- 📱 **移动端优化**: 更好的移动端体验
- 🎨 **现代 UI**: 美观的用户界面
- ⚡ **性能优化**: 更快的加载和交互
- 🧪 **类型安全**: 完整的 TypeScript 支持

## 🏗️ 项目结构

```
src_new/
├── src/
│   ├── components/          # Vue 组件
│   │   ├── common/         # 通用组件
│   │   └── admin/          # 管理员组件
│   ├── views/              # 页面视图
│   │   ├── admin/          # 管理员页面
│   │   ├── Login.vue       # 登录页面
│   │   ├── Dashboard.vue   # 仪表盘
│   │   ├── Emails.vue      # 邮件列表
│   │   ├── Settings.vue    # 个人设置
│   │   └── Debug.vue       # 调试工具
│   ├── stores/             # Pinia 状态管理
│   │   ├── auth.ts         # 认证状态
│   │   ├── system.ts       # 系统状态
│   │   ├── emails.ts       # 邮件状态
│   │   ├── user.ts         # 用户状态
│   │   └── admin.ts        # 管理员状态
│   ├── services/           # API 服务
│   │   └── api.ts          # HTTP 客户端
│   ├── types/              # TypeScript 类型定义
│   │   └── index.ts        # 通用类型
│   ├── utils/              # 工具函数
│   ├── assets/             # 静态资源
│   │   └── css/            # 样式文件
│   ├── router/             # 路由配置
│   │   └── index.ts        # 路由定义
│   ├── main.ts             # 应用入口
│   ├── App.vue             # 根组件
│   └── worker.ts           # Cloudflare Workers 集成
├── public/                 # 公共资源
├── dist/                   # 构建输出
├── index.html              # HTML 模板
├── vite.config.ts          # Vite 配置
├── vite.config.worker.ts   # Workers 构建配置
├── tsconfig.json           # TypeScript 配置
├── wrangler.toml           # Cloudflare 配置
└── package.json            # 项目配置
```

## 🛠️ 开发指南

### 环境要求

- Node.js 18+
- npm 或 yarn
- Cloudflare 账户

### 安装依赖

```bash
cd src_new
npm install
```

### 开发模式

```bash
# 启动前端开发服务器
npm run dev

# 启动 Cloudflare Workers 开发服务器
npm run dev:worker
```

### 构建和部署

```bash
# 构建前端和 Workers
npm run build

# 部署到 Cloudflare
npm run deploy
```

## 🎨 技术栈

### 前端技术

- **Vue 3**: 渐进式 JavaScript 框架
- **TypeScript**: 类型安全的 JavaScript 超集
- **Pinia**: Vue 3 官方推荐的状态管理库
- **Vue Router**: Vue.js 官方路由管理器
- **Vite**: 下一代前端构建工具
- **Axios**: HTTP 客户端库

### 后端技术

- **Cloudflare Workers**: 边缘计算平台
- **Hono**: 轻量级 Web 框架
- **D1**: Cloudflare 的 SQLite 数据库
- **R2**: Cloudflare 的对象存储
- **KV**: Cloudflare 的键值存储

## 📱 功能截图

### 登录界面
- 支持用户登录和注册
- 响应式设计，支持移动端
- 表单验证和错误处理

### 仪表盘
- 侧边栏导航
- 用户信息展示
- 管理员权限控制

### 邮件管理
- 邮件列表和搜索
- 邮件详情查看
- 附件下载
- 分页和过滤

### 个人设置
- 密码修改
- Webhook 配置
- 账户信息查看

### 管理员功能
- 用户管理
- 转发规则配置
- 系统设置
- 邮件监控

### 调试工具
- 模拟邮件发送
- API 测试
- 系统状态监控
- 操作日志

## 🔧 配置说明

### Cloudflare 配置

复制 `wrangler.example.toml` 到 `wrangler.toml` 并配置：

```toml
name = "your-worker-name"
main = "dist/worker.js"

[[d1_databases]]
binding = "DB"
database_name = "your-db-name"
database_id = "your-database-id"

[[r2_buckets]]
binding = "R2"
bucket_name = "your-bucket-name"

[[kv_namespaces]]
binding = "KV"
id = "your-kv-namespace-id"
```

### 环境变量

在 Cloudflare Workers 中配置以下环境变量：

- `JWT_SECRET`: JWT 签名密钥
- `DOMAIN`: 邮件域名
- `cem_debug`: 调试模式开关

## 🚦 部署流程

1. **准备环境**
   ```bash
   npm install
   npm run build
   ```

2. **配置 Cloudflare**
   - 创建 D1 数据库
   - 创建 R2 存储桶
   - 创建 KV 命名空间
   - 配置邮件路由

3. **部署应用**
   ```bash
   npm run deploy
   ```

4. **初始化数据库**
   ```bash
   wrangler d1 execute your-db-name --file=../db/schema.sql --remote
   ```

## 🔍 API 接口

### 认证接口
- `POST /api/login` - 用户登录
- `POST /api/register` - 用户注册
- `POST /api/logout` - 用户登出

### 用户接口
- `GET /api/protected/me` - 获取当前用户
- `GET /api/protected/emails` - 获取邮件列表
- `GET /api/protected/emails/:id` - 获取邮件详情
- `DELETE /api/protected/emails/:id` - 删除邮件
- `GET /api/protected/settings` - 获取用户设置
- `PUT /api/protected/settings` - 更新用户设置

### 管理员接口
- `GET /api/admin/users` - 获取用户列表
- `DELETE /api/admin/users/:id` - 删除用户
- `GET /api/admin/settings` - 获取系统设置
- `PUT /api/admin/settings` - 更新系统设置

### 系统接口
- `GET /api/system/config` - 获取系统配置

## 🐛 常见问题

### 1. 构建失败

确保安装了所有依赖：
```bash
npm install
```

### 2. 部署失败

检查 `wrangler.toml` 配置是否正确，确保所有绑定资源已创建。

### 3. 邮件接收失败

检查邮件路由配置，确保指向正确的 Worker。

### 4. 权限错误

确保 JWT_SECRET 配置正确，检查用户认证状态。

## 📚 相关文档

- [Vue 3 官方文档](https://vuejs.org/)
- [TypeScript 官方文档](https://www.typescriptlang.org/)
- [Pinia 官方文档](https://pinia.vuejs.org/)
- [Vite 官方文档](https://vitejs.dev/)
- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)

## 🤝 贡献指南

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

## 📄 许可证

MIT License - 详见 [LICENSE](../LICENSE) 文件

## 🙏 致谢

- Vue.js 团队提供的优秀框架
- Cloudflare 提供的边缘计算平台
- 所有贡献者和用户的支持

---

**注意**: 这是原项目的 Vue 3 + TypeScript 重构版本，保持了所有核心功能的同时提供了更好的开发体验和用户体验。