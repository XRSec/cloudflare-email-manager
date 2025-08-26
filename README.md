# Cloudflare 临时邮箱管理系统 (CEM)

一个基于 Cloudflare Workers 的现代化临时邮箱管理系统，支持邮件接收、存储、转发、附件管理等功能。

## ✨ 功能特性

### 🚀 核心功能
- **邮件接收**: 通过 Cloudflare Email Routing 自动接收邮件
- **邮件存储**: 使用 Cloudflare D1 数据库存储邮件内容
- **附件支持**: 支持最大 50MB 的邮件附件，存储在 Cloudflare R2 中
- **自动清理**: 可配置的邮件自动清理机制
- **邮件解析**: 完整的 MIME 邮件解析，支持 HTML 和纯文本

### 👥 用户管理
- **用户注册**: 支持用户自由注册（可配置开关）
- **随机前缀**: 自动生成随机邮件前缀，确保唯一性
- **权限控制**: 管理员和普通用户权限分离
- **账户设置**: 支持修改密码、配置 webhook 等

### 🔄 邮件转发
- **Webhook 支持**: 支持钉钉、飞书等平台
- **转发规则**: 管理员可配置复杂的邮件转发规则
- **过滤条件**: 支持按发件人、关键字、收件人等条件过滤
- **签名验证**: 支持 webhook 签名验证

### 🎨 用户界面
- **现代化 UI**: 基于 Vue 3 + Naive UI 的响应式界面
- **中文支持**: 完整的中文本地化
- **邮件管理**: 支持搜索、过滤、分页等
- **附件下载**: 一键下载邮件附件

## 🏗️ 技术架构

- **后端**: Cloudflare Workers + D1 数据库 + R2 存储 + KV 存储
- **前端**: Vue 3 + Naive UI + Vite
- **部署**: Wrangler CLI
- **邮件处理**: 自定义 MIME 解析器

## 🚀 快速开始

### 1. 环境要求

- Node.js 16+
- Wrangler CLI
- Cloudflare 账户

### 2. 安装依赖

```bash
npm install
```

### 3. 配置环境

复制配置文件模板：

```bash
cp wrangler.example.toml wrangler.toml
```

编辑 `wrangler.toml` 文件，配置你的域名和其他设置。

### 4. 部署

运行部署脚本：

```bash
node deploy.js
```

或者使用 shell 脚本：

```bash
./deploy.sh
```

部署脚本会自动：
- 创建 D1 数据库
- 创建 R2 存储桶
- 创建 KV 命名空间
- 配置环境变量
- 初始化管理员账户

### 5. 配置 Cloudflare Email Routing

在 Cloudflare 控制台中配置 Email Routing，将邮件路由到你的 Worker。

## 📁 项目结构

```
├── frontend/                 # 前端代码
│   ├── src/
│   │   ├── views/           # 页面组件
│   │   ├── components/      # 通用组件
│   │   ├── api/             # API 接口
│   │   └── store/           # 状态管理
├── worker/                   # Worker 相关文件
├── new_worker.ts            # 主要的 Worker 代码
├── new_db_schema.sql        # 数据库架构
├── deploy.js                # 部署脚本
├── wrangler.example.toml    # 配置文件模板
└── README.md                # 项目说明
```

## 🔧 配置说明

### 环境变量

- `DOMAIN`: 你的邮件域名
- `JWT_SECRET`: JWT 签名密钥
- `ALLOW_REGISTRATION`: 是否允许用户注册
- `CLEANUP_DAYS`: 邮件自动清理天数
- `MAX_ATTACHMENT_SIZE`: 最大附件大小（字节）

### 数据库表结构

- `users`: 用户信息表
- `emails`: 邮件内容表
- `attachments`: 附件信息表
- `forward_rules`: 转发规则表
- `system_settings`: 系统设置表
- `forward_logs`: 转发日志表

## 📖 API 文档

### 用户相关

- `POST /api/register` - 用户注册
- `POST /api/login` - 用户登录
- `GET /api/user/settings` - 获取用户设置
- `PUT /api/user/settings` - 更新用户设置

### 邮件相关

- `GET /api/mails` - 获取邮件列表
- `GET /api/mails/:id` - 获取邮件详情
- `DELETE /api/mails/:id` - 删除邮件
- `GET /api/attachments/:id/download` - 下载附件

### 管理员功能

- `GET /api/admin/users` - 获取用户列表
- `POST /api/admin/users` - 创建用户
- `DELETE /api/admin/users/:id` - 删除用户
- `GET /api/admin/forward-rules` - 获取转发规则
- `POST /api/admin/forward-rules` - 创建转发规则
- `GET /api/admin/settings` - 获取系统设置
- `PUT /api/admin/settings` - 更新系统设置

## 🎯 使用场景

- **临时邮箱**: 注册网站时使用临时邮箱
- **邮件转发**: 将重要邮件自动转发到其他平台
- **邮件归档**: 长期保存和搜索邮件内容
- **附件管理**: 安全存储和下载邮件附件
- **团队协作**: 管理员可以管理多个用户账户

## 🔒 安全特性

- JWT 身份验证
- 密码哈希存储
- 权限控制
- Webhook 签名验证
- SQL 注入防护

## 🚧 开发说明

### 本地开发

```bash
# 启动前端开发服务器
cd frontend
npm run dev

# 启动 Worker 开发服务器
wrangler dev
```

### 代码规范

- 使用 TypeScript
- 添加中文注释
- 遵循 ESLint 规则
- 使用 Prettier 格式化

## 📝 更新日志

### v1.0.0
- 初始版本发布
- 支持基本的邮件接收和存储
- 用户注册和登录功能
- 管理员控制台
- 邮件转发规则配置

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License

## 🆘 常见问题

### Q: 如何配置邮件域名？
A: 在 Cloudflare 控制台中配置 Email Routing，将邮件路由到你的 Worker。

### Q: 如何备份数据？
A: 使用 `wrangler d1 export` 命令导出数据库，使用 `wrangler r2 object list` 查看存储的文件。

### Q: 如何自定义邮件清理策略？
A: 在管理员控制台的系统设置中修改 `cleanup_days` 参数。

### Q: 支持哪些 webhook 平台？
A: 目前支持钉钉、飞书和自定义 webhook，可以轻松扩展支持其他平台。

## 📞 联系方式

如有问题，请通过以下方式联系：
- 提交 GitHub Issue
- 发送邮件到项目维护者

---

**注意**: 这是一个开源项目，请在生产环境中谨慎使用，并确保遵守相关法律法规。