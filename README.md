# 🚀 简洁临时邮箱系统

基于 Cloudflare Workers 构建的现代化临时邮箱服务，支持邮件接收、附件存储、智能转发等功能。

## ✨ 主要特性

### 📧 邮件处理
- 🔥 **高性能邮件接收** - 基于 Cloudflare Email Routing
- 📎 **附件支持** - 最大支持50MB附件，存储在R2
- 🗄️ **数据持久化** - 使用D1数据库存储邮件数据
- 🧹 **自动清理** - 可配置的自动清理策略

### 👥 用户管理
- 🔐 **安全认证** - JWT Token + 密码认证
- 🎲 **随机前缀** - 自动生成邮箱前缀，保护隐私
- 👨‍💼 **角色管理** - 支持普通用户和管理员角色
- ⚙️ **个人设置** - 支持修改密码、Webhook等

### 🔗 智能转发
- 🤖 **Webhook支持** - 钉钉、飞书、自定义Webhook
- 📋 **规则配置** - 灵活的转发规则设置
- 🔍 **条件过滤** - 发件人、关键词、收件人过滤
- 🔐 **签名验证** - 支持Webhook签名验证

### 🛡️ 安全特性
- 🚫 **防SQL注入** - 完善的输入验证和清理
- 🚦 **限流保护** - 基于IP的请求频率限制
- 🔒 **登录保护** - 失败尝试次数限制
- 📝 **安全日志** - 详细的安全事件记录

### 💻 管理功能
- 👥 **用户管理** - 创建、删除、查看用户
- 📊 **统计信息** - 邮件、用户、附件统计
- ⚙️ **系统设置** - 注册开关、清理配置等
- 📄 **转发日志** - 详细的转发记录

## 🏗️ 技术架构

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   前端界面      │    │  Cloudflare      │    │    外部服务     │
│   (静态文件)    │◄──►│    Workers       │◄──►│   (钉钉/飞书)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
            ┌─────────────────────────────────────────┐
            │              数据层                      │
            ├─────────────┬─────────────┬─────────────┤
            │     D1      │     R2      │     KV      │
            │   数据库    │  附件存储   │   缓存层    │
            └─────────────┴─────────────┴─────────────┘
```

- **前端**: 纯HTML/CSS/JavaScript，集成在Workers中
- **后端**: Cloudflare Workers + Hono框架
- **数据库**: Cloudflare D1 (SQLite)
- **存储**: Cloudflare R2 (附件存储)
- **缓存**: Cloudflare KV (限流、会话等)

## 🚀 快速开始

### 1. 环境准备

```bash
# 安装依赖
npm install

# 安装 Wrangler CLI
npm install -g wrangler

# 登录 Cloudflare
wrangler auth login
```

### 2. 创建资源

```bash
# 创建 D1 数据库
wrangler d1 create temp-email-db

# 创建 R2 存储桶
wrangler r2 bucket create temp-email-attachments

# 创建 KV 命名空间
wrangler kv:namespace create "temp-email-kv"
```

### 3. 配置环境

编辑 `wrangler.toml` 文件，填入上一步创建的资源ID：

```toml
# 更新数据库ID
database_id = "your-d1-database-id"

# 更新KV命名空间ID
id = "your-kv-namespace-id"

# 更新域名配置
DOMAIN = "your-domain.com"
JWT_SECRET = "your-strong-jwt-secret"
```

### 4. 初始化数据库

```bash
# 创建数据库表
wrangler d1 execute temp-email-db --file=./new_db_schema.sql
```

### 5. 配置邮件路由

在 Cloudflare 控制台中：

1. 进入您的域名管理
2. 启用 Email Routing
3. 创建路由规则：`*@your-domain.com` → `Send to Worker` → `temp-email-system`

### 6. 部署应用

```bash
# 开发模式
npm run dev

# 生产部署
npm run deploy
```

## 📖 使用指南

### 普通用户

#### 1. 注册账户
- 访问您的域名
- 点击"注册"标签
- 设置密码（至少6位）
- 系统自动分配邮箱前缀

#### 2. 查看邮件
- 使用分配的邮箱前缀和密码登录
- 在"邮件列表"中查看收到的邮件
- 支持按发件人、关键词、时间过滤
- 点击邮件查看详情和下载附件

#### 3. 个人设置
- 在"个人设置"中配置Webhook地址
- 设置Webhook签名密钥（可选）
- 修改登录密码

### 管理员

#### 1. 用户管理
- 查看所有用户列表
- 创建新用户（可指定前缀和角色）
- 删除用户及其所有数据
- 向用户发送登录信息

#### 2. 转发规则
- 创建邮件转发规则
- 支持多种过滤条件
- 配置钉钉、飞书或自定义Webhook
- 启用/禁用规则

#### 3. 系统管理
- 配置是否允许用户注册
- 设置邮件保留天数
- 查看系统统计信息
- 手动触发清理任务

## 🔧 配置说明

### 环境变量

| 变量名 | 说明 | 默认值 | 必需 |
|--------|------|--------|------|
| `DOMAIN` | 邮件域名 | - | ✅ |
| `JWT_SECRET` | JWT签名密钥 | - | ✅ |
| `ALLOW_REGISTRATION` | 是否允许注册 | `true` | ❌ |
| `CLEANUP_DAYS` | 邮件保留天数 | `7` | ❌ |
| `MAX_ATTACHMENT_SIZE` | 最大附件大小 | `52428800` | ❌ |
| `MAX_REQUESTS_PER_MINUTE` | 每分钟请求限制 | `60` | ❌ |
| `MAX_LOGIN_ATTEMPTS` | 登录尝试限制 | `5` | ❌ |

### Webhook配置

#### 钉钉机器人
```javascript
{
  "webhook_type": "dingtalk",
  "webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=YOUR_TOKEN",
  "webhook_secret": "YOUR_SECRET"
}
```

#### 飞书机器人
```javascript
{
  "webhook_type": "feishu",
  "webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/YOUR_HOOK_ID",
  "webhook_secret": "YOUR_SECRET"
}
```

#### 自定义Webhook
```javascript
{
  "webhook_type": "custom",
  "webhook_url": "https://your-api.com/webhook",
  "webhook_secret": "YOUR_SECRET"
}
```

## 🛠️ 开发指南

### 项目结构

```
src/
├── index.ts              # 主入口文件
├── api-routes.ts         # API路由定义
├── email-processor.ts    # 邮件处理器
├── webhook.ts           # Webhook系统
├── cleanup.ts           # 清理系统
├── security.ts          # 安全模块
└── static-handler.ts    # 静态文件处理

static/
├── index.html           # 主页面
├── admin.js            # 管理员功能
└── styles.css          # 样式文件

db/
└── schema.sql          # 数据库结构
```

### 本地开发

```bash
# 启动开发服务器
npm run dev

# 代码格式化
npm run format

# 代码检查
npm run lint

# 运行测试
npm test
```

### 数据库操作

```bash
# 执行SQL文件
wrangler d1 execute temp-email-db --file=./path/to/file.sql

# 备份数据库
npm run db:backup

# 查看数据库信息
wrangler d1 info temp-email-db
```

## 🔐 安全最佳实践

1. **强密码**: 使用至少32位的强随机JWT密钥
2. **HTTPS**: 确保所有通信使用HTTPS
3. **限流**: 根据实际需求调整限流参数
4. **监控**: 定期检查安全日志
5. **更新**: 及时更新依赖包和Worker运行时

## 📊 监控和日志

### Cloudflare 控制台
- Workers 执行次数和错误率
- D1 数据库查询统计
- R2 存储使用情况

### 应用日志
- 邮件处理日志
- 安全事件日志
- Webhook发送日志
- 清理任务日志

## 🐛 故障排除

### 常见问题

#### 1. 邮件收不到
- 检查 Email Routing 配置
- 确认 Worker 部署成功
- 查看 Worker 日志

#### 2. 附件下载失败
- 检查 R2 存储桶权限
- 确认附件文件存在
- 查看文件大小限制

#### 3. Webhook 不工作
- 验证 Webhook URL 可访问
- 检查签名配置
- 查看转发日志

### 调试模式

```bash
# 启用详细日志
wrangler dev --local

# 查看实时日志
wrangler tail
```

## 🤝 贡献指南

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 🙏 致谢

- [Cloudflare Workers](https://workers.cloudflare.com/) - 强大的边缘计算平台
- [Hono](https://hono.dev/) - 轻量级Web框架
- [vwh/temp-mail](https://github.com/vwh/temp-mail) - UI设计参考

## 📞 支持

如果您遇到问题或有建议：

- 📧 邮件: your-email@example.com
- 🐛 Issues: [GitHub Issues](https://github.com/your-username/temp-email-system/issues)
- 💬 讨论: [GitHub Discussions](https://github.com/your-username/temp-email-system/discussions)

---

⭐ 如果这个项目对您有帮助，请给它一个星标！