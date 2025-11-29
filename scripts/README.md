# 脚本说明

## 📁 脚本结构

```
scripts/
├── env-detector.js  # 环境检测模块（可复用）
├── deploy.js       # 部署脚本
└── db.js           # 数据库操作脚本
```

## 🚀 使用方法

### 开发环境
```bash
# 启动前端开发服务器
cd vue && npm run dev

# 启动 Worker（API + 后台）
cd worker && npx wrangler dev
```

### 部署
```bash
# 完整部署（包含资源创建、构建、部署）
npm run deploy

# 初始化部署（同 deploy）
npm run init

# 清理所有 Cloudflare 资源
npm run clean
```

### 数据库操作
```bash
# 本地命令
npm run db:init
npm run db:init:remote
npm run db:migrate
npm run db:import

# 执行 SQL 命令或 base64 SQL
npm run db -- "SELECT * FROM users"
npm run db -- U0VMRUNUICogRlJPTSB1c2Vycwo=
```

### 构建
```bash
# 构建前端
npm run build:vue

# 构建后端
npm run build:worker

# 构建所有
npm run build
```

## 🔧 脚本特性

### 1. 环境检测
- `env-detector.js` 提供统一的环境检测功能
- 自动校验本地必需依赖（npx、wrangler）
- 所有脚本共享环境检测逻辑

### 2. 部署脚本
- `deploy.js` 包含完整的部署流程
- 资源创建（D1、KV、R2）
- 用户交互（域名输入、管理员密码等）
- 数据库初始化和管理员账户创建
- 配置文件更新（wrangler.toml）
- 前后端构建和部署

### 3. 数据库脚本
- `db.js` 支持多种数据库操作
- 直接使用 wrangler 执行命令
- 支持 base64 编码的 SQL 命令
- 自动创建和清理临时脚本文件

## 📋 命令对照表

| 功能 | 命令 | 说明 |
|------|------|------|
| 开发 | `cd vue && npm run dev` / `cd worker && npx wrangler dev` | 启动前端与 Worker |
| 构建 | `npm run build` | 构建前端和后端 |
| 部署 | `npm run deploy` | 完整部署（资源创建+构建+部署） |
| 初始化 | `npm run init` | 同 deploy 命令 |
| 清理 | `npm run clean` | 删除所有 Cloudflare 资源 |
| 数据库初始化 | `npm run db:init` | 初始化本地数据库 |
| 远程数据库初始化 | `npm run db:init:remote` | 初始化远程数据库 |
| 数据库迁移 | `npm run db:migrate` | 执行数据库迁移 |
| 导入数据 | `npm run db:import` | 导入邮件数据 |

## 🎉 优势

1. **简洁**：只需记住几个简单的命令
2. **智能**：自动检测环境，无需手动配置
3. **易维护**：JavaScript 脚本，易于理解和修改
4. **统一**：所有操作通过 npm 脚本调用
5. **灵活**：支持参数传递和命令组合