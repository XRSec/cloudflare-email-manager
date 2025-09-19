# Cloudflare 临时邮箱管理系统

基于 Cloudflare Workers 的临时邮箱管理系统，提供完整的邮件接收、存储、发送、转发和管理功能。

## 🏗️ 项目架构

### 一体化部署架构
```
cloudflare-email-manager/
├── vue/              # Vue 3 前端项目
│   ├── src/              # 前端源码
│   └── dist/             # 构建产物（自动生成）
├── worker/               # Cloudflare Worker 后端
│   └── src/              # Worker 源码
├── db/                   # 数据库相关
├── scripts/              # 构建和开发脚本
├── package.json          # 统一依赖管理（前端 + 后端）
├── wrangler.toml         # Cloudflare Worker 配置
└── README.md             # 项目说明
```

### 核心特性
- **前后端一体化部署**：前端通过 Worker 的 ASSETS 绑定提供服务
- **模块化架构**：清晰的前后端分离，便于维护
- **TypeScript 支持**：全栈 TypeScript 开发
- **现代化 UI**：基于 Vue 3 + Naive UI 的响应式界面
- **完整的邮件管理**：接收、存储、发送、转发、附件处理
- **用户权限管理**：支持普通用户和管理员角色
- **Webhook 集成**：支持钉钉、飞书等通知

## 🚀 快速开始

### 环境要求
- Node.js >= 20.19.0
- Docker & Docker Compose
- Cloudflare 账户

### 安装依赖
```bash
# 安装所有依赖（前端 + 后端）
npm install
```

### 开发环境
```bash
# 启动 Docker 容器（前端 + 后端）
docker-compose up -d

# 查看容器状态
docker-compose ps

# 停止容器
docker-compose down

# 查看日志
docker-compose logs vue
docker-compose logs worker

# 重启服务
docker-compose restart

# 进入容器
docker exec -it vue zsh  # 前端容器
docker exec -it worker zsh    # 后端容器
```

### 构建和部署
```bash
# 构建前端
npm run build:vue

# 构建后端
npm run build:worker

# 完整部署到 Cloudflare
npm run deploy
```

### 数据库操作
```bash
# 通过 npm 脚本（在宿主机运行）
npm run db:init
npm run db:init:remote
npm run db:migrate
npm run db:import

# 直接在 Docker 容器内运行
docker exec -it worker zsh -c "node scripts/db.js init"
docker exec -it worker zsh -c "node scripts/db.js init --remote"
docker exec -it worker zsh -c "node scripts/db.js migrate"
docker exec -it worker zsh -c "node scripts/db.js import"

# 执行 SQL 命令
docker exec -it worker zsh -c "node scripts/db.js 'SELECT * FROM users'"
docker exec -it worker zsh -c "node scripts/db.js 'SELECT * FROM users' --remote"

# 执行 base64 编码的 SQL
docker exec -it worker zsh -c "node scripts/db.js U0VMRUNUICogMSBhcyB0ZXN0"
```

## 📁 目录结构

### 前端 (vue/)
- `src/` - Vue 3 源码
  - `components/` - 可复用组件
  - `views/` - 页面组件
  - `stores/` - Pinia 状态管理
  - `api/` - API 服务层
  - `router/` - 路由配置
- `dist/` - 构建产物（自动生成）

### 后端 (worker/)
- `src/` - Worker 源码
  - `routes/` - API 路由
  - `services/` - 业务逻辑
  - `handlers/` - 事件处理器
  - `middleware/` - 中间件
  - `utils/` - 工具函数
  - `types/` - 类型定义

### 根目录
- `package.json` - 统一依赖管理（前端 + 后端）
- `wrangler.toml` - Cloudflare Worker 配置
- `scripts/` - JavaScript 脚本
  - `deploy.js` - 部署脚本
  - `db.js` - 数据库操作脚本
  - `env-detector.js` - 环境检测模块

## 🔧 配置说明

### wrangler.toml
```toml
name = "cem"
main = "worker/src/main.ts"

# 静态资源绑定
[assets]
directory = "vue/dist/"
binding = "ASSETS"
run_worker_first = true

# 环境变量
[vars]
DOMAIN = "your-domain.com"
JWT_SECRET = "your-jwt-secret"

# D1 数据库
[[d1_databases]]
binding = "DB"
database_name = "cem-db"

# R2 存储桶
[[r2_buckets]]
binding = "R2"
bucket_name = "cem-r2"
```

### 环境变量
- `DOMAIN` - 邮箱域名
- `JWT_SECRET` - JWT 密钥
- `cem_debug` - 调试模式开关

## 📚 API 文档

详细的 API 文档请参考 [API/api-doc.yml](API/api-doc.yml)

### 主要接口
- `POST /api/auth/login` - 用户登录
- `POST /api/auth/register` - 用户注册
- `GET /api/emails` - 获取邮件列表
- `POST /api/emails/send` - 发送邮件
- `GET /api/mailboxes` - 获取邮箱列表
- `POST /api/mailboxes` - 创建邮箱

## 🛠️ 开发指南

### 添加新功能
1. 在 `worker/src/routes/` 中添加 API 路由
2. 在 `vue/src/views/` 中添加页面组件
3. 在 `vue/src/api/` 中添加 API 调用
4. 更新类型定义

### 数据库操作
```bash
# 初始化数据库
npm run db:init

# 导入测试数据
npm run import:emails
```

### 调试模式
设置环境变量 `cem_debug = "true"` 启用调试模式，可以访问：
- `/api/debug` - 调试信息
- `/api/debug/simulate-email` - 模拟邮件发送

## 📝 更新日志

详细的更新日志请参考 [UPDATE_LOG.md](UPDATE_LOG.md)

## 🤝 贡献指南

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

- [Cloudflare Workers](https://workers.cloudflare.com/)
- [Vue.js](https://vuejs.org/)
- [Naive UI](https://www.naiveui.com/)
- [Hono](https://hono.dev/)
