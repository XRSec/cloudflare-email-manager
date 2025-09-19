### 🔄 最近更新

#### 开发环境优化 (2024-01-XX)
- **Docker 配置完善**：完善 `docker-compose.yml` 配置，前端和后端独立容器
  - 前端容器：`vue` 服务，运行 Vite 开发服务器
  - 后端容器：`worker` 服务，运行 wrangler dev
  - 共享 node_modules 卷，避免依赖冲突
- **文档清理**：删除过时的文档文件
  - 删除 `docs/FRONTEND_SEPARATION.md`
  - 删除 `docs/MIGRATION.md`
  - 删除 `docs/ENV_CONFIG.md`
- **数据库操作优化**：直接使用 wrangler d1 execute 命令
  - 通过 `docker exec -it worker zsh -c "node scripts/db.js 'SQL'"` 执行 SQL 命令
  - 支持 base64 编码的 SQL 命令
  - 简化了数据库操作流程，无需复杂的参数传递
- **文档更新**：更新所有文档反映新的容器化开发环境
- **脚本整合**：将根目录 `deploy.js` 的功能整合到 `scripts/deploy.js` 中
- **功能完善**：新的部署脚本包含完整的部署流程
  - 资源创建（D1、KV、R2）
  - 用户交互（域名输入、管理员密码等）
  - 数据库初始化和管理员账户创建
  - 配置文件更新（wrangler.toml）
  - 前后端构建和部署
- **命令统一**：更新 `package.json` 中的脚本引用
  - `npm run deploy` - 完整部署
  - `npm run init` - 同 deploy 命令
  - `npm run clean` - 清理所有 Cloudflare 资源
- **文档更新**：更新 `docs/SCRIPTS.md` 反映新的脚本功能

#### 后端架构重构 - 前后端分离 (2024-01-XX)
- **静态资源服务**：移除内嵌HTML模板，改为通过 ASSETS 绑定服务前端
- **API路由重构**：统一API路径设计，符合 OpenAPI 3.0 规范
  - 认证：`/api/auth/*` (login, logout, register)
  - 用户：`/api/users/*` (me, 用户管理)
  - 邮件：`/api/emails/*` (列表、详情、删除、发送、附件)
  - 邮箱：`/api/mailboxes/*` (申请、管理)
  - 转发规则：`/api/forward-rules/*` (CRUD操作)
  - 系统：`/api/system/*` (配置、健康检查)
  - 管理员：`/api/admin/*` (管理功能)
- **类型定义更新**：完善 TypeScript 类型定义，支持新的API结构
- **服务函数优化**：重构服务层函数，支持分页和权限控制
- **配置更新**：更新 wrangler.toml 配置，添加 ASSETS 绑定

#### API 接口优化 (2024-01-XX)
- **用户搜索功能**：`/api/users` 接口新增 `query` 参数，支持按用户名、邮箱搜索
- **邮件查询优化**：`/api/emails` 接口调整 `scope` 参数逻辑
  - 默认行为：普通用户获取自己的邮件，管理员获取自己的邮件
  - 全部邮件：仅当 `scope=all` 时管理员可获取全部邮件
  - 移除了 `scope=mine` 的默认值，简化了查询逻辑
- **登录接口简化**：`/api/auth/login` 只返回 JWT token，不返回用户信息
  - 前端登录后需要调用 `/api/users/me` 获取用户详细信息
  - 避免了接口间的数据重复，职责更加清晰
