# 简化脚本说明

## 🎯 设计理念

用 JavaScript 脚本替代复杂的 shell 脚本，提供更简洁、易维护的开发体验。

## 📁 脚本结构

```
scripts/
├── env-detector.js  # 环境检测模块（可复用）
├── deploy.js       # 部署脚本
└── db.js           # 数据库操作脚本（包含初始化、清理、迁移、导入功能）
```

## 🚀 使用方法

### 开发环境
```bash
# 启动 Docker 容器（前端 + 后端）
docker-compose up -d

# 查看容器状态
docker-compose ps

# 停止容器
docker-compose down
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
docker exec -it worker zsh -c "node scripts/db.js U0VMRUNUICogRlJPTSB1c2Vycwo="
```

### Docker 管理
```bash
# 启动所有服务
docker-compose up -d

# 查看服务状态
docker-compose ps

# 查看日志
docker-compose logs vue
docker-compose logs worker

# 停止所有服务
docker-compose down

# 重启服务
docker-compose restart

# 进入容器
docker exec -it vue zsh  # 前端容器
docker exec -it worker zsh    # 后端容器
```

## 🔧 脚本特性

### 1. 自动环境检测
- 自动检测本地或 Docker 环境
- 智能选择最佳运行方式
- 无需手动配置

### 2. 统一接口
- 所有操作通过 npm 脚本调用
- 支持参数传递（如 `--remote`）
- 清晰的错误处理和日志输出

### 3. 易于维护
- 纯 JavaScript 实现
- 模块化设计
- 易于扩展和修改

### 4. 环境检测模块
- `env-detector.js` 提供统一的环境检测功能
- 可复用的模块，所有脚本共享
- 提供环境信息、可用性检查等功能

### 5. Docker 配置优化
- 使用 `--net=host` 网络模式，无需端口映射
- 使用 `-v "${PWD}/:${PWD}" -w ${PWD}` 路径映射
- 容器内路径与宿主机完全一致，直接使用相对路径

## 📋 命令对照表

| 功能 | 命令 | 说明 |
|------|------|------|
| 开发 | `npm run dev` | 启动前端和后端 |
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
