# 简化脚本说明

## 🎯 设计理念

用 JavaScript 脚本替代复杂的 shell 脚本，提供更简洁、易维护的开发体验。

## 📁 脚本结构

```
scripts/
├── env-detector.js  # 环境检测模块（可复用）
├── docker.js       # Docker 容器管理脚本
├── dev.js          # 开发环境启动脚本
├── deploy.js       # 部署脚本
└── db.js           # 数据库操作脚本（包含初始化、清理、迁移、导入功能）
```

## 🚀 使用方法

### 开发
```bash
# 启动开发环境（前端 + 后端）
npm run dev
```

### 部署
```bash
# 构建并部署
npm run deploy
```

### 数据库操作
```bash
# 初始化数据库
npm run db:init

# 初始化远程数据库
npm run db:init:remote

# 执行数据库迁移
npm run db:migrate

# 导入邮件数据
npm run db:import

# 查看帮助
npm run db
```

### Docker 管理
```bash
# 启动容器（如果不存在则创建）
npm run docker:start

# 停止容器
npm run docker:stop

# 重启容器
npm run docker:restart

# 查看容器状态
npm run docker:status

# 构建镜像
npm run docker:build

# 删除容器
npm run docker:remove
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
| 部署 | `npm run deploy` | 构建并部署到 Cloudflare |
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
