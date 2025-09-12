# 智能环境检测脚本

## 概述

这套脚本可以自动检测运行环境，并选择合适的执行方式（本地或 Docker 容器）。

## 脚本说明

### 1. `detect-env.sh` - 环境检测
自动检测当前环境类型：
- **local**: 本地环境，已安装 wrangler
- **docker**: Docker 环境，需要在容器中运行

检测逻辑：
1. 检查是否在 Docker 容器内（`/.dockerenv` 文件）
2. 检查本地是否安装了 wrangler
3. 检查是否有 node 容器运行
4. 默认选择 docker（保守策略）

### 2. `run-worker.sh` - 智能 Worker 运行
根据环境检测结果运行 Worker：
```bash
# 自动检测环境并运行
./scripts/run-worker.sh

# 或者通过 npm
npm run dev:worker
```

### 3. `run-deploy.sh` - 智能部署
根据环境检测结果部署 Worker：
```bash
# 自动检测环境并部署
./scripts/run-deploy.sh

# 或者通过 npm
npm run deploy
```

### 4. `run-db.sh` - 智能数据库操作
根据环境检测结果执行数据库操作：
```bash
# 初始化数据库
./scripts/run-db.sh init

# 初始化远程数据库
./scripts/run-db.sh init:remote

# 或者通过 npm
npm run db:init
npm run db:init:remote
```

## 使用方式

### 自动模式（推荐）
```bash
# 开发
npm run dev

# 部署
npm run deploy

# 数据库操作
npm run db:init
```

### 手动模式
```bash
# 强制本地运行
npm run dev:worker:local
npm run deploy:local
npm run db:init:local

# 强制 Docker 运行
npm run dev:worker:docker
npm run deploy:docker
npm run db:init:docker
```

## 环境要求

### 本地环境
- Node.js >= 18
- 已安装 wrangler: `npm install -g wrangler`

### Docker 环境
- Docker 已安装
- 构建镜像: `docker build -t node:cem --progress=plain .`
- 运行 node 容器: `docker run -itd --name node -v "${PWD}/:${PWD}" -w "${PWD}" --net=host node:cem`

## 故障排除

### 检测失败
如果环境检测失败，可以手动指定：
```bash
# 查看检测结果
./scripts/detect-env.sh

# 手动运行
npm run dev:worker:local  # 或 :docker
```

### 容器问题
```bash
# 检查容器状态
docker ps | grep node

# 如果容器不存在，先构建镜像再启动
docker build -t node:cem --progress=plain .
docker run -itd --name node -v "${PWD}/:${PWD}" -w "${PWD}" --net=host node:cem

# 如果容器已存在但未运行，启动它
docker start node

# 进入容器
docker exec -it node bash
```

### wrangler 问题
```bash
# 安装 wrangler
npm install -g wrangler

# 检查版本
wrangler --version

# 登录 Cloudflare
wrangler login
```

## 环境变量配置

### 解决路径冲突
为了避免 Docker 容器和本地环境的 `node_modules` 冲突，支持通过环境变量配置：

```bash
# 设置环境变量
export NODE_MODULES_PATH=./node_modules
export NPX_PATH=npx

# 运行脚本
npm run dev
npm run deploy
npm run db:init
```

### 环境变量说明
- `NODE_MODULES_PATH`: 指定 node_modules 路径（默认: ./node_modules）
- `NODE_PATH`: Docker 容器内的 node_modules 路径（默认: /app/node_modules）
- `NPX_PATH`: 指定 npx 命令路径（默认: npx）
- `DOCKER_CONTAINER`: 标识是否在 Docker 容器内（默认: false）

### npx 包管理器方案
- **全局使用 npx**: 不需要本地 node_modules，使用全局缓存
- **避免路径冲突**: 不需要复杂的 prefix 和 NODE_PATH 配置
- **更简洁**: 直接运行，无需安装到本地
- **Docker 环境**: 使用容器内的 npx 运行所有工具

### 包管理器
- 统一使用 npm 作为包管理器
- 本地环境：使用本地 npm
- Docker 环境：使用容器内的 npm

### 自动检测
脚本会自动检测环境并选择合适的路径，无需手动配置。
