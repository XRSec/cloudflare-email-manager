# 环境变量配置说明

## 概述

为了解决 Docker 容器和本地环境的 `node_modules` 冲突问题，我们支持通过环境变量来动态配置路径。

## 环境变量

### NODE_MODULES_PATH
指定 `node_modules` 的路径。

**默认值：**
- 本地环境：`./node_modules`
- Docker 环境：`/app/node_modules`

**示例：**
```bash
# 本地环境
export NODE_MODULES_PATH=./node_modules

# Docker 环境（使用独立的 node_modules 路径）
export NODE_MODULES_PATH=/app/node_modules
```

### NPX_PATH
指定 `npx` 命令的路径。

**默认值：**
- 本地环境：`npx`
- Docker 环境：`/app/node_modules/.bin/npx`

**示例：**
```bash
# 本地环境
export NPX_PATH=npx

# Docker 环境（使用容器内的 npx）
export NPX_PATH=/app/node_modules/.bin/npx
```

### DOCKER_CONTAINER
标识是否在 Docker 容器内运行。

**默认值：** `false`

**示例：**
```bash
# 在 Docker 容器内
export DOCKER_CONTAINER=true

# 在本地环境
export DOCKER_CONTAINER=false
```

## 使用方式

### 1. 环境变量方式
```bash
# 设置环境变量
export NODE_MODULES_PATH=./node_modules
export NPX_PATH=npx

# 运行脚本
npm run dev
npm run deploy
npm run db:init
```

### 2. .env 文件方式
创建 `.env` 文件：
```bash
NODE_MODULES_PATH=./node_modules
NPX_PATH=npx
DOCKER_CONTAINER=false
```

### 3. 脚本内设置
在脚本中直接设置：
```bash
NODE_MODULES_PATH=./node_modules NPX_PATH=npx npm run dev
```

## 自动检测

脚本会自动检测环境并选择合适的路径：

- **本地环境**：使用本地 `node_modules` 和 `npx`
- **Docker 环境**：使用容器内的 `node_modules` 和 `npx`

## 故障排除

### 路径冲突
如果遇到路径冲突，可以手动指定：
```bash
export NODE_MODULES_PATH=/path/to/correct/node_modules
export NPX_PATH=/path/to/correct/npx
```

### 权限问题
确保指定的路径有正确的权限：
```bash
chmod +x /path/to/npx
```

### 路径不存在
确保指定的路径存在：
```bash
ls -la /path/to/node_modules
ls -la /path/to/npx
```

## 包管理器配置

### 自动检测包管理器
脚本会自动检测并选择合适的包管理器：

- **本地环境**：根据项目根目录的锁文件检测（yarn.lock、pnpm-lock.yaml、package-lock.json）
- **Docker 环境**：优先使用 yarn，然后 npm

### 包管理器优先级
1. **yarn** - 如果检测到 yarn.lock 或容器内有 yarn
2. **pnpm** - 如果检测到 pnpm-lock.yaml
3. **npm** - 默认选择

### Docker 容器依赖安装
Docker 容器创建时会自动安装依赖：
1. 优先使用 `yarn install`
2. 如果 yarn 失败，使用 `npm install`
3. 依赖安装在 `/app/node_modules` 路径下
