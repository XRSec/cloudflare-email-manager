# 项目结构迁移说明

## 🎯 迁移目标

将项目从多 package.json 结构迁移到单 package.json 结构，简化依赖管理和开发流程。

## ✅ 已完成的迁移

### 1. 依赖合并
- ✅ 合并 `frontend/package.json` 到根目录
- ✅ 合并 `worker/package.json` 到根目录
- ✅ 删除子目录的 package.json 文件
- ✅ 统一所有依赖到根目录管理

### 2. 脚本优化
- ✅ 更新所有 npm 脚本使用根目录依赖
- ✅ 智能环境检测脚本支持本地依赖
- ✅ 使用 `npx` 运行本地安装的工具

### 3. 文档更新
- ✅ 更新 README.md 说明新的项目结构
- ✅ 更新安装和开发流程说明
- ✅ 更新目录结构说明

## 📁 新的项目结构

```
cloudflare-email-manager/
├── frontend/              # Vue 3 前端项目
│   ├── src/              # 前端源码
│   └── dist/             # 构建产物（自动生成）
├── worker/               # Cloudflare Worker 后端
│   └── src/              # Worker 源码
├── db/                   # 数据库相关
├── scripts/              # 智能环境检测和构建脚本
├── package.json          # 统一依赖管理（前端 + 后端）
├── wrangler.toml         # Cloudflare Worker 配置
└── README.md             # 项目说明
```

## 🚀 新的开发流程

### 安装依赖
```bash
# 一次性安装所有依赖
npm install
```

### 开发模式
```bash
# 智能检测环境并启动
npm run dev

# 手动指定环境
npm run dev:worker:local   # 本地运行
npm run dev:worker:docker  # Docker 运行
```

### 构建部署
```bash
# 构建项目
npm run build

# 智能检测环境并部署
npm run deploy

# 手动指定环境部署
npm run deploy:local   # 本地部署
npm run deploy:docker  # Docker 部署
```

## 🔧 技术细节

### 依赖管理
- 所有依赖统一在根目录的 `package.json` 中管理
- 使用 `npx` 运行本地安装的工具（如 wrangler）
- 智能环境检测支持本地和全局安装的工具

### 脚本优化
- 所有脚本直接使用根目录的依赖
- 智能环境检测自动选择最佳运行方式
- 支持强制指定运行环境

### 构建流程
- 前端构建：`cd frontend && vite build`
- 后端构建：`cd worker && tsc`
- 统一构建：`npm run build`

## 📋 迁移检查清单

- [x] 合并前端依赖到根目录
- [x] 合并后端依赖到根目录
- [x] 删除子目录 package.json 文件
- [x] 更新所有 npm 脚本
- [x] 更新智能环境检测脚本
- [x] 更新文档说明
- [x] 测试环境检测功能
- [x] 测试构建和部署流程

## 🎉 迁移完成

项目已成功迁移到单 package.json 结构，现在可以：

1. **简化依赖管理**：只需在一个地方管理所有依赖
2. **统一开发流程**：所有命令都在根目录执行
3. **智能环境检测**：自动选择最佳运行方式
4. **更好的维护性**：清晰的项目结构和脚本组织

## 🔄 回滚方案

如果需要回滚到多 package.json 结构：

1. 恢复子目录的 package.json 文件
2. 更新 npm 脚本使用子目录依赖
3. 更新环境检测脚本
4. 更新文档说明

但建议保持当前的单 package.json 结构，因为它更简洁和易于维护。

## 5. 数据库脚本合并

### 合并 db_init.js 功能
- 将 `db/db_init.js` 的数据库清理和初始化功能合并到 `scripts/db.js` 中
- 删除了 `db/db_init.js` 文件
- 统一了数据库操作接口

### 新的数据库操作流程
1. **清理**：自动删除所有用户表
2. **初始化**：执行 schema.sql 重建表结构
3. **迁移**：执行数据库迁移
4. **导入**：导入邮件数据

### 优势
- 减少了文件数量
- 统一了数据库操作逻辑
- 简化了维护工作
- 提供了更清晰的错误处理

## 6. 环境检测模块优化

### 提取环境检测功能
- 创建了 `scripts/env-detector.js` 模块
- 提供统一的环境检测功能
- 所有脚本共享环境检测逻辑

### 环境检测功能
- `detectEnvironment()` - 检测当前环境类型
- `getEnvironmentInfo()` - 获取详细环境信息
- `isEnvironmentAvailable()` - 检查环境是否可用

### 优化后的脚本
- `dev.js` - 使用环境检测模块
- `deploy.js` - 使用环境检测模块
- `db.js` - 使用环境检测模块

### 优势
- 代码复用：避免重复的环境检测逻辑
- 统一管理：所有环境检测逻辑集中管理
- 易于维护：修改环境检测逻辑只需修改一个文件
- 更好的错误处理：统一的环境可用性检查

## 7. Docker 配置优化

### 新的 Docker 运行方式
- 使用 `--net=host` 网络模式，无需端口映射
- 使用 `-v "${PWD}/:${PWD}" -w ${PWD}` 路径映射
- 容器内路径与宿主机完全一致

### 路径优化
- 移除了所有 `/app` 路径引用
- 直接使用相对路径（如 `cd worker`、`cd db`）
- 简化了 Docker 命令的复杂度

### 优势
- 路径映射：容器内外路径完全一致
- 网络简化：使用 host 网络，无需端口映射
- 命令简化：直接使用相对路径，更直观
- 开发体验：容器内外操作完全一致
