# 前后端分离配置说明

## 概述

本项目已成功实现前后端分离，后端专注于API服务，前端作为静态资源独立部署。

## 项目结构

```
/workspace/
├── src/                    # 后端源码
│   ├── main.ts            # 主入口文件（已移除HTML内嵌）
│   ├── services/
│   │   └── static.ts      # 静态资源服务模块
│   ├── routes/            # API路由
│   └── ...
├── frontend/              # 前端源码目录
│   └── dist/              # 前端构建产物
│       ├── index.html     # 主页面
│       ├── app.js         # 前端应用逻辑
│       └── style.css      # 样式文件
├── api/
│   └── api-doc.yml        # API文档
└── wrangler.example.toml  # Cloudflare Workers配置
```

## 配置变更

### 1. wrangler.toml 配置

添加了静态资源绑定配置：

```toml
# 静态资源绑定 - 前端构建产物
[assets]
directory = "frontend/dist/"
binding = "ASSETS"
run_worker_first = true
```

### 2. 后端代码变更

- **main.ts**: 移除了HTML模板内嵌，添加了静态资源路由处理
- **services/static.ts**: 新增静态资源服务模块，支持SPA路由
- **types/index.ts**: 添加了ASSETS绑定类型定义

### 3. API路由结构

所有API路径都以 `/api/` 开头：

- `/api/auth/*` - 认证相关
- `/api/protected/*` - 用户功能
- `/api/admin/*` - 管理员功能
- `/api/mailbox/*` - 邮箱管理
- `/api/system/*` - 系统配置
- `/api/debug/*` - 调试功能

## 部署说明

### 开发环境

1. **启动后端服务**：
   ```bash
   wrangler dev
   ```

2. **构建前端**：
   ```bash
   # 将前端构建产物放到 frontend/dist/ 目录
   # 或者使用你喜欢的构建工具
   ```

3. **访问应用**：
   - 前端：http://localhost:8787
   - API：http://localhost:8787/api/*

### 生产环境

1. **构建前端**：
   ```bash
   # 使用你的前端构建工具
   npm run build  # 或其他构建命令
   # 确保构建产物在 frontend/dist/ 目录
   ```

2. **部署到Cloudflare**：
   ```bash
   wrangler deploy
   ```

## 静态资源服务特性

### 1. SPA路由支持

- 所有非API路径都会返回 `index.html`
- 支持前端路由（React Router、Vue Router等）

### 2. 缓存策略

- 静态资源：1小时缓存
- HTML文件：无缓存
- 自动ETag支持

### 3. 安全特性

- 路径遍历攻击防护
- 内容类型自动检测
- 错误处理机制

## API文档

完整的API文档位于 `api/api-doc.yml`，包含：

- 所有API端点定义
- 请求/响应格式
- 认证方式
- 错误码说明

## 测试

运行测试脚本验证前后端分离：

```bash
node test-separation.js
```

测试内容包括：
- API服务可用性
- 静态资源服务
- SPA路由支持
- 路径隔离

## 注意事项

1. **前端构建**：确保前端构建产物在 `frontend/dist/` 目录
2. **API路径**：所有API调用必须以 `/api/` 开头
3. **静态资源**：CSS、JS等静态资源直接放在 `frontend/dist/` 根目录
4. **环境变量**：确保 `wrangler.toml` 中的ASSETS绑定配置正确

## 故障排除

### 1. 静态资源404

- 检查 `frontend/dist/` 目录是否存在
- 确认文件路径正确
- 检查 `wrangler.toml` 配置

### 2. API调用失败

- 确认API路径以 `/api/` 开头
- 检查后端服务是否正常运行
- 查看浏览器控制台错误信息

### 3. SPA路由不工作

- 确认 `index.html` 在 `frontend/dist/` 目录
- 检查静态资源服务配置
- 验证路径处理逻辑

## 开发建议

1. **前端开发**：使用现代前端框架（React、Vue、Angular等）
2. **API调用**：使用统一的API客户端
3. **错误处理**：实现全局错误处理机制
4. **类型安全**：使用TypeScript定义API接口类型
5. **测试**：编写单元测试和集成测试

## 更新日志

- **v1.0.0**: 实现前后端分离
  - 移除HTML内嵌
  - 添加静态资源服务
  - 更新API路由结构
  - 支持SPA路由