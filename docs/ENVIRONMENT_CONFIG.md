# 环境配置说明

## Cloudflare Workers 环境配置

### 命令对比

| 命令 | 用途 | 使用的配置段 | 连接的环境 |
|------|------|-------------|-----------|
| `wrangler dev` | 本地开发服务器 | `[dev]` + 主配置 | 生产环境资源 |
| `wrangler dev --env dev` | 本地开发服务器 | `[dev]` + `[env.dev]` | 开发环境资源 |
| `wrangler deploy` | 部署到云端 | 主配置 | 生产环境 |
| `wrangler deploy --env dev` | 部署到云端 | `[env.dev]` | 开发环境 |

### 推荐使用方式

#### 开发阶段
```bash
# 使用开发环境资源进行本地开发
wrangler dev --env dev
```

#### 生产部署
```bash
# 部署到生产环境
wrangler deploy
```

#### 开发环境部署
```bash
# 部署到开发环境（用于测试）
wrangler deploy --env dev
```

### 环境隔离

- **生产环境**：使用 `cem-db`、`cem-r2`、`cem-kv` 等资源
- **开发环境**：使用 `cem-db-dev`、`cem-r2-dev`、`cem-kv-dev` 等资源

### 配置结构说明

#### 全局配置段
- **`[dev]`**：本地开发服务器配置 (IP 和端口)
- **`[triggers]`**：定时任务配置
- **`[observability]`**：可观测性配置
- **`[assets]`**：静态资源绑定配置

#### 环境特定配置段
- **`[env.dev]`**：开发环境的资源绑定配置
  - 用于 `wrangler dev --env dev` 和 `wrangler deploy --env dev` 命令
  - 包含独立的 D1、R2、KV 资源绑定

#### 配置优先级
1. 全局配置段适用于所有环境
2. `[env.dev]` 段会覆盖对应的全局配置
3. 本地开发服务器配置 (`[dev]`) 始终使用，不受环境影响

### 注意事项

1. 开发环境资源需要单独创建
2. 使用 `npm run deploy` 脚本可以自动创建和管理环境资源
3. 开发环境资源与生产环境完全隔离，避免数据污染
