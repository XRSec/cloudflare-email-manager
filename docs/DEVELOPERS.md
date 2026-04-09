# Cloudflare Email Manager 开发者文档

本文档面向需要开发、调试、维护或二次开发项目的人。快速部署和普通使用请看 [README.md](./README.md)。

## 技术栈

- Cloudflare Workers
- Cloudflare Email Routing
- D1
- R2
- KV
- Vue 3
- TypeScript
- Vite
- Element Plus
- Pinia
- Hono
- Wrangler

## 项目结构

```text
.
├── db/                 # D1 schema
├── scripts/            # 初始化和资源创建脚本
├── vue/                # Vue 3 前端
├── worker/             # Cloudflare Worker 后端
├── wrangler.example.toml
├── wrangler.toml       # 本地实际配置，通常不提交
└── package.json
```

## 环境要求

- Node.js `^20.19.0 || >=22.12.0`
- npm
- Cloudflare 账号
- Wrangler 登录状态正常

```bash
npx wrangler login
```

## 安装依赖

```bash
npm install
```

## 首次初始化

```bash
npm run init
```

该命令会执行 `scripts/deploy.js`，主要流程：

- 检查 Wrangler 登录状态
- 创建或复用 D1、KV、R2
- 根据 `wrangler.example.toml` 生成或更新 `wrangler.toml`
- 写入 D1/KV 资源 ID
- 初始化 `db/schema.sql`
- 构建前端和后端
- 部署 Worker

初始化完成后，需要到 Cloudflare 控制台配置 Email Routing，把目标地址路由到该 Worker。

默认管理员账号：

```text
admin / 123456
```

首次登录后请立即修改密码。

## 本地开发

```bash
npm run dev
```

当前开发命令会同时启动：

- `wrangler dev --remote`
- `vite vue`

前端开发服务默认端口为 `5173`，Worker 本地端口由 `wrangler.toml` 的 `[dev]` 配置控制，默认 `8787`。

## 构建

```bash
npm run build
```

该命令只构建前端：

```bash
cd vue && vue-tsc --noEmit && vite build
```

前端产物输出到：

```text
vue/dist/
```

Worker 代码由 Wrangler 部署时按 `worker/src/main.ts` 入口处理。

## 部署

普通部署使用：

```bash
npm run deploy
```

当前 deploy 脚本等价于：

```bash
npm run build && npx wrangler deploy
```

`npm run deploy` 不会创建 D1/KV/R2，也不会初始化数据库。首次部署或资源变更请使用 `npm run init`。

## Wrangler 配置

生产配置来自根目录：

```text
wrangler.toml
```

模板文件：

```text
wrangler.example.toml
```

关键配置：

```toml
[assets]
directory = "vue/dist/"
binding = "ASSETS"
run_worker_first = true

[[d1_databases]]
binding = "DB"
database_name = "cem-db"

[[r2_buckets]]
binding = "R2"
bucket_name = "cem-r2"

[[kv_namespaces]]
binding = "KV"
```

`[assets]` 放在顶层，确保部署到 `cem` Worker 时同一个 Worker 同时拥有前端静态资源和后端绑定。

## 数据库

Schema 文件：

```text
db/schema.sql
```

重新执行远端 schema：

```bash
npx wrangler d1 execute cem-db --file=./db/schema.sql --remote
```

导出远端 D1 到本地：

```bash
npm run db:export
```

## 消息路由

消息路由页面支持统一保存：新增、编辑、启停、删除都会先保留在页面状态里，点击“保存全部配置”后一次性提交。

通知通道支持：

- 钉钉
- 飞书
- Bark

通道的“密钥”字段规则：

- 为空：不签名
- 钉钉通道有值：用于钉钉加签
- 飞书通道有值：用于飞书 `timestamp` / `sign` 签名

飞书通知使用结构化卡片，包含发件人、收件人、接收时间、附件数、主题和内容摘要。

## 转发日志和 Webhook 调试

转发日志支持：

- 查看详情
- 重发 Webhook
- 删除日志

Webhook 重发不会新写入转发日志。重发结果会直接显示本次请求的调试输出：

- request URL
- request method
- request headers
- request body
- response status
- response headers
- response body

对于飞书，HTTP `200` 不一定代表业务成功，应以响应 body 中的 `code` / `StatusCode` 为准。系统会将飞书 `code !== 0` 视为失败。

## 常用命令

```bash
npm install
npm run init
npm run dev
npm run build
npm run deploy
npm run db:export
npx tsc -p worker/tsconfig.json
```

## 维护注意事项

- `wrangler.toml` 中的资源 ID、域名和密钥类配置请按自己的 Cloudflare 环境维护。
- 如果飞书没有开启签名校验，请清空通知通道里的密钥字段。
- 如果飞书返回 HTTP 200 但没有收到消息，请查看转发日志详情里的响应 body。
- 修改消息路由后，需要点击“保存全部配置”才会生效。
