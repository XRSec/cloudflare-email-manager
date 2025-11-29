# R2 文件缓存测试指南

## 测试目的

验证后端 R2 文件缓存机制是否正常工作，包括：
- ETag 生成
- 304 Not Modified 响应
- Cache-Control 头设置
- Last-Modified 头设置

## 测试环境

1. 启动后端服务：
```bash
cd worker && npx wrangler dev
```

2. 准备测试数据：
   - 确保数据库中有邮件数据
   - 确保邮件有附件

## 测试步骤

### 1. 测试附件下载缓存

#### 首次请求（应返回 200 + 完整文件）

```bash
curl -i -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8787/api/emails/{EMAIL_ID}/attachments/{ATTACHMENT_ID}
```

**预期响应头：**
```
HTTP/1.1 200 OK
Content-Type: image/png
Content-Disposition: inline; filename="example.png"
Content-Length: 12345
ETag: "abc123"
Last-Modified: Sun, 30 Nov 2025 12:00:00 GMT
Cache-Control: public, max-age=31536000, immutable
Vary: Authorization
```

**说明：**
- 返回完整的文件内容
- 包含 ETag 和 Last-Modified 头
- Cache-Control 设置为 1 年

#### 第二次请求（使用 ETag，应返回 304）

```bash
curl -i -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "If-None-Match: \"abc123\"" \
  http://localhost:8787/api/emails/{EMAIL_ID}/attachments/{ATTACHMENT_ID}
```

**预期响应：**
```
HTTP/1.1 304 Not Modified
ETag: "abc123"
Last-Modified: Sun, 30 Nov 2025 12:00:00 GMT
Cache-Control: public, max-age=31536000
```

**说明：**
- 返回 304 状态码
- 无响应体（节省带宽）
- 保留必要的缓存头

#### 第三次请求（使用 If-Modified-Since）

```bash
curl -i -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "If-Modified-Since: Sun, 30 Nov 2025 12:00:00 GMT" \
  http://localhost:8787/api/emails/{EMAIL_ID}/attachments/{ATTACHMENT_ID}
```

**预期响应：**
```
HTTP/1.1 304 Not Modified
```

**说明：**
- 如果文件未修改，返回 304
- 浏览器使用本地缓存

### 2. 测试原始邮件下载缓存

#### 首次请求

```bash
curl -i -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8787/api/emails/{EMAIL_ID}/raw
```

**预期响应头：**
```
HTTP/1.1 200 OK
Content-Type: message/rfc822
Content-Disposition: attachment; filename="email_{EMAIL_ID}.eml"
ETag: "xyz789"
Last-Modified: Sun, 30 Nov 2025 12:00:00 GMT
Cache-Control: public, max-age=31536000, immutable
Vary: Authorization
```

#### 第二次请求（使用 ETag）

```bash
curl -i -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "If-None-Match: \"xyz789\"" \
  http://localhost:8787/api/emails/{EMAIL_ID}/raw
```

**预期响应：**
```
HTTP/1.1 304 Not Modified
```

## 浏览器测试

### 使用开发者工具

1. 打开浏览器开发者工具（F12）
2. 切换到 Network 标签
3. 访问邮件详情页面（包含附件）
4. 查看附件请求：

**首次加载：**
- Status: 200
- Size: 实际文件大小（如：123 KB）
- Time: 实际下载时间（如：150 ms）

**再次加载（刷新页面）：**
- Status: 304 Not Modified
- Size: (from disk cache) 或 (from memory cache)
- Time: < 10 ms

### 测试 immutable 缓存

1. 访问邮件详情页面
2. 等待附件加载完成
3. 使用 Ctrl+Shift+R（或 Cmd+Shift+R）强制刷新
4. 观察 Network 标签：
   - 普通刷新：应该看到 304 响应
   - 强制刷新：应该看到 200 响应（忽略缓存）

## 性能测试

### 测试场景 1：查看包含多个图片的邮件

1. 首次加载：
   - 10 张图片，每张 100 KB
   - 总下载量：1000 KB
   - 总时间：~1 秒

2. 再次查看（关闭后重新打开）：
   - 10 张图片
   - 总下载量：0 KB（全部使用缓存）
   - 总时间：< 100 ms

3. 性能提升：
   - 带宽节省：100%
   - 加载速度提升：10 倍

### 测试场景 2：重复下载附件

1. 下载附件（test.pdf，5 MB）
2. 再次下载同一附件
3. 观察：
   - 首次：从服务器下载，5 MB
   - 再次：304 响应，浏览器使用缓存

## 调试技巧

### 查看请求头

```bash
curl -v -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8787/api/emails/{EMAIL_ID}/attachments/{ATTACHMENT_ID}
```

`-v` 参数会显示详细的请求和响应头

### 清除浏览器缓存

- Chrome: Ctrl+Shift+Delete（或 Cmd+Shift+Delete）
- 选择"缓存的图片和文件"
- 点击"清除数据"

### 禁用缓存

在浏览器开发者工具中：
- Network 标签
- 勾选"Disable cache"
- 所有请求都会绕过缓存

## 常见问题

### Q: 为什么我看到的是 200 而不是 304？

A: 可能的原因：
1. 浏览器缓存已清除
2. 首次访问
3. ETag 或 Last-Modified 不匹配
4. 使用了强制刷新（Ctrl+Shift+R）

### Q: ETag 的格式是什么？

A: 
- 使用 R2 对象的 etag：`"r2-etag-value"`
- 或自定义哈希：`"generated-hash"`

### Q: Cache-Control 为什么设置为 1 年？

A: 
- 附件内容是不可变的（immutable）
- 即使邮件被删除，附件 ID 也不会复用
- 可以安全地长期缓存

### Q: 如何强制刷新缓存？

A: 
1. 浏览器：Ctrl+Shift+R（强制刷新）
2. API：不发送 If-None-Match 头
3. 管理：修改附件会生成新的 ID

## 验证清单

- [ ] 附件下载返回正确的缓存头
- [ ] 第二次请求返回 304 响应
- [ ] 原始邮件下载支持缓存
- [ ] If-None-Match 头正确处理
- [ ] If-Modified-Since 头正确处理
- [ ] 浏览器正确使用缓存
- [ ] 强制刷新可以绕过缓存
- [ ] Vary: Authorization 头正确设置

## 性能指标

预期性能提升：
- **首次加载**：正常速度（基准）
- **再次加载**：速度提升 10-100 倍
- **带宽节省**：90-100%
- **服务器负载**：减少 90-100%

## 注意事项

1. **认证要求**：所有请求都需要有效的 JWT token
2. **权限检查**：用户只能访问自己的附件
3. **缓存隔离**：不同用户的缓存完全隔离（Vary: Authorization）
4. **CDN 友好**：可以被 Cloudflare CDN 缓存

