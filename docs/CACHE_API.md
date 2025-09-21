# 缓存接口规范文档

> **📝 文档说明**：本文档仅提供函数名和规范，不包含具体代码实现。具体实现请参考源代码。

## 📋 概述

本文档定义了邮箱管理系统的统一缓存接口规范，包括前端缓存策略、后端缓存实现和Workers KV集成方案。

> **🔄 重要更新**：系统已统一使用 localStorage 进行缓存，不再使用 sessionStorage。所有缓存数据将持久化存储，确保系统配置和用户数据的持久性。

## 🏗️ 架构设计

### 缓存层级

```
┌─────────────────────────────────────────┐
│           用户请求                        │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│         前端缓存层 (LocalStorage)         │
│  • 用户会话数据                          │
│  • 系统配置信息                          │
│  • 持久化存储，TTL: 5-30分钟             │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│         Workers KV 缓存层                │
│  • 系统配置                            │
│  • 用户信息                            │
│  • 全局缓存数据                          │
│  • TTL: 1-24小时                       │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│         数据库层 (D1)                    │
│  • 持久化数据                            │
│  • 配置变更记录                          │
│  • 最终数据源                            │
└─────────────────────────────────────────┘
```

## 🏥 系统健康检查

### 接口方法

- `GET /api/system/health` - 获取系统健康状态

### 响应格式

- **成功**：返回系统状态、服务检查结果、配置信息
- **失败**：返回错误状态和服务异常信息
- **数据格式**：使用数字格式（1=正常/是，0=异常/否）

### 检查项目

- 数据库连接状态和延迟
- R2存储服务状态
- KV存储服务状态
- 系统配置信息（仅数据库正常时）

## 🔧 前端缓存接口

### 缓存管理器函数

- `set()` - 设置缓存
- `get()` - 获取缓存
- `delete()` - 删除缓存
- `clear()` - 清空所有缓存
- `isValid()` - 检查缓存是否有效
- `getCacheInfo()` - 获取缓存信息
- `cleanExpired()` - 清理过期缓存

### 业务缓存函数

- `getSystemConfig()` - 获取系统配置
- `getRegistrationStatus()` - 获取注册状态
- `getUserInfo()` - 获取用户信息
- `updateUserInfo()` - 更新用户信息
- `getPublicInfo()` - 获取公开系统信息
- `getSystemHealth()` - 获取系统健康状态
- `isSystemHealthy()` - 检查系统是否健康

### 缓存键命名规范

- `system:config` - 系统配置
- `system:registration` - 注册状态
- `system:debug` - 调试模式
- `user:info` - 用户信息
- `user:settings` - 用户设置
- `emails:list` - 邮件列表
- `mailboxes:list` - 邮箱列表
- `forward:rules` - 转发规则
- `webhook:config` - Webhook配置

### TTL配置

- `SHORT: 5分钟` - 短期缓存
- `MEDIUM: 30分钟` - 中期缓存
- `LONG: 2小时` - 长期缓存
- `VERY_LONG: 24小时` - 超长期缓存

## 🔧 后端缓存接口

### Workers KV 缓存服务函数

- `set()` - 设置缓存
- `get()` - 获取缓存
- `delete()` - 删除缓存
- `clear()` - 清空所有缓存

### 业务缓存函数

- `setSystemConfig()` - 设置系统配置
- `getSystemConfig()` - 获取系统配置
- `setRegistrationStatus()` - 设置注册状态
- `getRegistrationStatus()` - 获取注册状态
- `setUserInfo()` - 设置用户信息
- `getUserInfo()` - 获取用户信息

### 缓存策略服务函数

- `getSystemConfigWithCache()` - 获取系统配置（带缓存）
- `getUserInfoWithCache()` - 获取用户信息（带缓存）
- `updateUserInfoWithCache()` - 更新用户信息（带缓存）

### 缓存管理函数

- `refreshConfig()` - 刷新配置缓存
- `clearSystemCache()` - 清理系统缓存
- `warmupCache()` - 预热缓存
- `getCacheStatus()` - 获取缓存状态
- `getCacheStats()` - 获取缓存统计

## 🚀 部署配置

### wrangler.toml 配置

```toml
# Workers KV 配置
[[kv_namespaces]]
binding = "KV"
id = "your-kv-namespace-id"
preview_id = "your-preview-kv-namespace-id"

# 环境变量接口
interface Env {
  DB: D1Database
  R2: R2Bucket
  KV: KVNamespace        # Workers KV 存储
  ASSETS: Fetcher        # 静态资源绑定
}
```

### 环境变量

- `CACHE_TTL_SHORT = "300"` - 5分钟
- `CACHE_TTL_MEDIUM = "1800"` - 30分钟
- `CACHE_TTL_LONG = "7200"` - 2小时
- `CACHE_TTL_VERY_LONG = "86400"` - 24小时

## 📊 监控和调试

### 缓存状态查询

- `GET /api/cache/status` - 获取缓存状态
- `GET /api/cache/stats` - 获取缓存统计

### 缓存管理

- `POST /api/cache/clear` - 清理缓存
- `POST /api/cache/warmup` - 预热缓存

### 调试信息

- 缓存命中率
- 内存使用情况
- 过期清理统计
- 错误日志记录