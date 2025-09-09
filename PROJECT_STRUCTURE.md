# 项目结构

## 📁 完整的模块化结构

```
src/
├── main.ts                     # 主入口文件
├── types/
│   └── index.ts               # ✅ 类型定义文件（完整的TypeScript接口）
├── utils/
│   ├── crypto.ts              # 加密工具（JWT、密码哈希等）
│   ├── debug.ts               # 调试工具
│   └── template.ts            # HTML模板生成
├── services/
│   ├── user.ts                # 用户服务（CRUD操作）
│   ├── email.ts               # 邮件服务（邮件处理、附件管理）
│   ├── webhook.ts             # Webhook服务（转发规则、发送）
│   └── settings.ts            # 系统设置服务（配置管理）
├── middleware/
│   └── auth.ts                # 认证中间件（JWT验证、权限控制）
├── routes/
│   ├── auth.ts                # 认证路由（登录、注册、登出）
│   ├── user.ts                # 用户路由（邮件查看、设置修改）
│   ├── admin.ts               # 管理员路由（用户管理、规则配置）
│   └── system.ts              # 系统路由（公开配置、健康检查）
├── handlers/
│   ├── email.ts               # 邮件处理器（接收邮件、MIME解析）
│   └── scheduled.ts           # 定时任务处理器（清理任务）
└── static/
    ├── styles.ts              # 模块化CSS样式
    └── app.ts                 # 模块化JavaScript应用
```

## 📋 文件验证

所有文件都已创建并验证：

- ✅ `src/types/index.ts` - 3497字节，包含完整的TypeScript类型定义
- ✅ `src/main.ts` - 主入口文件，已配置所有路由
- ✅ 所有服务模块都已创建并导入类型
- ✅ 所有路由模块都已创建并导入类型
- ✅ TypeScript编译通过，无错误

## 🔍 如何查看types文件

如果您在IDE中看不到types文件夹，请尝试：

1. **刷新文件浏览器** - 在IDE中刷新项目目录
2. **重新打开项目** - 关闭并重新打开项目
3. **命令行验证**：
   ```bash
   ls -la src/types/
   cat src/types/index.ts
   ```

## 📄 types/index.ts 内容概览

该文件包含以下主要类型定义：

- `Env` - Cloudflare Workers环境变量
- `User` - 用户数据模型
- `Email` - 邮件数据模型
- `Attachment` - 附件数据模型
- `ForwardRule` - 转发规则模型
- `SystemSetting` - 系统设置模型
- `JWTPayload` - JWT载荷类型
- `ApiResponse<T>` - API响应类型
- `EmailQueryParams` - 邮件查询参数
- `UserSettingsUpdate` - 用户设置更新类型
- `SystemConfig` - 系统配置类型

所有类型都已正确导出并在各个模块中使用。
