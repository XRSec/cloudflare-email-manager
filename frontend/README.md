# 临时邮箱管理系统 - 前端

基于 Vue 3 + TypeScript + Pinia 的现代化前端应用，提供完整的邮件管理功能。

## 技术栈

- **Vue 3** - 渐进式 JavaScript 框架
- **TypeScript** - 类型安全的 JavaScript
- **Pinia** - Vue 状态管理库
- **Vue Router** - 官方路由管理器
- **Vite** - 快速构建工具

## 项目结构

```
src/
├── api/                    # API 服务层
│   └── index.ts           # 统一的 API 接口
├── assets/                # 静态资源
│   ├── styles.css         # 全局样式
│   └── main.css          # 主样式文件
├── components/            # 可复用组件
│   ├── Auth/             # 认证相关组件
│   │   └── LoginForm.vue # 登录表单
│   ├── Email/            # 邮件相关组件
│   │   ├── EmailList.vue # 邮件列表
│   │   └── EmailDetail.vue # 邮件详情
│   ├── Layout/           # 布局组件
│   │   ├── MainLayout.vue # 主布局
│   │   ├── Sidebar.vue   # 侧边栏
│   │   └── TopBar.vue    # 顶部栏
│   └── Mailbox/          # 邮箱相关组件
│       └── MailboxList.vue # 邮箱列表
├── router/               # 路由配置
│   └── index.ts         # 路由定义
├── stores/              # 状态管理
│   ├── auth.ts         # 认证状态
│   ├── counter.ts      # 计数器状态
│   ├── mailbox.ts      # 邮箱状态
│   └── system.ts       # 系统状态
├── views/              # 页面组件
│   ├── admin/          # 管理员页面
│   │   ├── UsersView.vue      # 用户管理
│   │   ├── ApplicationsView.vue # 申请审核
│   │   └── ...
│   ├── DashboardView.vue      # 仪表板
│   ├── EmailsView.vue         # 邮件页面
│   ├── LoginView.vue          # 登录页面
│   ├── MailboxView.vue        # 邮箱管理
│   ├── SettingsView.vue       # 设置页面
│   └── ...
├── App.vue             # 根组件
└── main.ts            # 应用入口
```

## 功能特性

### 用户功能
- ✅ 用户登录/注册
- ✅ 邮件查看和管理
- ✅ 邮箱申请和管理
- ✅ 个人设置和 Webhook 配置
- ✅ 申请记录查看

### 管理员功能
- ✅ 用户管理
- ✅ 邮箱管理
- ✅ 申请审核
- ✅ 系统设置
- ✅ 全部邮件查看

### 技术特性
- ✅ 响应式设计，支持移动端
- ✅ 类型安全的 TypeScript
- ✅ 模块化的组件架构
- ✅ 统一的状态管理
- ✅ 完整的 API 集成
- ✅ 现代化的 UI 设计

## 开发指南

### 环境要求
- Node.js 16+
- npm 或 yarn

### 安装依赖
```bash
npm install
```

### 开发模式
```bash
npm run dev
```

### 构建生产版本
```bash
npm run build
```

### 类型检查
```bash
npm run type-check
```

## API 集成

前端通过 `src/api/index.ts` 与后端 API 进行交互，支持：

- 认证管理（登录、注册、登出）
- 邮件管理（查看、删除、下载附件）
- 邮箱管理（申请、查看、删除）
- 用户管理（管理员功能）
- 系统配置（管理员功能）

## 组件说明

### 布局组件
- `MainLayout.vue` - 主应用布局，包含侧边栏和内容区域
- `Sidebar.vue` - 侧边栏导航，支持用户和管理员菜单
- `TopBar.vue` - 顶部栏，显示用户信息和操作按钮

### 功能组件
- `LoginForm.vue` - 登录表单，支持登录和注册
- `EmailList.vue` - 邮件列表，支持搜索、筛选和分页
- `EmailDetail.vue` - 邮件详情，支持查看内容和下载附件
- `MailboxList.vue` - 邮箱列表，支持申请和管理

### 页面组件
- `DashboardView.vue` - 仪表板，显示统计信息和快速操作
- `EmailsView.vue` - 邮件页面，包含列表和详情视图
- `MailboxView.vue` - 邮箱管理页面
- `SettingsView.vue` - 用户设置页面
- `DebugView.vue` - 调试页面（仅调试模式）

## 样式系统

使用统一的 CSS 变量和工具类：

- 全局样式定义在 `src/assets/styles.css`
- 组件样式使用 scoped CSS
- 支持响应式设计
- 统一的颜色和间距规范

## 状态管理

使用 Pinia 进行状态管理：

- `auth` - 用户认证状态
- `mailbox` - 邮箱相关状态
- `system` - 系统配置状态

## 路由配置

- 支持嵌套路由
- 路由守卫保护需要认证的页面
- 管理员页面需要管理员权限
- 调试页面需要调试模式

## 开发注意事项

1. **类型安全** - 所有 API 调用都有完整的 TypeScript 类型定义
2. **错误处理** - 统一的错误处理和用户提示
3. **加载状态** - 所有异步操作都有加载状态指示
4. **响应式** - 支持桌面和移动设备
5. **可访问性** - 遵循 Web 可访问性标准

## 部署

前端构建后可以部署到任何静态文件服务器，或与后端一起部署到 Cloudflare Workers。

构建产物在 `dist/` 目录中，包含所有静态资源。