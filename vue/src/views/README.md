# 视图结构说明

## 目录结构

```
views/
├── auth/                    # 认证相关视图
│   ├── LoginView.vue       # 登录视图
│   └── index.ts            # 认证视图导出
├── admin/                  # 管理员视图
│   ├── emails/             # 邮件管理
│   │   └── AllEmailsView.vue
│   ├── mailboxes/          # 邮箱管理
│   │   ├── MailboxManagementView.vue
│   │   └── ForwardRulesView.vue
│   ├── users/              # 用户管理
│   │   └── UsersView.vue
│   ├── settings/           # 系统设置
│   │   ├── SystemSettingsView.vue
│   │   └── DebugView.vue
│   ├── security/           # 安全管理
│   │   └── SecurityOverviewView.vue
│   └── index.ts            # 管理员视图导出
├── user/                   # 用户视图
│   ├── emails/             # 我的邮件
│   │   └── MyEmailsView.vue
│   ├── mailboxes/          # 我的邮箱
│   │   └── MyMailboxesView.vue
│   ├── settings/           # 个人设置
│   │   └── PersonalSettingsView.vue
│   └── index.ts            # 用户视图导出
├── shared/                 # 共享视图和组件
│   ├── dashboard/          # 仪表板（登录后共享）
│   │   └── DashboardView.vue
│   ├── error/              # 错误页面
│   │   └── NotFoundView.vue
│   ├── layouts/            # 布局组件
│   │   └── MainLayout.vue
│   ├── components/         # 共享组件
│   │   ├── AppLoadingSpinner.vue
│   │   ├── DataTable.vue
│   │   └── SearchBox.vue
│   └── index.ts            # 共享视图和组件导出
└── index.ts                # 所有视图导出
```

## 命名规范

### 文件命名
- 视图文件：`[功能]View.vue`（如：`LoginView.vue`、`DashboardView.vue`）
- 组件文件：`[功能]Component.vue`（如：`DataTable.vue`、`SearchBox.vue`）
- 布局文件：`[功能]Layout.vue`（如：`MainLayout.vue`）

### 目录命名
- 按功能模块组织：`auth`、`admin`、`user`、`shared`
- 子目录按具体功能：`emails`、`mailboxes`、`settings`、`dashboard`等

### 组件命名
- 视图组件：`[角色][功能]View`（如：`AdminAllEmailsView`、`UserMyEmailsView`）
- 共享视图：`[功能]View`（如：`DashboardView`）
- 共享组件：`[功能]Component`（如：`DataTable`、`SearchBox`）

## 导入方式

### 路由中的动态导入
```typescript
const LoginView = () => import('@/views/auth/LoginView.vue')
const DashboardView = () => import('@/views/shared/dashboard/DashboardView.vue')
const NotFoundView = () => import('@/views/shared/error/NotFoundView.vue')
const AdminAllEmailsView = () => import('@/views/admin/emails/AllEmailsView.vue')
```

### 组件中的导入
```typescript
import { LoginView, DashboardView, NotFoundView, AdminAllEmailsView } from '@/views'
// 或者
import { LoginView } from '@/views/auth'
import { DashboardView, NotFoundView } from '@/views/shared'
import { AdminAllEmailsView } from '@/views/admin'
```

## 优势

1. **清晰的层次结构**：按角色和功能模块组织，便于维护
2. **统一的命名规范**：所有视图都使用`View`后缀，组件使用`Component`后缀
3. **模块化设计**：每个功能模块独立，便于团队协作
4. **易于扩展**：新增功能时只需在对应目录下添加文件
5. **类型安全**：通过TypeScript提供完整的类型支持
6. **合理的共享设计**：Dashboard作为登录后的共享视图，符合业务逻辑
