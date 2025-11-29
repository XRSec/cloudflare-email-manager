# CEM 邮箱管理系统 - 前端

基于 Vue 3 + TypeScript + Element Plus + Pinia + VueUse 的现代化邮箱管理系统前端。

## 技术栈

- **Vue 3** - 渐进式 JavaScript 框架
- **TypeScript** - 类型安全的 JavaScript
- **Element Plus** - Vue 3 组件库
- **Pinia** - Vue 状态管理
- **VueUse** - Vue 组合式 API 工具集
- **Axios** - HTTP 客户端
- **Day.js** - 轻量级日期处理库
- **Vite** - 快速构建工具

## 功能特性

- ✅ 用户登录/注册
- ✅ 流式页面加载
- ✅ 响应式设计
- ✅ 类型安全
- ✅ 现代化 UI 设计
- ✅ 状态持久化

## 开发环境

### 安装依赖

```bash
npm install
```

### 启动开发服务器

```bash
npm run dev
```

访问 http://localhost:3000

### 构建生产版本

```bash
npm run build
```

### 类型检查

```bash
npm run type-check
```

## 项目结构

```
vue/
├── src/
│   ├── api/           # API 服务
│   ├── components/    # 组件
│   │   └── UI/       # UI 组件
│   ├── router/        # 路由配置
│   ├── stores/        # Pinia 状态管理
│   ├── types/         # TypeScript 类型定义
│   ├── views/         # 页面组件
│   ├── App.vue        # 根组件
│   └── main.js        # 入口文件
├── index.html         # HTML 模板
├── package.json       # 项目配置
├── tsconfig.json      # TypeScript 配置
├── tsconfig.node.json # Node.js TypeScript 配置
└── vite.config.ts     # Vite 配置
```

## 主要组件

### 登录页面 (LoginView.vue)
- 支持用户名/密码登录
- 支持用户注册（可配置）
- 响应式设计
- 错误处理
- 加载状态

### 主界面 (MainLayoutView.vue)
- 用户信息显示
- 退出登录功能
- 现代化布局

### 认证状态管理 (auth.ts)
- 基于 Pinia 的状态管理
- 使用 VueUse 进行持久化存储
- 完整的登录/注册/登出流程

## API 配置

API 服务配置在 `src/api/index.ts` 中，支持：
- Cookie 认证
- 请求/响应拦截
- 错误处理
- 自动重定向

## 开发说明

1. 所有组件都使用 TypeScript 编写
2. 使用 Element Plus 组件库
3. 状态管理使用 Pinia
4. 路由使用 Vue Router
5. 样式使用 scoped CSS

## 浏览器支持

- Chrome >= 87
- Firefox >= 78
- Safari >= 14
- Edge >= 88
