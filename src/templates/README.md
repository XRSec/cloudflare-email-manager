# Templates 模块

## 📋 概述

Templates 模块负责生成完整的 HTML 页面模板，将 CSS、JavaScript 和 HTML 内容组合成可直接在浏览器中运行的完整页面。这是一个服务端渲染(SSR)的解决方案，特别适合 Cloudflare Workers 环境。

## 🏗️ 架构设计

### 设计理念

1. **单页面应用(SPA)模式**：所有内容都打包在一个 HTML 文件中
2. **内联资源**：CSS 和 JavaScript 都内联在 HTML 中，减少网络请求
3. **模块化组装**：通过 TypeScript 模块动态生成内容
4. **版本控制**：自动添加时间戳进行缓存控制

### 为什么使用这种架构？

**Cloudflare Workers 的限制**：
- 不支持传统的静态文件服务
- 每个请求都需要通过 JavaScript 处理
- 需要将所有资源打包到 Worker 代码中

**优势**：
- ✅ 零网络请求（除了初始 HTML）
- ✅ 快速加载（所有资源已内联）
- ✅ 简化部署（单个 Worker 文件）
- ✅ 版本控制（自动缓存失效）

## 📁 文件结构

```
src/templates/
├── README.md              # 本文档
├── html-template.ts       # 主 HTML 模板生成器
└── [其他模板文件...]       # 未来可扩展的模板
```

## 🔧 核心文件详解

### `html-template.ts`

这是核心的 HTML 模板生成器，负责：

#### 1. **HTML 结构生成**
```typescript
function getHTMLHead(): string {
    return `
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="临时邮箱管理系统">
    <title>临时邮箱管理系统</title>
    ${getStyleTag()}  // 内联 CSS
    `;
}
```

#### 2. **页面主体生成**
```typescript
function getHTMLBody(): string {
    // 生成完整的页面结构
    // 包括登录界面、主界面、侧边栏等
}
```

#### 3. **脚本集成**
```typescript
function getHTMLScript(version: number): string {
    return `
    <script data-version="${version}">
        // 配置管理器
        ${AppConfig}
        
        // 主应用逻辑  
        ${await getJavaScript()}
        
        // 初始化代码
        document.addEventListener('DOMContentLoaded', async function() {
            // 应用初始化逻辑
        });
    </script>
    `;
}
```

#### 4. **完整模板导出**
```typescript
export async function getHTMLTemplate(): Promise<string> {
    const version = new Date().getTime(); // 缓存控制
    
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    ${getHTMLHead()}
</head>
<body>
    ${getHTMLBody()}
    ${getHTMLScript(version)}
</body>
</html>`;
}
```

## 🔄 数据流

```mermaid
graph TD
    A[用户请求] --> B[main.ts]
    B --> C[getTemplate()]
    C --> D[getHTMLTemplate()]
    D --> E[getStyleTag()]
    D --> F[AppConfig]
    D --> G[getJavaScript()]
    E --> H[内联 CSS]
    F --> I[配置管理代码]
    G --> J[主应用逻辑]
    H --> K[完整 HTML]
    I --> K
    J --> K
    K --> L[返回给用户]
```

## 🎯 模块依赖

### 导入的模块

```typescript
import { getStyleTag } from '../static/styles';     // CSS 样式
import { AppConfig } from '../static/app-config';   // 配置管理
import { getJavaScript } from '../static/app';      // 主应用逻辑
```

### 输出接口

```typescript
export async function getHTMLTemplate(): Promise<string>
```

## 🚀 使用方式

### 在 main.ts 中使用

```typescript
import { getTemplate } from './utils/template';

// 处理根路径请求
app.get('/', async (c) => {
    const html = await getTemplate();
    return c.html(html);
});
```

### 在其他路由中使用

```typescript
// 可以直接使用模板
import { getHTMLTemplate } from './templates/html-template';

const html = await getHTMLTemplate();
return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
});
```

## 🔧 配置和自定义

### 版本控制

模板自动生成版本号用于缓存控制：

```typescript
const version = new Date().getTime();
// 添加到 script 标签: data-version="${version}"
```

### 元数据配置

可以通过修改 `getHTMLHead()` 函数来自定义：

- 页面标题
- Meta 描述
- Favicon
- 其他 head 标签内容

### 主题和样式

通过 `../static/styles` 模块控制：

- CSS 变量
- 响应式设计
- 主题色彩
- 动画效果

## 🐛 常见问题和解决方案

### 1. JavaScript 函数未定义错误

**问题**：在模板中调用了未定义的函数（如 `checkAuth()`）

**原因**：
- 函数在 `getJavaScript()` 中定义，但在初始化代码中被调用
- 执行顺序问题

**解决方案**：
```typescript
// 错误的做法
if (token) {
    checkAuth(); // 函数可能还未定义
}

// 正确的做法
if (token) {
    // 等待应用初始化完成
    window.addEventListener('appReady', () => {
        checkAuth();
    });
}
```

### 2. 样式不生效

**问题**：CSS 样式没有正确应用

**检查项**：
- `getStyleTag()` 是否正确导入
- CSS 内容是否正确生成
- 是否有 CSP 限制内联样式

### 3. 脚本执行错误

**问题**：JavaScript 代码执行失败

**调试步骤**：
1. 检查浏览器控制台错误
2. 确认所有模块正确导入
3. 验证异步函数的执行顺序

## 📈 性能优化

### 1. 缓存策略

```typescript
// 在 HTTP 响应中添加缓存头
return c.html(html, {
    headers: {
        'Cache-Control': 'public, max-age=3600',
        'ETag': `"${version}"`
    }
});
```

### 2. 代码压缩

生产环境中可以考虑：
- 压缩 HTML
- 压缩内联的 CSS 和 JavaScript
- 移除注释和空白字符

### 3. 资源优化

- 优化 CSS 选择器
- 减少 JavaScript 包大小
- 使用 Tree Shaking 移除未使用代码

## 🔮 未来扩展

### 1. 多模板支持

```typescript
// 可以扩展支持不同的页面模板
export async function getLoginTemplate(): Promise<string>
export async function getAdminTemplate(): Promise<string>
export async function getErrorTemplate(): Promise<string>
```

### 2. 模板继承

```typescript
// 基础模板
class BaseTemplate {
    protected getHead(): string { /* ... */ }
    protected getFooter(): string { /* ... */ }
}

// 具体模板
class MainTemplate extends BaseTemplate {
    public async render(): Promise<string> { /* ... */ }
}
```

### 3. 组件化

```typescript
// 组件化的模板结构
interface TemplateComponent {
    render(props?: any): string;
}

class HeaderComponent implements TemplateComponent {
    render(props: { title: string }): string { /* ... */ }
}
```

## 📚 相关文档

- [Static 模块文档](../static/README.md) - 了解 CSS 和 JavaScript 生成
- [Utils 模块文档](../utils/README.md) - 了解模板工具函数
- [主应用架构](../../README.md) - 了解整体架构设计

---

**注意**：Templates 模块是整个应用的渲染核心，修改时请谨慎，确保在不同浏览器中进行充分测试。