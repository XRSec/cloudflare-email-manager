# 模块化架构

## 🏗️ 架构设计

### 文件结构
```
src/
├── templates/
│   └── html-template.ts    # HTML 结构模块
├── static/
│   ├── styles.ts           # CSS 样式模块
│   ├── app.ts              # JavaScript 主逻辑
│   └── app-config.ts       # 配置管理模块
├── utils/
│   ├── template.ts         # 模板加载器
│   └── cache.ts            # 全局缓存系统
└── main.ts                 # 主入口
```

## ✨ 核心特性

### 1. 模块化设计
- **HTML**: `html-template.ts` - 页面结构
- **CSS**: `styles.ts` - 所有样式定义
- **JS**: `app.ts` + `app-config.ts` - 应用逻辑和配置管理
- **缓存**: `cache.ts` - 全局缓存系统

### 2. 配置管理
```javascript
// 从 API 获取配置（带缓存）
const config = await ConfigManager.getSystemConfig();

// 强制刷新配置
const config = await ConfigManager.getSystemConfig(true);

// 全局刷新
window.refreshConfig();
```

### 3. 缓存策略
- **系统配置**: 5分钟缓存
- **用户信息**: 5分钟缓存
- **邮件列表**: 1分钟缓存
- **管理员数据**: 30分钟缓存

### 4. 动态配置
- `allow_registration`: 从 API 获取，控制注册按钮显示
- `debug_mode`: 从 API 获取，控制调试菜单显示
- `domains`: 从 API 获取，动态显示域名

## 🔄 数据流

```
用户操作
    ↓
ConfigManager.getSystemConfig()
    ↓
检查缓存 → 有效？→ 返回缓存数据
    ↓ 无效
API 请求 (/api/system/config)
    ↓
更新缓存
    ↓
更新 UI
```

## 📝 API 端点

### 公开配置
```
GET /api/system/config
{
    "allow_registration": boolean,
    "debug_mode": boolean,
    "domains": string[],
    "max_attachment_size": number
}
```

### 用户信息
```
GET /api/protected/me
Authorization: Bearer <token>
```

## 🎯 使用示例

### 初始化应用
```javascript
// 自动执行
document.addEventListener('DOMContentLoaded', async () => {
    await ConfigManager.init();
});
```

### 刷新配置
```javascript
// 用户点击刷新按钮
<button onclick="refreshConfig()">刷新配置</button>

// 程序中刷新
ConfigManager.clearCache();
await ConfigManager.init();
```

### 检查调试模式
```javascript
const config = await ConfigManager.getSystemConfig();
if (config.debug_mode) {
    // 显示调试功能
}
```

## 🚀 优势

1. **模块化**: 代码组织清晰，易于维护
2. **缓存优化**: 减少 API 请求，提升性能
3. **动态配置**: 无需重新部署即可更改配置
4. **类型安全**: TypeScript 提供类型检查
5. **版本控制**: 自动添加版本号用于缓存控制

## 📊 性能指标

| 模块 | 大小 | 说明 |
|------|------|------|
| HTML | ~5KB | 结构模块 |
| CSS | ~15KB | 样式模块 |
| JS | ~20KB | 逻辑模块 |
| 总计 | ~40KB | 压缩前 |

## 🔧 配置说明

### 环境变量
- `cem_debug`: 强制开启调试模式

### 系统设置（数据库）
- `allow_registration`: 是否允许注册
- `debug_mode`: 是否开启调试
- `domains`: 支持的域名列表
- `jwt_secret`: JWT 密钥
- `cleanup_days`: 邮件清理天数

## 📝 开发指南

### 添加新样式
编辑 `src/static/styles.ts`:
```typescript
const newStyles = \`
    .new-class {
        /* 样式定义 */
    }
\`;
```

### 添加新页面
编辑 `src/templates/html-template.ts`:
```typescript
function getNewSection(): string {
    return \`
        <div id="newSection" class="card hidden">
            <!-- 内容 -->
        </div>
    \`;
}
```

### 添加新配置
1. 在数据库添加配置项
2. 更新 API 返回
3. 在 `ConfigManager` 中使用

## 🎉 总结

通过模块化重构：
- ✅ HTML/CSS/JS 完全分离
- ✅ 全局缓存系统
- ✅ 动态配置管理
- ✅ API 驱动的配置
- ✅ 类型安全的 TypeScript

---

**状态**: 生产就绪
**更新**: 2025年1月