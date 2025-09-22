### 🔄 最近更新

#### 修复我的邮箱页面没有内容问题 - 数据库状态字段类型错误 (2025-01-21)

**问题分析：**
- "我的邮箱"页面显示空白，没有任何邮箱数据
- 后端API查询使用了错误的status字段值（字符串'active'而不是数字1）
- 数据库schema中status字段为INTEGER类型：1=激活, 2=停用, 3=删除
- 前端缺少debug模式下的原始JSON数据显示

**修复方案：**
- 修复后端所有status字段查询，使用正确的数字值
- 在前端添加debug模式显示原始API响应数据
- 统一数据库状态字段的使用规范

**技术实现：**
- 修复 `worker/src/services/mailbox.ts`：
  - `getAllMailboxes`函数：`WHERE m.status = 'active'` → `WHERE m.status = 1`
  - `deleteMailbox`函数：`SET status = 'deleted'` → `SET status = 3`
- 修复 `worker/src/services/permission.ts`：
  - 管理员权限验证：`WHERE status = 'active'` → `WHERE status = 1`
- 修复 `worker/src/routes/user-info.ts`：
  - 用户信息查询：`WHERE status = 'active'` → `WHERE status = 1`
  - 修复TypeScript类型错误：`userMap: Record<number, any>`
- 修复 `worker/src/services/user.ts`：
  - 创建用户函数：`VALUES (?, ?, ?, 'active', ...)` → `VALUES (?, ?, ?, 1, ...)`
- 前端 `vue/src/layouts/Admin/MailboxesView.vue`：
  - 添加debug模式显示原始JSON响应
  - 显示请求参数和处理后的数据
  - 导入并使用systemStore进行debug模式判断

**修复效果：**
- "我的邮箱"页面正常显示用户的邮箱列表
- 管理员可以正常查看所有邮箱
- Debug模式下可以查看完整的API响应数据
- 数据库查询性能提升（使用数字索引而非字符串比较）
- 所有状态字段查询统一使用数字值
- 全局刷新功能修复：强制刷新时跳过缓存，确保获取最新数据
- 前端状态渲染修复：支持数字状态值（1=正常, 2=已停用, 3=已删除），兼容字符串状态值
- 用户信息显示修复：修复前端字段名不匹配问题（row.username → row.owner_username），后端添加owner_usertype字段
- 前后端字段同步：统一使用owner_usertype字段名，更新API文档schema定义
- 用户类型字段类型修正：owner_usertype改为数字类型（0=普通用户, 1=管理员），后端使用CASE语句转换

#### 修复页面布局滚动条问题 - 确保内容超出时才显示滚动条 (2025-01-21)

**问题分析：**
- 页面默认状态下出现滚动条，即使内容不多
- 页面高度设置不合理，使用了 `min-height` 而不是固定 `height`
- 主内容区域没有正确控制溢出行为

**修复方案：**
- 修改 `vue/src/layouts/MainLayoutView.vue` 中的页面布局样式
- 使用固定高度替代最小高度，确保页面占满整个屏幕
- 正确设置溢出控制，只在内容超出时显示滚动条

**技术实现：**
- 修改 `.main-content` 样式：
  - 将 `min-height: 100vh` 改为 `height: 100vh`
  - 添加 `overflow: hidden` 防止主内容区域出现滚动条
- 修改 `.page-content` 样式：
  - 将 `min-height: calc(100vh - 60px)` 改为 `height: calc(100vh - 60px)`
  - 保持 `overflow-y: auto` 确保内容超出时显示滚动条

**修复效果：**
- 页面默认状态下占满整个屏幕，无滚动条
- 只有当内容超出视口高度时才显示滚动条
- 所有页面（仪表板、邮箱、邮件等）都应用此修复
- 移动端响应式布局正常工作

#### 清理仪表板页面统计信息显示 (2025-01-21)

**清理内容：**
- 删除仪表板统计卡片中的"总邮件数"、"我的邮箱数"、"待审核申请"显示
- 删除安全概览部分的统计信息显示
- 保留管理员快捷操作卡片（用户管理、系统设置）
- 保留最近邮件显示功能

**技术实现：**
- 修改 `vue/src/layouts/Admin/DashboardView.vue`：
  - 删除统计卡片中的邮件、邮箱、申请统计显示
  - 删除安全概览中的统计信息内容
  - 移除相关的响应式数据：`emailStats`、`mailboxStats`、`applicationStats`
  - 删除不再需要的数据加载函数：`loadMailboxesData`、`loadApplicationsData`
  - 简化预加载逻辑，只保留邮件数据预加载
  - 删除不再使用的 `goToMailboxes` 方法

**优化效果：**
- 简化仪表板界面，减少冗余信息显示
- 减少不必要的数据加载和API请求
- 为后续安全概览功能调整预留空间
- 保持核心功能（最近邮件、快捷操作）完整

#### 移除仪表板页面单独刷新按钮，集成全局刷新机制 (2025-01-21)

**问题分析：**
- 仪表板页面有单独的刷新按钮，与全局刷新功能重复
- 用户需要记住不同页面的刷新按钮位置
- 全局刷新机制已经完善，应该统一使用

**优化方案：**
- 移除仪表板页面的单独刷新按钮
- 集成全局刷新机制，支持全局刷新事件监听
- 统一刷新体验，用户只需使用顶部栏的全局刷新按钮

**技术实现：**
- 修改 `vue/src/layouts/Admin/DashboardView.vue`：
  - 移除 `PageHeader` 的 `show-refresh` 属性
  - 移除 `refreshData` 方法
  - 添加 `handleGlobalRefresh` 全局刷新事件处理
  - 添加 `refreshDashboardPage` 页面级刷新函数
  - 在 `onMounted` 中注册全局刷新事件监听和页面刷新函数
  - 在 `onUnmounted` 中清理事件监听和全局函数

**全局刷新机制：**
```
MainLayoutView 全局刷新按钮：
1. 触发 'global:refresh' 自定义事件
2. 调用 window.refreshCurrentPage() 页面级刷新函数

仪表板页面响应：
1. 监听 'global:refresh' 事件
2. 注册 refreshDashboardPage 到 window.refreshCurrentPage
3. 收到刷新事件时调用 loadDashboardData(true) 强制刷新
```

**优势：**
- 统一刷新体验：所有页面使用相同的全局刷新按钮
- 减少UI冗余：移除重复的刷新按钮
- 保持功能完整：支持强制刷新和缓存失效
- 代码简洁：减少重复的刷新逻辑

#### 优化仪表板数据加载策略 - 移除冗余API，实现智能预加载 (2025-01-21)

**问题分析：**
- `dashboard-stats` API 造成数据重复，与现有页面数据重复
- 仪表板显示的数据实际上就是各个页面第一页的数据
- 可以预加载页面数据，既满足仪表板显示，又为后续页面访问提供缓存

**优化方案：**
- 移除 `dashboard-stats` API，避免数据重复
- 实现智能预加载系统，在仪表板加载时预加载各页面第一页数据
- 仪表板统计数据直接从预加载的数据中提取
- 用户点击进入页面时直接使用缓存数据，无需重新加载

**技术实现：**
- 移除 `worker/src/routes/system.ts` 中的 `dashboard-stats` API
- 移除 `vue/src/composables/api.ts` 中的 `getDashboardStats` 方法
- 重构 `vue/src/layouts/Admin/DashboardView.vue`：
  - 实现智能预加载管理器 `preloadPageData`
  - 分别实现 `loadEmailsData`、`loadMailboxesData`、`loadApplicationsData`
  - 每个数据加载函数都支持缓存机制
  - 仪表板统计数据从预加载数据中提取

**预加载策略：**
```
仪表板预加载：
- 邮件数据：page=1, limit=10（最近10封邮件）
- 邮箱数据：page=1, limit=1（获取总数统计）
- 申请数据：page=1, limit=1（获取待审核数量）

缓存复用：
- 用户点击"我的邮件"页面：直接使用缓存的 page=1, limit=10 数据
- 用户点击"我的邮箱"页面：直接使用缓存的 page=1, limit=1 数据
- 用户点击"申请审核"页面：直接使用缓存的 page=1, limit=1 数据
```

**性能优化：**
- 减少API数量：从4个API减少到3个现有API
- 数据复用：仪表板数据与页面数据完全复用
- 预加载缓存：用户进入页面时数据已准备就绪
- 智能缓存：支持依赖关系和自动失效

**测试验证：**
- 邮件API：返回正确数据 ✅
- 邮箱API：返回统计信息和可用域名 ✅
- 预加载系统：数据正确提取和缓存 ✅
- 缓存复用：页面访问时直接使用缓存 ✅

#### 智能缓存系统重构 - 解决数据重复请求和缓存失效问题 (2025-01-21)

**问题描述：**
- 仪表板数据重复请求，缓存策略不合理
- 分页数据无法复用，每次翻页都重新请求
- 缓存失效机制不完善，数据更新后缓存未及时清理
- 后端API数据结构不够灵活，缺少聚合统计信息

**解决方案：**
- 设计智能缓存管理系统，支持依赖关系和自动失效
- 创建专门的仪表板统计API，避免重复请求
- 实现分层缓存策略，统计数据与列表数据分离
- 优化后端API返回结构，包含统计信息和可用域名

**技术实现：**
- 新增 `vue/src/composables/smartCache.ts`：智能缓存管理器
  - 支持缓存依赖关系，自动失效相关缓存
  - 分层缓存策略，不同数据不同TTL
  - 缓存键生成器，统一管理缓存键
  - 缓存失效工具函数，事件驱动的缓存清理
- 新增 `worker/src/routes/system.ts`：仪表板统计API
  - `/api/system/dashboard-stats`：获取聚合统计数据
  - 支持管理员和普通用户不同权限
  - 并行查询，提升性能
- 优化 `worker/src/routes/mailbox.ts`：邮箱API增强
  - 返回统计信息：用户邮箱数、总邮箱数
  - 返回可用域名列表
  - 支持管理员和普通用户不同数据范围
- 重构前端缓存逻辑：
  - 仪表板使用智能缓存，统计数据5分钟，最近邮件2分钟
  - 邮箱列表支持分页缓存，10分钟TTL
  - 申请列表支持分页缓存，10分钟TTL
  - 自动缓存失效：新邮箱创建时失效相关缓存

**缓存策略设计：**
```
缓存键设计：
- user_stats_{userId}: 用户统计数据
- recent_emails_{userId}: 最近邮件
- mailboxes_{userId}_{page}_{limit}_{scope}: 邮箱列表
- applications_{userId}_{page}_{limit}_{scope}: 申请列表
- dashboard_stats_{userId}: 仪表板统计

依赖关系：
- new_email: 失效邮件相关缓存
- new_mailbox: 失效邮箱相关缓存
- application_change: 失效申请相关缓存
- user_change: 失效用户相关缓存
- system_config_change: 失效系统配置缓存
```

**性能优化：**
- 仪表板数据：从4个API请求减少到2个
- 分页数据：支持缓存复用，减少重复请求
- 统计数据：专门API，避免重复计算
- 缓存失效：事件驱动，及时清理过期数据

**测试验证：**
- 仪表板统计API：返回正确数据 ✅
- 邮箱API增强：包含统计和域名信息 ✅
- 智能缓存：依赖关系正确失效 ✅
- 分页缓存：支持缓存复用 ✅

#### 完善仪表板和邮箱申请功能 - 数据填充和用户体验优化 (2025-01-21)

**问题描述：**
- 仪表板数据填充不完整，最近邮件、安全概览、我的邮箱数量统计不准确
- 我的邮箱页面使用模拟数据，未连接真实API
- 申请邮箱页面缺少永久选项，申请理由字数限制不合理
- 邮箱地址下拉选项使用硬编码域名，未使用系统设置

**修复内容：**
- 完善仪表板数据填充：最近10封邮件、总邮件数量、我的邮箱数量、待审核申请数量
- 添加缓存支持：仪表板数据缓存2分钟，提升加载速度
- 清理我的邮箱页面：移除模拟数据，连接真实API
- 优化申请邮箱页面：添加永久选项、调整字数限制（4-200字）、移除补充说明字段
- 动态域名选项：从系统配置获取可用域名，在mailboxes API中返回

**技术实现：**
- 修复 `vue/src/layouts/Admin/DashboardView.vue`：并行加载数据、添加缓存、完善安全概览
- 修复 `vue/src/layouts/Admin/MailboxesView.vue`：连接真实API、优化表单验证、动态域名
- 修复 `worker/src/routes/mailbox.ts`：在API响应中添加可用域名信息
- 修复 `vue/src/composables/api.ts`：支持对象参数的getMailboxApplications方法

**测试验证：**
- 仪表板数据加载：总邮件数、我的邮箱数、待审核申请数 ✅
- 最近邮件显示：最近10封邮件，支持缓存 ✅
- 邮箱申请表单：永久选项、字数限制、动态域名 ✅
- API数据一致性：mailboxes接口返回可用域名 ✅

#### 统一前后端status字段类型 - 全面使用数字类型 (2025-01-21)

**问题描述：**
- 前后端status字段类型不一致，后端部分使用字符串('active'/'disabled')，部分使用数字(1/2/3)
- 数据库schema使用INTEGER类型，但代码中存在字符串比较和赋值
- 类型转换逻辑复杂，容易出错

**修复内容：**
- 统一所有status字段使用数字类型：1=激活, 2=停用, 3=删除
- 移除所有字符串status的使用和转换逻辑
- 修复数据库查询中的status条件
- 简化状态切换逻辑，直接使用数字值

**技术实现：**
- 修复 `worker/src/routes/user.ts`：用户状态切换使用数字类型
- 修复 `worker/src/services/mailbox.ts`：邮箱状态查询和更新使用数字类型
- 修复 `worker/src/routes/mailbox.ts`：邮箱状态切换使用数字类型
- 修复 `worker/src/routes/user-info.ts`：用户查询条件使用数字类型
- 修复 `worker/src/services/permission.ts`：权限验证使用数字类型
- 移除 `toggleUserStatus` 函数，直接在路由中处理状态更新
- 修复 `toggleMailboxStatus` 函数参数类型

**测试验证：**
- 用户列表查询：`GET /api/admin/users` ✅
- 用户状态切换：`PUT /api/users/{id}/status` ✅
- 状态值验证：只接受1(启用)或2(停用) ✅
- 数据库一致性：所有status字段使用INTEGER类型 ✅

#### 修复管理员用户列表接口 - 参数传递和类型转换 (2025-01-21)

**问题描述：**
- `/api/admin/users?page=1&limit=20` 接口调用失败
- `getAllUsers` 函数参数传递不正确
- 用户状态字段类型转换不一致

**修复内容：**
- 修复 `worker/src/routes/admin.ts` 中 `getAllUsers` 函数调用参数
- 统一用户状态字段类型为 `1 | 2 | 3`（数字类型）
- 修复 `toggleUserStatus` 函数中的状态转换逻辑
- 完善分页参数传递和返回数据结构

**技术实现：**
- 修正 `getAllUsers` 函数调用：传递正确的 `page`, `limit`, `searchParams` 参数
- 统一状态类型：数据库使用 INTEGER，TypeScript 使用 `1 | 2 | 3`
- 添加状态转换：字符串状态（'active'/'disabled'）转换为数字状态（1/2）
- 完善返回数据：包含 `total`, `items`, `page`, `limit`, `total_pages`

**测试验证：**
- 基础分页查询：`GET /api/admin/users?page=1&limit=20` ✅
- 搜索查询：`GET /api/admin/users?page=1&limit=10&query=admin` ✅
- 返回数据结构完整，包含所有必要字段

#### 优化 Worker 静态资源处理 - 移除动态注入 (2025-01-20)

**变更内容：**
- 移除 Worker 后端直接返回 HTML 字符串的代码
- 保留 ASSETS 绑定，通过 Cloudflare 原生方式提供静态资源
- 移除动态配置注入功能，前端通过 API 获取配置

**技术实现：**
- 删除 `worker/src/utils/dynamic-config.ts`：动态配置注入功能
- 删除 `worker/src/static/` 目录：前端代码生成器
- 删除 `worker/src/templates/` 目录：HTML 模板生成器  
- 删除 `worker/src/utils/template.ts`：模板加载器
- 保留 `worker/src/main.ts` 中的 ASSETS 绑定处理逻辑
- 恢复 `wrangler.toml` 中的 ASSETS 绑定配置

**架构改进：**
- Worker 后端通过 ASSETS 绑定提供静态资源，不直接返回 HTML 字符串
- 前端通过 `/api` 接口获取系统配置和动态数据
- 简化了动态配置逻辑，提升了性能
- 保持了 Cloudflare 原生的静态资源服务能力

#### 统一缓存策略 - 全面使用 localStorage (2025-01-20)

**变更内容：**
- 统一使用 localStorage 进行缓存，完全移除 sessionStorage 的使用
- 确保系统配置和用户数据的持久化存储
- 提升用户体验，避免标签页关闭后数据丢失

**技术实现：**
- 更新 `vue/src/layouts/Admin/DebugView.vue`：移除 sessionStorage 相关代码
- 修改 `worker/src/static/app-config.ts`：将 SessionCache 改为 LocalCache
- 重构 `worker/src/utils/session-cache.ts` → `local-cache.ts`：完全基于 localStorage
- 更新 `docs/CACHE_API.md`：反映缓存策略变更

**缓存策略改进：**
- 所有缓存数据使用 `cem_cache_` 前缀存储在 localStorage
- 系统配置持久化存储，不会因标签页关闭而丢失
- 保持 TTL 机制，自动清理过期缓存
- 统一缓存管理接口，简化开发维护

#### 移除环境变量依赖 - 完全基于数据库配置 (2025-01-20)

**变更内容：**
- 移除了 `DOMAIN`、`JWT_SECRET`、`cem_debug`、`ALLOW_REGISTRATION`、`CLEANUP_DAYS`、`MAX_ATTACHMENT_SIZE` 环境变量的依赖
- 系统现在完全基于数据库中的系统设置进行配置
- 简化了部署配置，减少了环境变量管理的复杂性

**技术实现：**
- 修改 `worker/src/types/index.ts`：移除环境变量类型定义
- 更新 `worker/src/main.ts`：移除环境变量使用
- 修改 `worker/src/routes/api.ts`：使用 `getPrimaryDomain()` 替代 `c.env.DOMAIN`
- 更新 `worker/src/routes/user.ts`：使用数据库配置替代环境变量
- 更新 `worker/src/routes/admin.ts`：使用数据库配置替代环境变量
- 清理 `wrangler.example.toml`：移除所有环境变量示例配置

**配置管理改进：**
- 域名配置：通过系统设置中的 `primary_domain` 或 `domains` 配置
- JWT密钥：通过 `getJWTSecret()` 函数自动管理（环境变量 > 数据库 > 自动生成）
- 调试模式：完全由数据库中的 `debug_mode` 设置控制
- 用户注册：通过数据库中的 `allow_registration` 设置控制
- 邮件清理：通过数据库中的 `cleanup_days` 设置控制
- 附件大小：通过数据库中的 `max_attachment_size` 设置控制

**文档更新：**
- 更新 `docs/README.md`：移除所有环境变量说明，更新为完全基于数据库配置
- 更新 `docs/CACHE_API.md`：移除环境变量接口定义
- 更新 `wrangler.example.toml`：移除所有环境变量示例配置

#### 系统配置参数类型统一 - 统一使用数字格式 (2025-01-20)

**问题描述：**
- SystemConfig、SystemConfigUpdate 和 health 接口中的配置参数类型不统一
- health 接口使用数字格式 (1/0)，而 SystemConfig 使用布尔格式 (true/false)
- 需要统一所有接口使用数字格式，提高一致性

**统一方案：**
- 所有配置参数统一使用数字格式：1=是/开启，0=否/关闭
- 包括：`debug_mode`、`allow_registration`、`auto_approve_mailbox`、`allow_user_send`

**API文档更新：**
- `SystemConfig` 接口：所有布尔类型参数改为数字类型
- `SystemConfigUpdate` 接口：所有布尔类型参数改为数字类型
- health 接口：保持数字格式不变

**后端更新：**
- `worker/src/types/index.ts`：SystemConfig 接口类型定义更新
- `worker/src/services/settings.ts`：配置读取和更新逻辑适配数字格式
- `worker/src/routes/system.ts`：健康检查接口配置返回逻辑简化

**前端更新：**
- `vue/src/types/index.ts`：相关接口类型定义更新
- `vue/src/composables/system.ts`：配置读取逻辑适配数字格式

**文件变更：**
- `api/api-doc.yml` - 更新 SystemConfig 和 SystemConfigUpdate 类型定义
- `worker/src/types/index.ts` - 更新 SystemConfig 接口类型
- `worker/src/services/settings.ts` - 适配数字格式的配置处理
- `worker/src/routes/system.ts` - 简化健康检查配置返回
- `vue/src/types/index.ts` - 更新前端类型定义
- `vue/src/composables/system.ts` - 适配数字格式的配置读取

#### API数据格式统一 - 统一health和config接口的数据格式 (2025-01-20)

**问题描述：**
- 后端响应的数据格式不统一：`/api/system/config` 返回 `"debug_mode": false`，`/api/system/health` 返回 `"debug_mode": 0`
- 需要根据 API 文档统一数据格式

**统一方案：**
- `/api/system/config` 接口：返回 `boolean` 类型（true/false）
- `/api/system/health` 接口：返回 `integer` 类型（1/0）
- 前端需要处理两种不同的数据格式

**API文档更新：**
- 更新 health 接口的 config 字段定义，只保留 `allow_registration` 和 `debug_mode` 两个字段
- 移除不需要的敏感字段：`allow_user_send`、`max_mailboxes_per_user`、`storage_provider`、`max_attachment_size`、`mail_retention_days`、`supported_domains`

**前端处理：**
- health 接口返回 `debug_mode: 0/1`，前端转换为 `boolean` 类型
- config 接口返回 `debug_mode: true/false`，前端直接使用
- 统一存储到 `systemStore.systemConfig` 中

**文件变更：**
- `api/api-doc.yml` - 更新 health 接口的 config 字段定义
- `vue/src/composables/system.ts` - 处理不同数据格式的转换

#### 安全优化 - 精简health接口配置字段 (2025-01-20)

**安全考虑：**
- health 接口的 config 字段不应该泄露太多敏感信息
- 只保留前端真正需要的配置字段
- 缓存更新应该在配置修改的地方进行，而不是在 health 接口

**优化内容：**
- 移除 health 接口中的 `storage_provider` 字段
- 只保留 `allow_registration` 和 `debug_mode` 两个前端必需的字段
- 移除 health 接口中的缓存更新逻辑
- 缓存更新由 `updateSystemConfig` 函数在配置修改时自动处理

**保留的配置字段：**
- `allow_registration`: 注册状态（前端需要）
- `debug_mode`: 调试模式（前端需要）

**缓存更新策略：**
- health 接口：只获取配置，不更新缓存
- 配置修改：通过 `updateSystemConfig` → `setSystemSetting` → 自动更新缓存
- 其他接口：通过 `getSystemConfig` 从缓存读取

**文件变更：**
- `worker/src/routes/system.ts` - 精简 health 接口配置字段，移除缓存更新
- `vue/src/types/index.ts` - 更新 SystemHealth 接口类型

#### 缓存共享优化 - health接口作为systemConfig同步器 (2025-01-20)

**优化思路：**
- health 接口负责将 config 字段同步到 `systemConfig` 缓存
- 其他接口的关键内容都从 `systemConfig` 读取
- health 接口变成"配置同步器"，避免重复数据库查询

**技术实现：**
- 新增 `updateSystemSettingsCache()` 函数：批量更新系统设置缓存（不写入数据库）
- 修改 health 接口：获取配置后同步到 `systemConfig` 缓存
- 前端统一从 `systemConfig` 读取配置，不再依赖 health 接口的 config 字段
- 更新 `SystemConfig` 接口：添加缺失的配置字段，确保类型安全

**工作流程：**
1. **health 接口**：查询数据库 → 同步到 `systemConfig` 缓存 → 返回健康状态
2. **其他接口**：直接从 `systemConfig` 缓存读取配置
3. **前端**：统一从 `systemConfig` 获取配置，保证数据一致性

**性能改进：**
- 减少重复的数据库查询
- 提高配置获取的响应速度
- 统一配置管理，避免数据不一致
- health 接口承担配置同步职责

**文件变更：**
- `worker/src/services/settings.ts` - 新增缓存更新函数，完善类型定义
- `worker/src/routes/system.ts` - health接口同步配置到缓存
- `vue/src/composables/system.ts` - 统一从systemConfig读取配置
- `worker/src/types/index.ts` - 完善SystemConfig接口

#### 前端调试模式显示修复 - 优先使用health接口配置 (2025-01-20)

**问题描述：**
- 前端调试模式在调试模式未开启的情况下依然显示
- 前端没有正确使用 `/api/system/health` 接口中的 `debug_mode` 字段
- 多个地方使用硬编码的调试模式检查逻辑

**修复内容：**
- 更新 `SystemHealth` 类型定义，匹配实际的 health 接口数据结构
- 修改 `system.ts` 中的 `isDebugMode` 计算属性，优先使用 health 接口中的 `debug_mode` 配置
- 添加 `isRegistrationAllowed` 计算属性，同样优先使用 health 接口配置
- 统一所有调试模式检查逻辑，移除硬编码的环境变量检查

**技术实现：**
- 更新 `vue/src/types/index.ts`：修正 `SystemHealth` 接口结构
- 优化 `vue/src/composables/system.ts`：优先使用 health 接口配置
- 修复 `vue/src/composables/routes.ts`：使用 systemStore 的调试模式状态
- 更新 `vue/src/composables/globalState.ts`：统一调试模式获取方式

**数据结构对应：**
```json
{
  "success": true,
  "data": {
    "health": {
      "config": {
        "debug_mode": 0,  // 0=关闭, 1=开启
        "allow_registration": 0
      }
    }
  }
}
```

**文件变更：**
- `vue/src/types/index.ts` - 更新 SystemHealth 接口
- `vue/src/composables/system.ts` - 优化调试模式检查逻辑
- `vue/src/composables/routes.ts` - 统一调试模式权限检查
- `vue/src/composables/globalState.ts` - 移除硬编码调试模式

#### 调试模式查询优化 - 避免重复数据库查询 (2025-01-20)

**变更内容：**
- 创建了专门的调试模式中间件 `debugModeMiddleware`
- 优化了调试模式检查逻辑，避免重复数据库查询
- 统一了调试模式检查的实现方式

**技术实现：**
- 新增 `worker/src/middleware/debug.ts`：专门的调试模式中间件
- 优化 `database.ts`：移除重复的调试模式查询代码，使用中间件
- 更新 `main.ts`：调试接口使用新的中间件链
- 利用 `getSystemConfig()` 的缓存机制，提高性能

**性能改进：**
- 减少了重复的数据库查询
- 统一使用缓存的系统配置
- 简化了调试模式检查逻辑

**文件变更：**
- `worker/src/middleware/debug.ts` - 新增调试模式中间件
- `worker/src/routes/database.ts` - 使用中间件，移除重复查询
- `worker/src/main.ts` - 调试接口使用中间件链

#### 调试模式配置优化 - 移除环境变量依赖 (2025-01-20)

**变更内容：**
- 移除了 worker 中通过环境变量 `cem_debug` 检查调试模式的逻辑
- 调试模式现在完全由数据库中的 `debug_mode` 设置控制
- 简化了调试模式检查逻辑，提高了配置的一致性

**技术实现：**
- 修改 `main.ts`：移除所有 `c.env.cem_debug` 检查，只依赖数据库配置
- 更新 `database.ts`：简化调试模式校验逻辑，统一从数据库读取
- 优化 `debug.ts`：移除环境变量依赖，更新初始化逻辑
- 清理 `types/index.ts`：移除 `cem_debug` 环境变量类型定义

**配置管理改进：**
- 调试模式现在完全由管理员通过系统设置界面控制
- 不再需要修改环境变量来启用/禁用调试功能
- 提高了配置的透明度和可管理性

**文件变更：**
- `worker/src/main.ts` - 移除环境变量检查逻辑
- `worker/src/routes/database.ts` - 简化调试模式校验
- `worker/src/utils/debug.ts` - 更新初始化逻辑
- `worker/src/types/index.ts` - 移除环境变量类型定义

#### UI优化 - 移除刷新检测并添加手动刷新按钮 (2025-09-20)

**变更内容：**
- 删除了所有基于 `performance.navigation` 的自动刷新检测代码
- 在顶部工具栏（top-bar）添加了手动刷新按钮
- 实现了清理当前页面缓存并重新加载的功能

**技术实现：**
- 修改 `useSimplePageData.ts`：移除刷新检测逻辑，简化初始加载流程
- 增强 `cache.ts`：添加 `clearAndRefreshCurrentPage` 方法支持页面级缓存清理
- 更新 `MainLayoutView.vue`：在菜单按钮旁边添加刷新按钮，显示加载状态

**用户体验提升：**
- 用户可以主动控制页面刷新，不再依赖自动检测
- 刷新按钮提供实时反馈（🔄 刷新 / 🔄 刷新中...）
- 更精确的缓存管理，只清理当前页面相关缓存

**文件变更：**
- `vue/src/composables/useSimplePageData.ts` - 移除刷新检测代码
- `vue/src/composables/cache.ts` - 添加页面级缓存清理方法
- `vue/src/layouts/MainLayoutView.vue` - 添加刷新按钮UI和交互逻辑

**Bug修复：**
- 修复 `admin-emails` 页面 "API method getEmails not found" 错误
- 在 `adminApiService` 中添加 `getEmails` 方法，支持管理员查看所有邮件
- 修复 `EmailsView.vue` 中缺少 `computed` 导入的问题
- 确保前后端数据结构一致：后端返回 `{ total: number, items: Email[] }`，前端正确解析
- 移除调试代码，清理模板中的临时输出

#### 开发环境优化 (2024-01-XX)
- **Docker 配置完善**：完善 `docker-compose.yml` 配置，前端和后端独立容器
  - 前端容器：`vue` 服务，运行 Vite 开发服务器
  - 后端容器：`worker` 服务，运行 wrangler dev
  - 共享 node_modules 卷，避免依赖冲突
- **文档清理**：删除过时的文档文件
  - 删除 `docs/FRONTEND_SEPARATION.md`
  - 删除 `docs/MIGRATION.md`
  - 删除 `docs/ENV_CONFIG.md`
- **数据库操作优化**：直接使用 wrangler d1 execute 命令
  - 通过 `docker exec -it worker zsh -c "node scripts/db.js 'SQL'"` 执行 SQL 命令
  - 支持 base64 编码的 SQL 命令
  - 简化了数据库操作流程，无需复杂的参数传递
- **文档更新**：更新所有文档反映新的容器化开发环境
- **脚本整合**：将根目录 `deploy.js` 的功能整合到 `scripts/deploy.js` 中
- **功能完善**：新的部署脚本包含完整的部署流程
  - 资源创建（D1、KV、R2）
  - 用户交互（域名输入、管理员密码等）
  - 数据库初始化和管理员账户创建
  - 配置文件更新（wrangler.toml）
  - 前后端构建和部署
- **命令统一**：更新 `package.json` 中的脚本引用
  - `npm run deploy` - 完整部署
  - `npm run init` - 同 deploy 命令
  - `npm run clean` - 清理所有 Cloudflare 资源
- **文档更新**：更新 `docs/SCRIPTS.md` 反映新的脚本功能

#### 后端架构重构 - 前后端分离 (2024-01-XX)
- **静态资源服务**：移除内嵌HTML模板，改为通过 ASSETS 绑定服务前端
- **API路由重构**：统一API路径设计，符合 OpenAPI 3.0 规范
  - 认证：`/api/auth/*` (login, logout, register)
  - 用户：`/api/users/*` (me, 用户管理)
  - 邮件：`/api/emails/*` (列表、详情、删除、发送、附件)
  - 邮箱：`/api/mailboxes/*` (申请、管理)
  - 转发规则：`/api/forward-rules/*` (CRUD操作)
  - 系统：`/api/system/*` (配置、健康检查)
  - 管理员：`/api/admin/*` (管理功能)
- **类型定义更新**：完善 TypeScript 类型定义，支持新的API结构
- **服务函数优化**：重构服务层函数，支持分页和权限控制
- **配置更新**：更新 wrangler.toml 配置，添加 ASSETS 绑定

#### API 接口优化 (2024-01-XX)
- **用户搜索功能**：`/api/users` 接口新增 `query` 参数，支持按用户名、邮箱搜索
- **邮件查询优化**：`/api/emails` 接口调整 `scope` 参数逻辑
  - 默认行为：普通用户获取自己的邮件，管理员获取自己的邮件
  - 全部邮件：仅当 `scope=all` 时管理员可获取全部邮件
  - 移除了 `scope=mine` 的默认值，简化了查询逻辑
- **登录接口简化**：`/api/auth/login` 只返回 JWT token，不返回用户信息
  - 前端登录后需要调用 `/api/users/me` 获取用户详细信息
  - 避免了接口间的数据重复，职责更加清晰
