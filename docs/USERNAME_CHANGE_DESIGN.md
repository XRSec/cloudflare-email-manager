# 用户名修改设计说明

## 🚨 当前问题

### **MailboxWithUser.owner_username 的问题**
当前设计中，`MailboxWithUser` 接口包含 `owner_username` 字段，这会导致以下问题：

1. **数据不一致**：如果用户修改用户名，`owner_username` 会过时
2. **维护困难**：需要同步更新所有相关记录
3. **查询复杂**：需要额外的 JOIN 操作

## 💡 解决方案

### **方案1：始终通过 owner_id 查询（推荐）**

#### **优点**
- 数据一致性：始终获取最新用户名
- 维护简单：无需同步更新
- 性能优化：减少数据冗余

#### **实现方式**
```typescript
// 查询时动态获取用户名
const mailboxes = await db.prepare(`
    SELECT 
        m.id,
        m.owner_id,
        m.address,
        m.status,
        m.created_at,
        m.updated_at,
        u.username as owner_username
    FROM mailboxes m
    JOIN users u ON m.owner_id = u.id
    WHERE m.status = 'active'
`).all();
```

### **方案2：缓存用户名（不推荐）**

#### **缺点**
- 数据不一致风险
- 需要复杂的同步机制
- 维护成本高

## 🔧 技术实现

### **数据库设计**
```sql
-- 邮箱表只存储 owner_id
CREATE TABLE mailboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,           -- 只存储用户ID
    address TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 用户表支持用户名修改
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,       -- 用户名可修改
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    user_type TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### **API 响应设计**
```typescript
// 邮箱列表响应
interface MailboxListResponse {
    total: number;
    items: Array<{
        id: number;
        owner_id: number;
        address: string;
        status: string;
        created_at: string;
        updated_at: string;
        owner_username: string;  // 动态查询获取
    }>;
}
```

### **前端处理**
```typescript
// 前端始终使用 owner_id 作为唯一标识
const mailbox = {
    id: 1,
    owner_id: 123,           // 唯一标识
    owner_username: "user1", // 显示用，可随时更新
    address: "user1@example.com"
};

// 如果用户名修改，重新查询即可
const updatedMailbox = await fetchMailbox(mailbox.id);
```

## 📋 最佳实践

### **1. 数据查询**
- 始终通过 `owner_id` 关联查询用户名
- 避免在数据库中存储冗余的用户名信息
- 使用 JOIN 查询获取最新用户名

### **2. 缓存策略**
- 前端可以缓存用户名，但需要定期更新
- 后端不缓存用户名，始终查询最新数据
- 使用 `owner_id` 作为缓存键

### **3. 错误处理**
- 如果用户被删除，`owner_id` 关联会失效
- 需要处理用户不存在的情况
- 提供友好的错误提示

### **4. 性能优化**
- 为 `owner_id` 字段创建索引
- 使用适当的 JOIN 查询
- 考虑分页查询的性能

## 🎯 实施建议

### **立即实施**
1. 修改 `MailboxWithUser` 接口，移除 `owner_username` 字段
2. 更新所有查询，使用 JOIN 获取用户名
3. 修改前端代码，使用 `owner_id` 作为唯一标识

### **长期规划**
1. 考虑添加用户名修改历史记录
2. 实现用户名唯一性检查
3. 添加用户名修改的审计日志

## 🔍 相关文件

- `worker/src/types/index.ts` - 类型定义
- `worker/src/services/mailbox.ts` - 邮箱服务
- `vue/src/api/index.ts` - 前端类型定义
- `api/api-doc.yml` - API 文档

## 📝 总结

通过始终使用 `owner_id` 查询用户名，我们可以：

1. **保证数据一致性**：用户名修改后，所有相关查询都会返回最新值
2. **简化维护**：无需同步更新多个表
3. **提高性能**：减少数据冗余，优化查询效率
4. **增强可扩展性**：支持用户名修改功能

这是一个更加健壮和可维护的设计方案。
