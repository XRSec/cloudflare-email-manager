# 权限验证设计说明

## 🔐 权限验证系统

### **核心原则**
1. **用户存在性验证**：确保 `user_id` 是真实存在的用户
2. **权限范围验证**：确保用户只能操作自己有权限的资源
3. **操作人验证**：确保操作人身份真实，防止伪造
4. **所有者验证**：确保资源所有者身份真实，防止越权

## 🛡️ 权限验证函数

### **1. validateUserExists**
```typescript
// 验证用户是否存在且状态正常
const { exists, user } = await validateUserExists(db, userId);
```

**验证内容**：
- 用户ID是否存在于数据库中
- 用户状态是否为 `active`
- 返回用户基本信息

### **2. validateMailboxOwner**
```typescript
// 验证用户是否为邮箱所有者
const { isOwner, mailbox } = await validateMailboxOwner(db, mailboxId, userId);
```

**验证内容**：
- 邮箱是否存在
- 用户是否为邮箱的所有者
- 返回邮箱基本信息

### **3. validateAdminPermission**
```typescript
// 验证管理员权限
const { isAdmin, user } = await validateAdminPermission(db, userId);
```

**验证内容**：
- 用户是否存在
- 用户类型是否为 `admin`
- 用户状态是否为 `active`

### **4. validateMailboxOperationPermission**
```typescript
// 验证邮箱操作权限（综合验证）
const { hasPermission, mailbox, reason } = await validateMailboxOperationPermission(
    db, mailboxId, userId, userType
);
```

**验证内容**：
- 用户存在性验证
- 邮箱存在性验证
- 权限范围验证（管理员 vs 普通用户）
- 所有者权限验证

## 🔍 关键操作权限验证

### **邮箱删除操作**
```typescript
export async function deleteMailbox(
    db: D1Database, 
    mailboxId: number, 
    userId: number, 
    userType: string
): Promise<void> {
    // 1. 验证操作权限
    const permissionCheck = await validateMailboxOperationPermission(db, mailboxId, userId, userType);
    if (!permissionCheck.hasPermission) {
        throw new Error(permissionCheck.reason || '权限验证失败');
    }

    // 2. 验证用户存在
    const userValidation = await validateUserExists(db, userId);
    if (!userValidation.exists) {
        throw new Error('用户不存在');
    }

    // 3. 执行删除操作
    // 4. 记录操作历史
}
```

### **邮箱状态切换操作**
```typescript
export async function toggleMailboxStatus(
    db: D1Database,
    mailboxId: number,
    status: 'active' | 'disabled',
    adminId: number
): Promise<void> {
    // 1. 验证管理员权限
    const userValidation = await validateUserExists(db, adminId);
    if (!userValidation.exists) {
        throw new Error('用户不存在');
    }

    if (userValidation.user!.user_type !== 'admin') {
        throw new Error('需要管理员权限');
    }

    // 2. 验证邮箱存在
    const mailbox = await db.prepare(`
        SELECT id, owner_id, address, status FROM mailboxes WHERE id = ?
    `).bind(mailboxId).first();
    
    if (!mailbox) {
        throw new Error('邮箱不存在');
    }

    // 3. 执行状态切换
    // 4. 记录操作历史
}
```

## 📋 权限验证检查点

### **1. 用户身份验证**
- ✅ 用户ID是否存在于数据库
- ✅ 用户状态是否为 `active`
- ✅ 用户类型是否正确（admin/user）

### **2. 资源权限验证**
- ✅ 资源是否存在（邮箱、申请等）
- ✅ 用户是否有权限操作该资源
- ✅ 权限范围是否正确（自己的 vs 所有的）

### **3. 操作权限验证**
- ✅ 操作类型是否被允许
- ✅ 操作时机是否合适
- ✅ 操作结果是否符合预期

## 🚨 安全防护

### **1. 防止用户ID伪造**
```typescript
// 每次操作前都验证用户存在性
const userValidation = await validateUserExists(db, userId);
if (!userValidation.exists) {
    throw new Error('用户不存在');
}
```

### **2. 防止越权操作**
```typescript
// 验证用户是否有权限操作特定资源
const permissionCheck = await validateMailboxOperationPermission(db, resourceId, userId, userType);
if (!permissionCheck.hasPermission) {
    throw new Error('无权操作此资源');
}
```

### **3. 防止权限提升**
```typescript
// 验证管理员权限
if (userType === 'admin') {
    const adminValidation = await validateAdminPermission(db, userId);
    if (!adminValidation.isAdmin) {
        throw new Error('需要管理员权限');
    }
}
```

## 📊 权限验证流程

### **邮箱操作权限验证流程**
```
1. 验证用户存在性
   ├─ 用户不存在 → 抛出错误
   └─ 用户存在 → 继续

2. 验证资源存在性
   ├─ 资源不存在 → 抛出错误
   └─ 资源存在 → 继续

3. 验证权限范围
   ├─ 管理员 → 允许操作所有资源
   └─ 普通用户 → 验证是否为资源所有者

4. 执行操作
5. 记录操作历史
```

### **管理员操作权限验证流程**
```
1. 验证用户存在性
   ├─ 用户不存在 → 抛出错误
   └─ 用户存在 → 继续

2. 验证管理员权限
   ├─ 不是管理员 → 抛出错误
   └─ 是管理员 → 继续

3. 验证资源存在性
4. 执行操作
5. 记录操作历史
```

## 🔧 实现细节

### **数据库查询优化**
```sql
-- 用户存在性验证（带状态检查）
SELECT id, username, user_type, created_at
FROM users 
WHERE id = ? AND status = 'active'

-- 邮箱所有者验证
SELECT id, owner_id, address, status
FROM mailboxes 
WHERE id = ? AND owner_id = ?

-- 管理员权限验证
SELECT id, username, user_type
FROM users 
WHERE id = ? AND user_type = 'admin' AND status = 'active'
```

### **错误处理**
```typescript
// 统一的错误处理
if (!permissionCheck.hasPermission) {
    throw new Error(permissionCheck.reason || '权限验证失败');
}
```

### **日志记录**
```typescript
// 权限验证成功日志
debugLog('[权限验证] 邮箱所有者权限验证通过:', userId, '邮箱ID:', mailboxId);

// 权限验证失败日志
debugLog('[权限验证] 权限验证失败:', userId, '邮箱ID:', mailboxId, '原因:', reason);
```

## 📝 最佳实践

### **1. 始终验证用户存在性**
- 每个需要用户ID的操作都要验证用户存在
- 防止伪造用户ID进行攻击

### **2. 权限验证前置**
- 在执行任何操作前先验证权限
- 避免无效操作和资源浪费

### **3. 详细的错误信息**
- 提供清晰的错误原因
- 便于调试和问题排查

### **4. 完整的操作记录**
- 记录所有关键操作
- 包含操作人、资源、时间等信息

### **5. 权限验证复用**
- 使用统一的权限验证函数
- 避免重复代码和逻辑不一致

## 🎯 总结

通过完善的权限验证系统，我们确保了：

1. **安全性**：防止用户ID伪造和越权操作
2. **一致性**：统一的权限验证逻辑
3. **可维护性**：清晰的权限验证流程
4. **可扩展性**：支持更多权限验证场景
5. **可追踪性**：完整的操作记录和日志

这样的设计确保了系统的安全性和可靠性！🛡️
