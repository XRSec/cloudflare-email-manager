# 邮箱状态说明文档

## 📋 邮箱状态定义

### **active（正常）**
- **含义**：邮箱处于正常使用状态
- **权限**：可以接收邮件，用户可以正常使用
- **操作**：用户可以删除邮箱，管理员可以停用邮箱
- **显示**：绿色标签显示"正常"

### **disabled（停用）**
- **含义**：被管理员停用/封禁的邮箱
- **权限**：不能接收邮件，用户无法使用
- **操作**：只有管理员可以重新激活
- **限制**：该邮箱地址不能被其他用户申请
- **显示**：红色标签显示"停用"

### **deleted（已删除）**
- **含义**：用户主动删除的邮箱
- **权限**：不能接收邮件，用户无法使用
- **操作**：用户可以重新申请该邮箱地址
- **限制**：该邮箱地址可以被其他用户申请
- **显示**：橙色标签显示"已删除"

## 🔄 状态转换流程

### **用户操作流程**
```
active → deleted（用户删除邮箱）
```

### **管理员操作流程**
```
active → disabled（管理员停用邮箱）
disabled → active（管理员重新激活邮箱）
```

### **邮箱重新申请流程**
```
deleted → active（用户重新申请已删除的邮箱）
```

## 📊 状态对比表

| 状态 | 接收邮件 | 用户可见 | 可重新申请 | 管理员操作 | 用户操作 |
|------|----------|----------|------------|------------|----------|
| active | ✅ | ✅ | ❌ | 停用 | 删除 |
| disabled | ❌ | ❌ | ❌ | 激活 | ❌ |
| deleted | ❌ | ❌ | ✅ | ❌ | 重新申请 |

## 🎯 业务场景

### **场景1：用户删除邮箱**
1. 用户删除邮箱 `user@example.com`
2. 邮箱状态变为 `deleted`
3. 用户或其他用户可以重新申请 `user@example.com`
4. 重新申请后状态变为 `active`

### **场景2：管理员封禁邮箱**
1. 管理员发现邮箱 `spam@example.com` 发送垃圾邮件
2. 管理员将邮箱状态设为 `disabled`
3. 该邮箱地址永久不可用，不能被重新申请
4. 只有管理员可以重新激活

### **场景3：邮箱查询逻辑**
- **用户查询**：只显示 `active` 状态的邮箱
- **管理员查询**：显示所有状态的邮箱
- **邮箱申请**：检查 `active` 和 `disabled` 状态，允许 `deleted` 状态重新申请

## 🔧 技术实现

### **数据库约束**
```sql
status TEXT DEFAULT 'active' CHECK(status IN ('active','disabled','deleted'))
```

### **查询逻辑**
```sql
-- 用户查询邮箱（只显示 active）
SELECT * FROM mailboxes WHERE status = 'active' AND owner_id = ?

-- 管理员查询邮箱（显示所有状态）
SELECT * FROM mailboxes WHERE owner_id = ?

-- 检查邮箱是否可用（排除 deleted）
SELECT * FROM mailboxes WHERE address = ? AND status IN ('active', 'disabled')
```

### **状态更新**
```sql
-- 用户删除邮箱
UPDATE mailboxes SET status = 'deleted' WHERE id = ?

-- 管理员停用邮箱
UPDATE mailboxes SET status = 'disabled' WHERE id = ?

-- 重新激活邮箱
UPDATE mailboxes SET status = 'active', owner_id = ? WHERE address = ?
```

## 📝 注意事项

1. **数据一致性**：删除邮箱时邮件不会消失，仍然属于用户
2. **权限控制**：只有管理员可以操作 `disabled` 状态
3. **邮箱唯一性**：`active` 和 `disabled` 状态的邮箱地址唯一，`deleted` 状态可以重新申请
4. **状态显示**：前端需要根据状态显示不同的标签和操作按钮
5. **API 响应**：API 需要根据用户权限返回不同状态的邮箱列表
