import { Hono } from 'hono'
import { HTTPException } from 'hono/http-exception'
import { jwtAuthMiddleware, adminAuthMiddleware } from '../middleware/auth'
import { debugModeMiddleware } from '../middleware/debug'
import { hashPassword } from '../utils/crypto'
import { getSystemConfig } from '../services/settings'
import type { Env, D1Database } from '../types'

// =====================================================
// 数据库 SQL 语句集中管理（与 db/schema.sql 保持一致）
// =====================================================

const DATABASE_SCHEMAS = {
  // 基础表（无外键依赖）
  users: `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL CHECK(LENGTH(username) >= 3 AND LENGTH(username) <= 50),
      password TEXT NOT NULL CHECK(LENGTH(password) >= 6),
      user_type INTEGER DEFAULT 0 CHECK(user_type IN (0,1)), -- 0=普通用户, 1=管理员
      status INTEGER DEFAULT 1 CHECK(status IN (1,2,3)),
      deleted_at DATETIME,
      webhook_url TEXT CHECK(webhook_url IS NULL OR webhook_url LIKE 'http%'),
      webhook_secret TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `,

  system_settings: `
    CREATE TABLE IF NOT EXISTS system_settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `,

  forward_rules: `
    CREATE TABLE IF NOT EXISTS forward_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rule_name TEXT NOT NULL,
      sender_filter TEXT,
      keyword_filter TEXT,
      recipient_filter TEXT,
      webhook_url TEXT NOT NULL,
      webhook_secret TEXT,
      webhook_type TEXT DEFAULT 'custom',
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0,1)),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `,

  emails: `
    CREATE TABLE IF NOT EXISTS emails (
      id TEXT PRIMARY KEY,
      message_id TEXT,
      subject TEXT NOT NULL,
      from_address TEXT NOT NULL,
      to_address TEXT NOT NULL,
      reply_to TEXT,
      cc TEXT,
      bcc TEXT,
      content_type TEXT DEFAULT 'text/plain',
      content TEXT,
      raw_content TEXT,
      is_read INTEGER DEFAULT 0 CHECK(is_read IN (0,1)),
      has_attachments INTEGER DEFAULT 0 CHECK(has_attachments IN (0,1)),
      size_bytes INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `,

  // 依赖 users 的表
  mailboxes: `
    CREATE TABLE IF NOT EXISTS mailboxes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      address TEXT UNIQUE NOT NULL CHECK(address LIKE '%@%'),
      status INTEGER DEFAULT 1 CHECK(status IN (1,2,3)),
      deleted_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `,

  mailbox_applications: `
    CREATE TABLE IF NOT EXISTS mailbox_applications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      requested_address TEXT NOT NULL CHECK(requested_address LIKE '%@%'),
      reason TEXT,
      status INTEGER DEFAULT 0 CHECK(status IN (0,1,2)),
      admin_comment TEXT,
      processed_by INTEGER,
      processed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (processed_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `,

  security_audit: `
    CREATE TABLE IF NOT EXISTS security_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      action_type INTEGER NOT NULL,
      resource_type INTEGER, -- 0=mailbox, 1=email, 2=user, 3=system
      resource_id INTEGER,
      request_ip TEXT,
      user_agent TEXT,
      attack_type INTEGER,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `,

  user_webhooks: `
    CREATE TABLE IF NOT EXISTS user_webhooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      webhook_name TEXT NOT NULL,
      webhook_url TEXT NOT NULL,
      webhook_secret TEXT,
      webhook_type TEXT DEFAULT 'custom',
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0,1)),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `,

  // 依赖多个表的表
  mailbox_history: `
    CREATE TABLE IF NOT EXISTS mailbox_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mailbox_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      owner_id INTEGER NOT NULL,
      action_type INTEGER NOT NULL CHECK(action_type IN (1,2,3)),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `,

  attachments: `
    CREATE TABLE IF NOT EXISTS attachments (
      id TEXT PRIMARY KEY,
      email_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      content_type TEXT,
      size_bytes INTEGER DEFAULT 0,
      r2_key TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
    )
  `,

  forward_logs: `
    CREATE TABLE IF NOT EXISTS forward_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email_id TEXT NOT NULL,
      rule_id INTEGER,
      webhook_url TEXT NOT NULL,
      status INTEGER NOT NULL CHECK(status IN (0,1)), -- 0=成功, 1=失败
      response_code INTEGER,
      error_message TEXT,
      sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE,
      FOREIGN KEY (rule_id) REFERENCES forward_rules(id) ON DELETE SET NULL
    )
  `
}

// 触发器创建 SQL 语句
const DATABASE_TRIGGERS = [
  `CREATE TRIGGER update_users_updated_at
    AFTER UPDATE ON users
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END`,

  `CREATE TRIGGER update_mailboxes_updated_at
    AFTER UPDATE ON mailboxes
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE mailboxes SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END`,

  `CREATE TRIGGER update_mailbox_applications_updated_at
    AFTER UPDATE ON mailbox_applications
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE mailbox_applications SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END`,

  `CREATE TRIGGER update_emails_updated_at
    AFTER UPDATE ON emails
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE emails SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END`,

  `CREATE TRIGGER update_attachments_updated_at
    AFTER UPDATE ON attachments
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE attachments SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END`,

  `CREATE TRIGGER update_forward_rules_updated_at
    AFTER UPDATE ON forward_rules
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE forward_rules SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END`,

  `CREATE TRIGGER update_user_webhooks_updated_at
    AFTER UPDATE ON user_webhooks
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE user_webhooks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END`,

  `CREATE TRIGGER update_system_settings_updated_at
    AFTER UPDATE ON system_settings
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE system_settings SET updated_at = CURRENT_TIMESTAMP WHERE key = NEW.key;
END`,

  `CREATE TRIGGER update_forward_logs_updated_at
    AFTER UPDATE ON forward_logs
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE forward_logs SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END`
]

// 索引创建 SQL 语句
const DATABASE_INDEXES = [
  // 用户表索引
  'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
  'CREATE INDEX IF NOT EXISTS idx_users_user_type ON users(user_type)',
  'CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)',

  // 邮箱表索引
  'CREATE INDEX IF NOT EXISTS idx_mailboxes_owner_id ON mailboxes(owner_id)',
  'CREATE INDEX IF NOT EXISTS idx_mailboxes_address ON mailboxes(address)',
  'CREATE INDEX IF NOT EXISTS idx_mailboxes_status ON mailboxes(status)',

  // 邮箱申请表索引
  'CREATE INDEX IF NOT EXISTS idx_mailbox_applications_user_id ON mailbox_applications(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_mailbox_applications_status ON mailbox_applications(status)',
  'CREATE INDEX IF NOT EXISTS idx_mailbox_applications_processed_at ON mailbox_applications(processed_at)',
  'CREATE INDEX IF NOT EXISTS idx_mailbox_applications_requested_address ON mailbox_applications(requested_address)',

  // 邮箱历史表索引
  'CREATE INDEX IF NOT EXISTS idx_mailbox_history_mailbox_id ON mailbox_history(mailbox_id)',
  'CREATE INDEX IF NOT EXISTS idx_mailbox_history_user_id ON mailbox_history(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_mailbox_history_owner_id ON mailbox_history(owner_id)',
  'CREATE INDEX IF NOT EXISTS idx_mailbox_history_action_type ON mailbox_history(action_type)',
  'CREATE INDEX IF NOT EXISTS idx_mailbox_history_created_at ON mailbox_history(created_at)',

  // 安全审计表索引
  'CREATE INDEX IF NOT EXISTS idx_security_audit_user_id ON security_audit(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_security_audit_action_type ON security_audit(action_type)',
  'CREATE INDEX IF NOT EXISTS idx_security_audit_attack_type ON security_audit(attack_type)',
  'CREATE INDEX IF NOT EXISTS idx_security_audit_created_at ON security_audit(created_at)',
  'CREATE INDEX IF NOT EXISTS idx_security_audit_request_ip ON security_audit(request_ip)',

  // 邮件表索引
  'CREATE INDEX IF NOT EXISTS idx_emails_from_address ON emails(from_address)',
  'CREATE INDEX IF NOT EXISTS idx_emails_to_address ON emails(to_address)',
  'CREATE INDEX IF NOT EXISTS idx_emails_subject ON emails(subject)',
  'CREATE INDEX IF NOT EXISTS idx_emails_is_read ON emails(is_read)',
  'CREATE INDEX IF NOT EXISTS idx_emails_user_id ON emails(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_emails_sender_email ON emails(sender_email)',
  'CREATE INDEX IF NOT EXISTS idx_emails_recipient_email ON emails(recipient_email)',
  'CREATE INDEX IF NOT EXISTS idx_emails_received_at ON emails(received_at)',
  'CREATE INDEX IF NOT EXISTS idx_emails_created_at ON emails(created_at)',

  // 附件表索引
  'CREATE INDEX IF NOT EXISTS idx_attachments_email_id ON attachments(email_id)',
  'CREATE INDEX IF NOT EXISTS idx_attachments_r2_key ON attachments(r2_key)',
  'CREATE INDEX IF NOT EXISTS idx_attachments_content_type ON attachments(content_type)',

  // 转发规则表索引
  'CREATE INDEX IF NOT EXISTS idx_forward_rules_enabled ON forward_rules(enabled)',
  'CREATE INDEX IF NOT EXISTS idx_forward_rules_webhook_type ON forward_rules(webhook_type)',

  // 用户Webhook表索引
  'CREATE INDEX IF NOT EXISTS idx_user_webhooks_user_id ON user_webhooks(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_user_webhooks_enabled ON user_webhooks(enabled)',
  'CREATE INDEX IF NOT EXISTS idx_user_webhooks_webhook_type ON user_webhooks(webhook_type)',

  // 转发日志表索引
  'CREATE INDEX IF NOT EXISTS idx_forward_logs_email_id ON forward_logs(email_id)',
  'CREATE INDEX IF NOT EXISTS idx_forward_logs_status ON forward_logs(status)',
  'CREATE INDEX IF NOT EXISTS idx_forward_logs_sent_at ON forward_logs(sent_at)'
]

// 初始化数据 SQL 语句（与 schema.sql 保持一致）
const INITIAL_DATA_SQL = {
  // 系统设置数据
  systemSettings: `
    INSERT OR IGNORE INTO system_settings (key, value, description) VALUES
    ('allow_registration', '0', '是否允许用户自由注册 (1=是, 0=否)'),
    ('cleanup_days', '7', '邮件自动清理天数'),
    ('max_attachment_size', '52428800', '最大附件大小（50MB）'),
    ('domain', 'example.com', '邮件域名'),
    ('admin_email', 'admin@example.com', '管理员邮箱'),
    ('primary_domain', 'example.com', '主域名'),
    ('cookie_max_age', '604800', 'Cookie过期时间（秒）'),
    ('debug_mode', '0', '调试模式开关 (1=开启, 0=关闭)'),
    ('domains', '["example.com"]', '支持的域名列表（JSON格式）'),
    ('auto_approve_mailbox', '0', '是否自动批准邮箱申请 (1=是, 0=否)'),
    ('reserved_mailboxes', '["admin","administrator","root","postmaster","abuse","noreply","no-reply","support","info","contact","webmaster","mail","email","help","security","privacy","legal","billing","sales","marketing","news","newsletter","updates","alerts","notifications"]', '保留邮箱列表（JSON格式）'),
    ('max_mailboxes_per_user', '5', '每个用户最大邮箱数量')
  `,

  // 测试用户数据
  testUser: `
    INSERT OR IGNORE INTO users (username, password, user_type, status) 
    VALUES ('test', ?, 0, 1)
  `,

  // 测试用户邮箱
  testUserMailbox: `
    INSERT INTO mailboxes (owner_id, address, status) 
    VALUES (?, 'test@example.com', 1)
  `,

  // 管理员用户数据
  adminUser: `
    INSERT OR IGNORE INTO users (username, password, user_type, status) 
    VALUES ('admin', ?, 1, 1)
  `,

  // 管理员用户邮箱
  adminUserMailbox: `
    INSERT INTO mailboxes (owner_id, address, status) 
    VALUES (?, 'admin@example.com', 1)
  `
}

// 创建数据库路由实例
const databaseRoutes = new Hono<{ Bindings: Env }>()

// 应用认证、管理员权限和调试模式中间件
databaseRoutes.use('*', jwtAuthMiddleware)
databaseRoutes.use('*', adminAuthMiddleware)
databaseRoutes.use('*', debugModeMiddleware)

// 获取数据库信息
databaseRoutes.get('/info', async (c) => {
  try {
    // 调试模式检查已由中间件处理

    // 获取SQLite版本（使用兼容的方法）
    let sqliteVersion = { version: 'Cloudflare D1' };
    try {
      sqliteVersion = await c.env.DB.prepare('SELECT sqlite_version() as version').first() || sqliteVersion;
    } catch (error) {
      // D1可能不支持某些SQLite函数，使用默认值
      console.warn('无法获取SQLite版本，使用默认值:', error);
    }

    // 获取所有表信息
    const tables = await c.env.DB.prepare(`
      SELECT name, type FROM sqlite_master 
      WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
      ORDER BY name
    `).all()

    // 获取每个表的记录数
    const tableStats: Record<string, any> = {}
    let totalRecords = 0

    for (const table of tables.results) {
      try {
        const count = await c.env.DB.prepare(`SELECT COUNT(*) as count FROM ${(table as any).name}`).first()
        const recordCount = (count as any)?.count || 0
        tableStats[(table as any).name] = { recordCount }
        totalRecords += recordCount
      } catch (error) {
        tableStats[(table as any).name] = { recordCount: 0, error: `无法获取记录数: ${error}` }
      }
    }

    return c.json({
      success: true,
      data: {
        sqliteVersion: sqliteVersion?.version || 'Unknown',
        totalRecords,
        timestamp: new Date().toISOString(),
        tables: tableStats
      }
    })
  } catch (error) {
    console.error('获取数据库信息失败:', error)
    if (error instanceof HTTPException) {
      throw error
    }
    throw new HTTPException(500, { message: '获取数据库信息失败: ' + (error as Error).message })
  }
})

// 获取所有表的数据
databaseRoutes.get('/tables', async (c) => {
  try {
    // 调试模式检查已由中间件处理

    // 获取数据库中的所有表（排除系统表）
    const tables = await c.env.DB.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
      ORDER BY name
    `).all()

    const tablesData = []

    for (const table of tables.results) {
      const tableName = (table as any).name
      try {
        // 获取表结构（列信息）
        const tableInfo = await c.env.DB.prepare(`PRAGMA table_info(${tableName})`).all()
        const columns = tableInfo.results.map((col: any) => col.name)

        // 获取总记录数
        const totalCount = await c.env.DB.prepare(`SELECT COUNT(*) as count FROM ${tableName}`).first()
        const total = (totalCount as any)?.count || 0

        // 获取最新10条记录
        const orderColumn = await getOrderColumn(c.env.DB, tableName)
        const records = await c.env.DB.prepare(`
          SELECT * FROM ${tableName} 
          ORDER BY ${orderColumn} DESC 
          LIMIT 10
        `).all()

        tablesData.push({
          table: tableName,
          total,
          columns,
          records: records.results || []
        })
      } catch (error) {
        // 如果表不存在或查询失败，添加错误信息
        tablesData.push({
          table: tableName,
          total: 0,
          columns: [],
          records: [],
          error: `查询失败: ${(error as Error).message}`
        })
      }
    }

    return c.json({
      success: true,
      data: tablesData
    })
  } catch (error) {
    console.error('获取表数据失败:', error)
    if (error instanceof HTTPException) {
      throw error
    }
    throw new HTTPException(500, { message: '获取表数据失败: ' + (error as Error).message })
  }
})

// 获取数据库统计信息
databaseRoutes.get('/stats', async (c) => {
  try {
    // 调试模式检查已由中间件处理

    // 获取数据库统计信息
    const stats = await getDatabaseStats(c.env.DB)

    return c.json({
      success: true,
      data: stats
    })
  } catch (error) {
    console.error('获取数据库统计失败:', error)
    if (error instanceof HTTPException) {
      throw error
    }
    throw new HTTPException(500, { message: '获取数据库统计失败: ' + (error as Error).message })
  }
})

// 初始化数据库
databaseRoutes.post('/init', async (c) => {
  try {
    // 调试模式检查已由中间件处理

    const { confirmText } = await c.req.json()

    // 二次确认
    if (confirmText !== 'CONFIRM_RESET_DATABASE') {
      throw new HTTPException(400, { message: '请输入确认文本: CONFIRM_RESET_DATABASE' })
    }

    // 执行数据库初始化
    const result = await performDatabaseReset(c.env.DB)

    return c.json({
      success: true,
      data: result
    })
  } catch (error) {
    console.error('数据库初始化失败:', error)
    if (error instanceof HTTPException) {
      throw error
    }
    throw new HTTPException(500, { message: '数据库初始化失败: ' + (error as Error).message })
  }
})

// 执行数据库重置的具体逻辑
async function performDatabaseReset(db: D1Database) {
  const steps: string[] = []
  const logResult = function (msg: string) {
    console.log(msg)
    steps.push(msg)
  }

  try {
    steps.push('✅ 开始数据库初始化')

    // 1. 获取所有表名
    const tables = await db.prepare(`
      SELECT name FROM sqlite_master 
        WHERE type="table" 
          AND name NOT LIKE "sqlite_%" 
          AND name NOT LIKE "_cf%"
    `).all()

    // 2. 删除触发器（先删除触发器，避免依赖问题）
    try {
      // 一次性生成所有删除触发器的 SQL 语句
      const dropAllTriggersQuery = `
        SELECT 'DROP TRIGGER IF EXISTS "' || name || '";' as sql
        FROM sqlite_master 
        WHERE type = 'trigger'
      `

      const triggers = await db.prepare(dropAllTriggersQuery).all()
      if (triggers.results && triggers.results.length > 0) {
        // 将所有删除语句合并成一个 SQL
        const allDropSQL = triggers.results.map((trigger: any) => trigger.sql).join(' ')

        try {
          await db.prepare(allDropSQL).run()
          console.log(`✅ 批量删除 ${triggers.results.length} 个触发器成功`)
          logResult('✅ 删除触发器成功')
        } catch (error) {
          console.warn('批量删除触发器失败，回退到逐个删除:', error)
          // 回退到逐个删除
          for (const trigger of triggers.results) {
            try {
              await db.prepare((trigger as any).sql).run()
              console.log(`✅ 删除触发器: ${(trigger as any).sql.replace('DROP TRIGGER IF EXISTS "', '').replace('";', '')} 成功`)
            } catch (error) {
              console.warn(`删除触发器失败: ${(trigger as any).sql} - ${error}`)
            }
          }
          logResult('✅ 删除触发器成功')
        }
      } else {
        console.log('没有找到触发器')
      }
    } catch (error) {
      console.warn('查询触发器时出现错误，忽略:', error)
      steps.push('⚠️ 删除触发器（跳过）')
    }

    // 3. 删除所有表（先禁用外键约束，忽略错误）
    try {
      await db.prepare('PRAGMA foreign_keys = OFF').run()
      console.log('✅ 已禁用外键约束')
    } catch (error) {
      console.warn('禁用外键约束时出现错误，忽略:', error)
    }

    // 动态获取表依赖关系并删除表
    if (tables.results && tables.results.length > 0) {
      const tableNames = tables.results.map((table: any) => table.name)
      console.log(`📋 发现 ${tableNames.length} 个表:`, tableNames.join(', '))

      // 一次性获取所有表的外键依赖关系
      const tableDependencies: { [key: string]: string[] } = {}
      for (const tableName of tableNames) {
        tableDependencies[tableName] = []
      }

      try {
        // 使用 sqlite_master 表一次性查询所有外键信息
        const allFkQuery = `
          SELECT 
            m.name as table_name,
            pti.\`table\` as ref_table
          FROM sqlite_master m
          JOIN pragma_foreign_key_list(m.name) pti
          WHERE m.type = 'table' 
            AND m.name NOT LIKE 'sqlite_%' 
            AND m.name NOT LIKE '_cf%'
        `

        const fkResult = await db.prepare(allFkQuery).all()
        if (fkResult.results) {
          for (const fk of fkResult.results) {
            if (tableDependencies[(fk as any).table_name]) {
              tableDependencies[(fk as any).table_name].push((fk as any).ref_table)
            }
          }
        }
      } catch (error) {
        console.warn('批量获取外键信息失败，回退到逐个查询:', error)
        // 回退到逐个查询
        for (const tableName of tableNames) {
          try {
            const fkResult = await db.prepare(`PRAGMA foreign_key_list(${tableName})`).all()
            if (fkResult.results) {
              tableDependencies[tableName] = fkResult.results.map((fk: any) => fk.table)
            }
          } catch (error) {
            console.warn(`获取表 ${tableName} 外键信息失败:`, error)
          }
        }
      }

      // 构建反向依赖图：找出哪些表依赖于当前表
      const reverseDependencies: { [key: string]: string[] } = {}
      for (const tableName of tableNames) {
        reverseDependencies[tableName] = []
      }

      for (const tableName of tableNames) {
        const dependencies = tableDependencies[tableName] || []
        for (const dep of dependencies) {
          if (tableNames.includes(dep)) {
            reverseDependencies[dep].push(tableName)
          }
        }
      }

      // 拓扑排序：找到删除顺序（先删除依赖表，再删除被依赖的表）
      const deleteOrder: string[] = []
      const visited = new Set<string>()
      const visiting = new Set<string>()

      function visit(tableName: string) {
        if (visiting.has(tableName)) {
          console.warn(`检测到循环依赖: ${tableName}`)
          return
        }
        if (visited.has(tableName)) {
          return
        }

        visiting.add(tableName)

        // 先处理依赖当前表的表（依赖表要先删除）
        const dependents = reverseDependencies[tableName] || []
        for (const dependent of dependents) {
          if (tableNames.includes(dependent)) {
            visit(dependent)
          }
        }

        visiting.delete(tableName)
        visited.add(tableName)
        deleteOrder.push(tableName)
      }

      // 对所有表进行拓扑排序
      for (const tableName of tableNames) {
        if (!visited.has(tableName)) {
          visit(tableName)
        }
      }

      console.log(`📋 删除顺序:`, deleteOrder.join(' -> '))

      // 一次性生成所有删除表的 SQL 语句
      const dropTablesSQL = deleteOrder.map(tableName => `DROP TABLE IF EXISTS ${tableName}`).join('; ')

      try {
        await db.prepare(dropTablesSQL).run()
        console.log(`✅ 批量删除 ${deleteOrder.length} 个表成功`)
      } catch (error) {
        console.warn('批量删除表失败，回退到逐个删除:', error)
        // 回退到逐个删除
        for (const tableName of deleteOrder) {
          try {
            await db.prepare(`DROP TABLE IF EXISTS ${tableName}`).run()
            console.log(`✅ 删除表 ${tableName} 成功`)
          } catch (error) {
            console.warn(`删除表 ${tableName} 时出现错误，忽略:`, error)
          }
        }
      }
    } else {
      console.log('📋 数据库中没有表')
    }

    try {
      await db.prepare('PRAGMA foreign_keys = ON').run()
      console.log('✅ 已启用外键约束')
    } catch (error) {
      console.warn('启用外键约束时出现错误，忽略:', error)
    }
    logResult('✅ 删除现有表结构成功')

    // 4. 清空自增序列（忽略错误）
    try {
      await db.prepare('DELETE FROM sqlite_sequence').run()
      logResult('✅ 清空自增序列成功')
    } catch (error) {
      console.warn('清空自增序列时出现错误，忽略:', error)
      steps.push('⚠️ 清空自增序列（跳过）')
    }

    // 5. 创建新表结构
    for (const [tableName, createSQL] of Object.entries(DATABASE_SCHEMAS)) {
      await db.prepare(createSQL).run()
      console.log(`✅ 创建表: ${tableName} 成功`)
    }
    logResult('✅ 创建新表结构')

    // 6. 创建索引
    for (const indexSql of DATABASE_INDEXES) {
      try {
        await db.prepare(indexSql).run()
      } catch (error) {
        console.warn('创建索引失败:', indexSql, error)
      }
    }
    logResult('✅ 创建索引成功')

    // 7. 创建触发器
    for (const triggerSql of DATABASE_TRIGGERS) {
      try {
        await db.prepare(triggerSql).run()
      } catch (error) {
        console.warn('创建触发器失败:', triggerSql, error)
      }
    }
    logResult('✅ 创建触发器成功')

    // 8. 插入初始数据
    await insertInitialData(db)
    logResult('✅ 插入初始数据成功')

    logResult('✅ 数据库初始化完成')

    return {
      success: true,
      steps
    }
  } catch (error) {
    steps.push(`❌ 初始化失败: ${(error as Error).message}`)
    throw error
  }
}


// 插入初始数据
async function insertInitialData(db: D1Database) {
  // 使用工具函数生成哈希密码（123456）
  const hashedPassword = await hashPassword('123456')

  // 插入系统设置（使用集中管理的SQL）
  await db.prepare(INITIAL_DATA_SQL.systemSettings).run()

  // 插入管理员用户
  const adminResult = await db.prepare(INITIAL_DATA_SQL.adminUser).bind(hashedPassword).run()
  const adminId = adminResult.meta?.last_row_id

  // 插入测试用户
  const testResult = await db.prepare(INITIAL_DATA_SQL.testUser).bind(hashedPassword).run()
  const testId = testResult.meta?.last_row_id

  // 为管理员创建默认邮箱
  if (adminId) {
    await db.prepare(INITIAL_DATA_SQL.adminUserMailbox).bind(adminId).run()
  }

  // 为测试用户创建默认邮箱
  if (testId) {
    await db.prepare(INITIAL_DATA_SQL.testUserMailbox).bind(testId).run()
  }
}


// 获取数据库统计信息
async function getDatabaseStats(db: D1Database) {
  try {
    // 获取总记录数
    let totalRecords = 0
    let activeTableCount = 0

    // 获取所有表
    const tables = await db.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
    `).all()

    activeTableCount = tables.results.length

    // 计算总记录数
    for (const table of tables.results) {
      try {
        const count = await db.prepare(`SELECT COUNT(*) as count FROM ${(table as any).name}`).first()
        totalRecords += (count as any)?.count || 0
      } catch (error) {
        // 忽略不能访问的表
        console.warn(`无法统计表 ${(table as any).name}:`, error)
      }
    }

    // 获取邮件统计
    const emailStats = await getEmailStats(db)

    // 获取用户统计
    const userStats = await getUserStats(db)

    // 获取系统统计
    const systemStats = await getSystemStats(db)

    // 模拟数据库大小（实际上 D1 不提供直接的大小查询）
    const estimatedSize = totalRecords * 1024 // 简单估算

    return {
      totalRecords,
      activeTableCount,
      totalSize: estimatedSize,
      emailStats,
      userStats,
      systemStats
    }
  } catch (error) {
    console.error('获取数据库统计失败:', error)
    throw error
  }
}

// 获取邮件统计
async function getEmailStats(db: D1Database) {
  try {
    // 总邮件数
    const totalResult = await db.prepare('SELECT COUNT(*) as count FROM emails').first()
    const total = totalResult?.count || 0

    // 今日邮件数
    const todayResult = await db.prepare(`
      SELECT COUNT(*) as count FROM emails 
      WHERE DATE(created_at) = DATE('now')
    `).first()
    const today = todayResult?.count || 0

    // 未读邮件数
    const unreadResult = await db.prepare('SELECT COUNT(*) as count FROM emails WHERE is_read = 0').first()
    const unread = unreadResult?.count || 0

    return { total, today, unread }
  } catch (error) {
    console.warn('获取邮件统计失败:', error)
    return { total: 0, today: 0, unread: 0 }
  }
}

// 获取用户统计
async function getUserStats(db: D1Database) {
  try {
    // 总用户数
    const totalResult = await db.prepare('SELECT COUNT(*) as count FROM users WHERE status = 1').first()
    const total = totalResult?.count || 0

    // 管理员数量
    const adminsResult = await db.prepare("SELECT COUNT(*) as count FROM users WHERE user_type = 1 AND status = 1").first()
    const admins = adminsResult?.count || 0

    // 活跃用户（最近7天有活动的用户）
    const activeResult = await db.prepare(`
      SELECT COUNT(DISTINCT owner_id) as count FROM mailboxes 
      WHERE created_at >= DATE('now', '-7 days')
    `).first()
    const active = activeResult?.count || 0

    return { total, admins, active }
  } catch (error) {
    console.warn('获取用户统计失败:', error)
    return { total: 0, admins: 0, active: 0 }
  }
}

// 获取系统统计
async function getSystemStats(db: D1Database) {
  try {
    // 转发规则数量
    const forwardRulesResult = await db.prepare('SELECT COUNT(*) as count FROM forward_rules WHERE enabled = 1').first()
    const forwardRules = forwardRulesResult?.count || 0

    // 活跃邮箱数量
    const mailboxesResult = await db.prepare('SELECT COUNT(*) as count FROM mailboxes WHERE status = 1').first()
    const mailboxes = mailboxesResult?.count || 0

    // 系统设置数量
    const settingsResult = await db.prepare('SELECT COUNT(*) as count FROM system_settings').first()
    const settings = settingsResult?.count || 0

    return {
      forwardRules,
      activeMailboxes: mailboxes,
      settings
    }
  } catch (error) {
    console.warn('获取系统统计失败:', error)
    return { forwardRules: 0, activeMailboxes: 0, settings: 0 }
  }
}

// 智能获取表的排序列
async function getOrderColumn(db: any, tableName: string): Promise<string> {
  try {
    // 获取表结构信息
    const tableInfo = await db.prepare(`PRAGMA table_info(${tableName})`).all()
    const columns = tableInfo.results.map((col: any) => col.name)

    // 优先选择顺序：id -> created_at -> updated_at -> 第一个列
    if (columns.includes('id')) {
      return 'id'
    } else if (columns.includes('created_at')) {
      return 'created_at'
    } else if (columns.includes('updated_at')) {
      return 'updated_at'
    } else if (columns.length > 0) {
      return columns[0] // 使用第一个列
    } else {
      return 'ROWID' // SQLite默认行ID
    }
  } catch (error) {
    console.warn(`获取表 ${tableName} 排序列失败:`, error)
    return 'ROWID'
  }
}

export { databaseRoutes }