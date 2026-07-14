import { Hono } from 'hono'
import { HTTPException } from 'hono/http-exception'
import { jwtAuthMiddleware } from '../middleware/auth'
import type { Env, D1Database } from '../types'
import schemaSql from '../../../db/schema.sql'

// =====================================================
// 数据库 SQL 从 db/schema.sql 导入，避免工具页初始化与脚本初始化维护两份 schema
// =====================================================

// 创建 D1 管理路由实例（挂载在 /api/tools/d1/* 下）
const d1Routes = new Hono<{ Bindings: Env }>()

d1Routes.use('*', jwtAuthMiddleware)

// 获取 D1 数据库信息
d1Routes.get('/info', async (c) => {
  try {
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
d1Routes.get('/tables', async (c) => {
  try {
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
d1Routes.get('/stats', async (c) => {
  try {
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

// 初始化数据库（危险操作）
d1Routes.post('/init', async (c) => {
  try {
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
          logResult('✅ 删除触发器成功')
        } catch (error) {
          console.warn('批量删除触发器失败，回退到逐个删除:', error)
          // 回退到逐个删除
          for (const trigger of triggers.results) {
            try {
              await db.prepare((trigger as any).sql).run()
            } catch (error) {
              console.warn(`删除触发器失败: ${(trigger as any).sql} - ${error}`)
            }
          }
          logResult('✅ 删除触发器成功')
        }
      }
    } catch (error) {
      console.warn('查询触发器时出现错误，忽略:', error)
      steps.push('⚠️ 删除触发器（跳过）')
    }

    // 3. 删除所有表（先禁用外键约束，忽略错误）
    try {
      await db.prepare('PRAGMA foreign_keys = OFF').run()
    } catch (error) {
      console.warn('禁用外键约束时出现错误，忽略:', error)
    }

    // 动态获取表依赖关系并删除表
    if (tables.results && tables.results.length > 0) {
      const tableNames = tables.results.map((table: any) => table.name)

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

      // 一次性生成所有删除表的 SQL 语句
      const dropTablesSQL = deleteOrder.map(tableName => `DROP TABLE IF EXISTS ${tableName}`).join('; ')

      try {
        await db.prepare(dropTablesSQL).run()
      } catch (error) {
        console.warn('批量删除表失败，回退到逐个删除:', error)
        // 回退到逐个删除
        for (const tableName of deleteOrder) {
          try {
            await db.prepare(`DROP TABLE IF EXISTS ${tableName}`).run()
          } catch (error) {
            console.warn(`删除表 ${tableName} 时出现错误，忽略:`, error)
          }
        }
      }
    }

    try {
      await db.prepare('PRAGMA foreign_keys = ON').run()
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

    // 5. 使用 db/schema.sql 重建表结构、索引、触发器和初始数据
    await executeSchemaSql(db)
    logResult('✅ 已执行 db/schema.sql')

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


async function executeSchemaSql(db: D1Database) {
  const statements = splitSqlStatements(schemaSql)

  for (const statement of statements) {
    await db.prepare(statement).run()
  }
}

function splitSqlStatements(sql: string): string[] {
  const statements: string[] = []
  let current = ''
  let quote: "'" | '"' | '`' | null = null
  let inLineComment = false
  let inBlockComment = false

  for (let index = 0; index < sql.length; index++) {
    const char = sql[index]
    const next = sql[index + 1]

    current += char

    if (inLineComment) {
      if (char === '\n') {
        inLineComment = false
      }
      continue
    }

    if (inBlockComment) {
      if (char === '*' && next === '/') {
        current += next
        index++
        inBlockComment = false
      }
      continue
    }

    if (quote) {
      if (char === quote) {
        if (next === quote) {
          current += next
          index++
        } else {
          quote = null
        }
      }
      continue
    }

    if (char === '-' && next === '-') {
      current += next
      index++
      inLineComment = true
      continue
    }

    if (char === '/' && next === '*') {
      current += next
      index++
      inBlockComment = true
      continue
    }

    if (char === '\'' || char === '"' || char === '`') {
      quote = char
      continue
    }

    if (char === ';' && isStatementBoundary(current)) {
      const statement = current.trim()
      if (hasExecutableSql(statement)) {
        statements.push(statement)
      }
      current = ''
    }
  }

  const statement = current.trim()
  if (hasExecutableSql(statement)) {
    statements.push(statement)
  }

  return statements
}

function isStatementBoundary(statement: string) {
  if (!/\bCREATE\s+TRIGGER\b/i.test(statement)) {
    return true
  }

  return /\bEND\s*;\s*$/i.test(statement)
}

function hasExecutableSql(statement: string) {
  return statement
    .replace(/--.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .trim().length > 0
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
    const activeUsersResult = await db.prepare("SELECT COUNT(*) as count FROM users WHERE status = 1").first()
    const activeUsers = activeUsersResult?.count || 0

    return { total, activeUsers, active: 0 }
  } catch (error) {
    console.warn('获取用户统计失败:', error)
    return { total: 0, activeUsers: 0, active: 0 }
  }
}

// 获取系统统计
async function getSystemStats(db: D1Database) {
  try {
    // 系统设置数量
    const settingsResult = await db.prepare('SELECT COUNT(*) as count FROM system_settings').first()
    const settings = settingsResult?.count || 0

    return {
      settings
    }
  } catch (error) {
    console.warn('获取系统统计失败:', error)
    return { settings: 0 }
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

export { d1Routes }
