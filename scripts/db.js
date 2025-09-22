#!/usr/bin/env node

/**
 * 数据库操作脚本
 * 在 Docker 容器内运行，直接使用 wrangler d1 execute 命令
 * 
 * 用法:
 *   node scripts/db.js init [--remote]
 *   node scripts/db.js migrate
 *   node scripts/db.js import
 *   node scripts/db.js "SELECT * FROM users"
 *   node scripts/db.js U0VMRUNUICogRlJPTSB1c2Vycwo=  # base64 编码的 SQL
 */

import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// 解析命令行参数
function parseArgs() {
  const args = process.argv.slice(2);

  // 如果没有参数，显示帮助
  if (args.length === 0) {
    return { command: 'help' };
  }

  const firstArg = args[0];
  const isRemote = args.includes('--remote');

  // 检查是否是预定义命令
  const predefinedCommands = ['init', 'migrate', 'import', 'help'];
  if (predefinedCommands.includes(firstArg)) {
    return { command: firstArg, isRemote };
  }

  // 检查是否是 base64 编码的 SQL
  if (isBase64(firstArg)) {
    return { command: 'sql', sql: decodeBase64(firstArg), isRemote };
  }

  // 否则当作直接的 SQL 命令
  return { command: 'sql', sql: firstArg, isRemote };
}

// 检查是否是 base64 编码
function isBase64(str) {
  try {
    // 检查字符串是否只包含 base64 字符
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(str)) {
      return false;
    }

    // 尝试解码并重新编码，看是否一致
    const decoded = Buffer.from(str, 'base64').toString('utf-8');
    const reencoded = Buffer.from(decoded, 'utf-8').toString('base64');
    return reencoded === str;
  } catch (err) {
    return false;
  }
}

// 解码 base64
function decodeBase64(str) {
  try {
    return Buffer.from(str, 'base64').toString('utf-8');
  } catch (err) {
    return str;
  }
}

// 执行数据库清理（使用与 database.ts 相同的逻辑）
async function executeDbClean(isRemote) {
  console.log(`🧹 清理数据库${isRemote ? ' (远程)' : ''}...`);

  try {
    // 1. 获取所有表名
    console.log('📋 查询数据库中的表...');
    const tablesResult = await executeSQL('SELECT name FROM sqlite_master WHERE type="table" AND name NOT LIKE "sqlite_%" AND name NOT LIKE "_cf%"', isRemote);

    // 2. 删除触发器（先删除触发器，避免依赖问题）
    console.log('🗑️ 删除触发器...');
    try {
      // 一次性生成所有删除触发器的 SQL 语句
      const dropAllTriggersQuery = `
        SELECT 'DROP TRIGGER IF EXISTS "' || name || '";' as sql
        FROM sqlite_master 
        WHERE type = 'trigger'
      `;

      const triggers = await executeSQL(dropAllTriggersQuery, isRemote);
      if (triggers && triggers.results && triggers.results.length > 0) {
        // 将所有删除语句合并成一个 SQL
        const allDropSQL = triggers.results.map(trigger => trigger.sql).join(' ');

        try {
          await executeSQL(allDropSQL, isRemote);
          console.log(`✅ 批量删除 ${triggers.results.length} 个触发器成功`);
        } catch (error) {
          console.warn('批量删除触发器失败，回退到逐个删除:', error);
          // 回退到逐个删除
          for (const trigger of triggers.results) {
            try {
              await executeSQL(trigger.sql, isRemote);
              console.log(`  删除触发器: ${trigger.sql.replace('DROP TRIGGER IF EXISTS "', '').replace('";', '')} 成功`);
            } catch (error) {
              console.log(`⚠️ 删除触发器失败: ${trigger.sql} - ${error}`);
            }
          }
        }
      } else {
        console.log('  没有找到触发器');
      }
    } catch (error) {
      console.log('⚠️ 查询触发器失败...');
    }

    // 3. 删除所有表（先禁用外键约束，忽略错误）
    try {
      await executeSQL('PRAGMA foreign_keys = OFF', isRemote);
      console.log('✅ 已禁用外键约束');
    } catch (error) {
      console.warn('禁用外键约束时出现错误，忽略:', error);
    }

    // 动态获取表依赖关系并删除表
    if (tablesResult && tablesResult.results && tablesResult.results.length > 0) {
      const tables = tablesResult.results.map(row => row.name);
      console.log(`📋 发现 ${tables.length} 个表:`, tables.join(', '));

      // 一次性获取所有表的外键依赖关系
      const tableDependencies = {};
      for (const tableName of tables) {
        tableDependencies[tableName] = [];
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
        `;

        const fkResult = await executeSQL(allFkQuery, isRemote);
        if (fkResult && fkResult.results) {
          for (const fk of fkResult.results) {
            if (tableDependencies[fk.table_name]) {
              tableDependencies[fk.table_name].push(fk.ref_table);
            }
          }
        }
      } catch (error) {
        console.warn('批量获取外键信息失败，回退到逐个查询:', error);
        // 回退到逐个查询
        for (const tableName of tables) {
          try {
            const fkResult = await executeSQL(`PRAGMA foreign_key_list(${tableName})`, isRemote);
            if (fkResult && fkResult.results) {
              tableDependencies[tableName] = fkResult.results.map(fk => fk.table);
            }
          } catch (error) {
            console.warn(`获取表 ${tableName} 外键信息失败:`, error);
          }
        }
      }

      // 构建反向依赖图：找出哪些表依赖于当前表
      const reverseDependencies = {};
      for (const tableName of tables) {
        reverseDependencies[tableName] = [];
      }

      for (const tableName of tables) {
        const dependencies = tableDependencies[tableName] || [];
        for (const dep of dependencies) {
          if (tables.includes(dep)) {
            reverseDependencies[dep].push(tableName);
          }
        }
      }

      // 拓扑排序：找到删除顺序（先删除依赖表，再删除被依赖的表）
      const deleteOrder = [];
      const visited = new Set();
      const visiting = new Set();

      function visit(tableName) {
        if (visiting.has(tableName)) {
          console.warn(`检测到循环依赖: ${tableName}`);
          return;
        }
        if (visited.has(tableName)) {
          return;
        }

        visiting.add(tableName);

        // 先处理依赖当前表的表（依赖表要先删除）
        const dependents = reverseDependencies[tableName] || [];
        for (const dependent of dependents) {
          if (tables.includes(dependent)) {
            visit(dependent);
          }
        }

        visiting.delete(tableName);
        visited.add(tableName);
        deleteOrder.push(tableName);
      }

      // 对所有表进行拓扑排序
      for (const tableName of tables) {
        if (!visited.has(tableName)) {
          visit(tableName);
        }
      }

      console.log(`📋 删除顺序:`, deleteOrder.join(' -> '));

      // 按依赖顺序批量删除所有表
      const dropTablesSQL = deleteOrder.map(tableName => `DROP TABLE IF EXISTS ${tableName}`).join('; ');

      try {
        await executeSQL(dropTablesSQL, isRemote);
        console.log(`✅ 批量删除 ${deleteOrder.length} 个表成功`);
      } catch (error) {
        console.warn('批量删除表失败，回退到逐个删除:', error);
        // 回退到逐个删除
        for (const tableName of deleteOrder) {
          try {
            await executeSQL(`DROP TABLE IF EXISTS ${tableName}`, isRemote);
            console.log(`✅ 删除表 ${tableName} 成功`);
          } catch (error) {
            console.warn(`删除表 ${tableName} 时出现错误，忽略:`, error);
          }
        }
      }
    } else {
      console.log('📋 数据库中没有表');
    }

    try {
      await executeSQL('PRAGMA foreign_keys = ON', isRemote);
      console.log('✅ 已启用外键约束');
    } catch (error) {
      console.warn('启用外键约束时出现错误，忽略:', error);
    }

    // 4. 清空自增序列（忽略错误）
    try {
      await executeSQL('DELETE FROM sqlite_sequence', isRemote);
      console.log('✅ 清空自增序列成功');
    } catch (error) {
      console.warn('清空自增序列时出现错误，忽略:', error);
    }

    console.log('✅ 数据库清理完成');
  } catch (error) {
    console.error('❌ 数据库清理失败:', error);
    throw error;
  }
}

// 执行数据库初始化
async function executeDbInit(isRemote) {
  console.log(`🔧 初始化数据库${isRemote ? ' (远程)' : ''}...`);

  // 先清理数据库
  await executeDbClean(isRemote);

  // 执行 schema.sql
  try {
    execSync(`npx wrangler d1 execute cem-db --file=db/schema.sql${isRemote ? ' --remote' : ''} --json`, {
      stdio: 'ignore',
      cwd: projectRoot
    });
    console.log('✅ 数据库初始化完成');
  } catch (error) {
    console.error('❌ 数据库初始化失败:', error.message);
    process.exit(1);
  }
}

// 执行迁移命令
async function executeMigrate() {
  console.log('🔧 执行数据库迁移...');

  try {
    execSync('npx wrangler d1 migrations apply cem-db', {
      stdio: 'inherit',
      cwd: join(projectRoot, 'worker')
    });
    console.log('✅ 数据库迁移完成');
  } catch (error) {
    console.error('❌ 数据库迁移失败:', error.message);
    process.exit(1);
  }
}

// 执行导入命令
async function executeImport() {
  console.log('🔧 导入邮件数据...');

  try {
    execSync('node import-emails-to-db-local.js', {
      stdio: 'inherit',
      cwd: join(projectRoot, 'worker')
    });
    console.log('✅ 邮件数据导入完成');
  } catch (error) {
    console.error('❌ 邮件数据导入失败:', error.message);
    process.exit(1);
  }
}

// 执行自定义 SQL 命令
async function executeSQL(sql, isRemote) {
  console.log(`🔧 执行 SQL 命令${isRemote ? ' (远程)' : ''}...`);
  console.log(`SQL: ${sql.replace(/\s+/g, ' ').replace(/\n/g, ' ')}`);

  try {
    // 使用 spawn 而不是 execSync 来避免 shell 引号问题
    const { spawn } = await import('child_process');

    return new Promise((resolve, reject) => {
      const args = ['wrangler', 'd1', 'execute', 'cem-db', '--command', sql, '--json'];
      if (isRemote) args.push('--remote');

      let stdout = '';
      let stderr = '';

      const process = spawn('npx', args, {
        cwd: projectRoot,
        stdio: ['inherit', 'pipe', 'pipe']
      });

      process.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      process.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      process.on('close', (code) => {
        if (code === 0) {
          console.log('✅ SQL 命令执行完成');
          try {
            // 解析 JSON 输出 - wrangler 返回的是数组格式
            const results = JSON.parse(stdout);

            // 处理数组格式的结果
            if (Array.isArray(results) && results.length > 0) {
              const result = results[0]; // 取第一个结果

              // 如果是查询结果，显示数据
              if (result && result.results && result.results.length > 0) {
                console.log('📊 查询结果:');
                console.log(JSON.stringify(result));
              } else if (result && result.success) {
                console.log('✅ 命令执行成功');
              }

              resolve(result);
            } else {
              console.log('✅ 命令执行成功');
              resolve({ success: true });
            }
          } catch (parseError) {
            console.log('⚠️ JSON 解析失败，返回原始输出');
            console.log('原始输出:', stdout);
            resolve({ success: true, raw: stdout });
          }
        } else {
          console.error('❌ SQL 命令执行失败');
          console.error('stderr:', stderr);
          console.error('stdout:', stdout);
          reject(new Error(`Command failed with code ${code}`));
        }
      });

      process.on('error', (error) => {
        console.error('❌ SQL 命令执行失败:', error.message);
        reject(error);
      });
    });
  } catch (error) {
    console.error('❌ SQL 命令执行失败:', error.message);
    throw error;
  }
}

// 显示帮助信息
function showHelp() {
  console.log(`
📋 数据库操作脚本

用法:
  node scripts/db.js <command|sql> [options]

命令:
  init     初始化数据库
  migrate  执行数据库迁移
  import   导入邮件数据
  help     显示帮助信息

SQL 执行:
  node scripts/db.js "SELECT * FROM users"
  node scripts/db.js "SELECT * FROM users" --remote
  node scripts/db.js U0VMRUNUICogRlJPTSB1c2Vycwo=  # base64 编码

选项:
  --remote 使用远程数据库

示例:
  node scripts/db.js init
  node scripts/db.js init --remote
  node scripts/db.js migrate
  node scripts/db.js import
  node scripts/db.js "SELECT * FROM users"
  node scripts/db.js "SELECT * FROM users" --remote
  node scripts/db.js U0VMRUNUICogRlJPTSB1c2Vycwo=  # base64: "SELECT * FROM users"
`);
}

// 主函数
async function main() {
  const { command, isRemote, sql } = parseArgs();

  try {
    switch (command) {
      case 'init':
        await executeDbInit(isRemote);
        break;
      case 'migrate':
        await executeMigrate();
        break;
      case 'import':
        await executeImport();
        break;
      case 'sql':
        if (!sql) {
          console.error('❌ 需要提供 SQL 命令');
          showHelp();
          process.exit(1);
        }
        await executeSQL(sql, isRemote);
        break;
      case 'help':
      default:
        showHelp();
        break;
    }

    if (command !== 'help') {
      console.log('🎉 操作成功！');
    }
  } catch (error) {
    console.error('❌ 操作失败:', error.message);
    process.exit(1);
  }
}

main();