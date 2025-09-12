#!/usr/bin/env node

/**
 * 数据库操作脚本
 * 支持参数和命令语句
 * 
 * 用法:
 *   node scripts/db.js init [--remote]
 *   node scripts/db.js migrate
 *   node scripts/db.js import
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { getEnvironmentInfo, isEnvironmentAvailable } from './env-detector.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// 解析命令行参数
function parseArgs() {
  const args = process.argv.slice(2);
  const command = args[0];
  const isRemote = args.includes('--remote');

  return { command, isRemote };
}

// 执行数据库清理
async function executeDbClean(isRemote) {
  const envInfo = getEnvironmentInfo();
  console.log(`🧹 清理数据库 (${envInfo.description}${isRemote ? ', 远程' : ''})...`);

  return new Promise((resolve, reject) => {
    const cleanSQL = `
      -- 查询所有表
      SELECT name FROM sqlite_master WHERE type='table';
    `;

    let cmd, args;

    if (envInfo.isLocal) {
      cmd = 'npx';
      args = ['wrangler', 'd1', 'execute', 'cem-db', '--command', cleanSQL];
      if (isRemote) args.push('--remote');
      args.push('--json');
    } else {
      // Docker 环境（使用 --net=host，路径映射到宿主机）

      cmd = 'docker';
      args = ['exec', 'node', 'bash', '-c'];
      const scriptCmd = `cd worker && npx wrangler d1 execute cem-db --command "${cleanSQL}"${isRemote ? ' --remote' : ''} --json`;
      args.push(scriptCmd);
    }

    const process = spawn(cmd, args, {
      cwd: envInfo.isLocal ? projectRoot : projectRoot,
      stdio: 'pipe',
      shell: true
    });

    let output = '';
    process.stdout.on('data', (data) => {
      output += data.toString();
    });

    process.on('exit', async (code) => {
      if (code === 0) {
        try {
          const data = JSON.parse(output);
          const userTables = data[0].results
            .map(r => r.name)
            .filter(name => !name.startsWith("_cf_") && name !== "sqlite_sequence");

          if (userTables.length === 0) {
            console.log("没有需要删除的用户表。");
          } else {
            console.log("用户表列表:", userTables);

            // 删除所有用户表
            for (const table of userTables) {
              console.log(`删除表: ${table}`);
              await executeSQL(`DROP TABLE IF EXISTS "${table}";`, isRemote);
            }

            // 清空自增序列
            try {
              await executeSQL("DELETE FROM sqlite_sequence;", isRemote);
            } catch (e) {
              console.log("⚠️ 没有 sqlite_sequence 表，跳过。");
            }
          }

          console.log('✅ 数据库清理完成');
          resolve();
        } catch (error) {
          reject(new Error(`数据库清理失败: ${error.message}`));
        }
      } else {
        reject(new Error(`数据库清理失败，代码: ${code}`));
      }
    });
  });
}

// 执行 SQL 命令
async function executeSQL(sql, isRemote) {
  const envInfo = getEnvironmentInfo();

  return new Promise((resolve, reject) => {
    let cmd, args;

    if (envInfo.isLocal) {
      cmd = "npx";
      args = ['wrangler', 'd1', 'execute', 'cem-db', '--command', sql];
      if (isRemote) args.push('--remote');
    } else {
      // Docker 环境（使用 --net=host，路径映射到宿主机）

      cmd = 'docker';
      args = ['exec', 'node', 'bash', '-c'];
      const scriptCmd = `cd worker && npx wrangler d1 execute cem-db --command "${sql}"${isRemote ? ' --remote' : ''}`;
      args.push(scriptCmd);
    }

    const process = spawn(cmd, args, {
      cwd: envInfo.isLocal ? projectRoot : projectRoot,
      stdio: 'inherit',
      shell: true
    });

    process.on('exit', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`SQL 执行失败，代码: ${code}`));
      }
    });
  });
}

// 执行数据库初始化
async function executeDbInit(isRemote) {
  const envInfo = getEnvironmentInfo();
  console.log(`🔧 初始化数据库 (${envInfo.description}${isRemote ? ', 远程' : ''})...`);

  // 先清理数据库
  await executeDbClean(isRemote);

  // 然后执行 schema.sql
  return new Promise((resolve, reject) => {
    let cmd, args;

    if (envInfo.isLocal) {

      cmd = pm;
      args = ['wrangler', 'd1', 'execute', 'cem-db'];
      if (isRemote) args.push('--remote');
      args.push('--file=' + join(projectRoot, 'db', 'schema.sql'));
    } else {
      // Docker 环境（使用 --net=host，路径映射到宿主机）

      cmd = 'docker';
      args = ['exec', 'node', 'bash', '-c'];
      const scriptCmd = `cd worker && npx wrangler d1 execute cem-db --file=db/schema.sql${isRemote ? ' --remote' : ''}`;
      args.push(scriptCmd);
    }

    const process = spawn(cmd, args, {
      cwd: envInfo.isLocal ? projectRoot : projectRoot,
      stdio: 'inherit',
      shell: true
    });

    process.on('exit', (code) => {
      if (code === 0) {
        console.log('✅ 数据库初始化完成');
        resolve();
      } else {
        reject(new Error(`数据库初始化失败，代码: ${code}`));
      }
    });
  });
}

// 执行迁移命令
async function executeMigrate() {
  const envInfo = getEnvironmentInfo();
  console.log(`🔧 执行数据库迁移 (${envInfo.description})...`);

  return new Promise((resolve, reject) => {
    let cmd, args;

    if (envInfo.isLocal) {

      cmd = pm;
      args = ['wrangler', 'd1', 'migrations', 'apply', 'cem-db'];
    } else {
      // Docker 环境（使用 --net=host，路径映射到宿主机）

      cmd = 'docker';
      args = ['exec', 'node', 'bash', '-c', `cd worker && npx wrangler d1 migrations apply cem-db`];
    }

    const process = spawn(cmd, args, {
      cwd: envInfo.isLocal ? join(projectRoot, 'worker') : projectRoot,
      stdio: 'inherit',
      shell: true
    });

    process.on('exit', (code) => {
      if (code === 0) {
        console.log('✅ 数据库迁移完成');
        resolve();
      } else {
        reject(new Error(`数据库迁移失败，代码: ${code}`));
      }
    });
  });
}

// 执行导入命令
async function executeImport() {
  const envInfo = getEnvironmentInfo();
  console.log(`🔧 导入邮件数据 (${envInfo.description})...`);

  return new Promise((resolve, reject) => {
    let cmd, args;

    if (envInfo.isLocal) {
      cmd = 'node';
      args = ['import-emails-to-db-local.js'];
    } else {
      // Docker 环境（使用 --net=host，路径映射到宿主机）
      cmd = 'docker';
      args = ['exec', 'node', 'bash', '-c', 'cd worker && node import-emails-to-db-local.js'];
    }

    const process = spawn(cmd, args, {
      cwd: envInfo.isLocal ? join(projectRoot, 'worker') : projectRoot,
      stdio: 'inherit',
      shell: true
    });

    process.on('exit', (code) => {
      if (code === 0) {
        console.log('✅ 邮件数据导入完成');
        resolve();
      } else {
        reject(new Error(`邮件数据导入失败，代码: ${code}`));
      }
    });
  });
}

// 显示帮助信息
function showHelp() {
  console.log(`
📋 数据库操作脚本

用法:
  node scripts/db.js <command> [options]

命令:
  init     初始化数据库
  migrate  执行数据库迁移
  import   导入邮件数据

选项:
  --remote 使用远程数据库（仅对 init 命令有效）

示例:
  node scripts/db.js init
  node scripts/db.js init --remote
  node scripts/db.js migrate
  node scripts/db.js import
`);
}

// 主函数
async function main() {
  const { command, isRemote } = parseArgs();

  if (!command) {
    showHelp();
    return;
  }

  try {
    // 检查环境是否可用
    if (!isEnvironmentAvailable()) {
      console.error('❌ 环境不可用，请检查 wrangler 安装或 Docker 容器状态');
      process.exit(1);
    }

    const envInfo = getEnvironmentInfo();
    console.log(`🔧 检测到环境: ${envInfo.description}`);

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
      default:
        console.error(`❌ 未知命令: ${command}`);
        showHelp();
        process.exit(1);
    }

    console.log('🎉 操作成功！');
  } catch (error) {
    console.error('❌ 操作失败:', error.message);
    process.exit(1);
  }
}

main();
