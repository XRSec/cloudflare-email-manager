#!/usr/bin/env node

/**
 * 邮件处理测试脚本
 * 用法: node test-process-email.js [filename.eml] [to@email.com]
 * 
 * 例如：
 *   node test-process-email.js email_1dfba050-c2cf-440a-8987-8de6c6a07fd4.eml
 *   node test-process-email.js email_1dfba050-c2cf-440a-8987-8de6c6a07fd4.eml k@doubi.tech
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function processEmail() {
  const filename = process.argv[2] || 'email_1dfba050-c2cf-440a-8987-8de6c6a07fd4.eml';
  const toAddress = process.argv[3] || 'k@doubi.tech';
  const workerUrl = process.env.WORKER_URL || 'http://localhost:8787';

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📧 邮件处理测试');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // 读取 .eml 文件
  const emlPath = path.join(__dirname, filename);

  if (!fs.existsSync(emlPath)) {
    console.error('❌ 文件不存在:', emlPath);
    console.log('\n💡 可用的 .eml 文件:');
    const files = fs.readdirSync(__dirname).filter(f => f.endsWith('.eml'));
    files.forEach(f => console.log('   -', f));
    process.exit(1);
  }

  console.log('📂 读取文件:', filename);
  const emlContent = fs.readFileSync(emlPath, 'utf-8');
  console.log('   文件大小:', (emlContent.length / 1024).toFixed(2), 'KB');

  // 从邮件中提取信息
  const fromMatch = emlContent.match(/^From:\s*(.+)$/m);
  const subjectMatch = emlContent.match(/^Subject:\s*(.+)$/m);

  const fromAddress = fromMatch ? fromMatch[1].trim() : 'test@example.com';
  const subject = subjectMatch ? subjectMatch[1].trim() : '(无主题)';

  console.log('   发件人:', fromAddress);
  console.log('   收件人:', toAddress);
  console.log('   主题:', subject);
  console.log();

  // 发送到 Worker
  console.log('🚀 发送到 Worker:', workerUrl + '/api/test/process-email');

  try {
    const response = await fetch(workerUrl + '/api/test/process-email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        emlContent: emlContent,
        from: fromAddress,
        to: toAddress
      })
    });

    const result = await response.json();

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📊 处理结果');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    if (result.success) {
      console.log('✅ 邮件处理成功！');
      console.log('\n详细信息:');
      console.log('   发件人:', result.details?.from);
      console.log('   收件人:', result.details?.to);
      console.log('   大小:', (result.details?.size / 1024).toFixed(2), 'KB');

      console.log('\n💡 提示:');
      console.log('   - 邮件已保存到数据库');
      console.log('   - 附件已保存到 R2');
      console.log('   - 精简版 .eml 已保存到 R2');
      console.log('   - 可以在前端查看邮件详情');

      console.log('\n🔗 查看邮件:');
      console.log('   前端: http://localhost:5173');
      console.log('   或查询数据库: npm run db -- "SELECT * FROM emails ORDER BY created_at DESC LIMIT 1"');
    } else {
      console.log('❌ 邮件处理失败！');
      console.log('\n错误信息:', result.error);
      if (result.stack) {
        console.log('\n堆栈跟踪:');
        console.log(result.stack);
      }
    }

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  } catch (error) {
    console.error('\n❌ 请求失败:', error.message);
    console.log('\n💡 请确保 Worker 正在运行:');
    console.log('   cd worker && npx wrangler dev');
    console.log('\n   或设置 WORKER_URL 环境变量:');
    console.log('   WORKER_URL=http://localhost:8788 node test-process-email.js');
    process.exit(1);
  }
}

// 运行测试
processEmail().catch(err => {
  console.error('❌ 测试失败:', err);
  process.exit(1);
});

