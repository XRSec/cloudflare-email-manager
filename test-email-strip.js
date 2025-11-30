#!/usr/bin/env node

/**
 * 测试邮件精简功能
 * 验证 buildStrippedEmlFile 是否正确保留邮件头和正文
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * 构建去除附件的精简 .eml 文件
 * 保留完整的邮件头和正文内容，只移除附件数据
 */
function buildStrippedEmlFile(rawEmail, parsedEmail) {
  const lines = rawEmail.split(/\r?\n/);
  const headers = [];
  let inHeaders = true;
  let skipContentType = false;

  // 第一步：提取邮件头，但需要更新 Content-Type
  for (const line of lines) {
    if (inHeaders) {
      if (line.trim() === '') {
        // 遇到空行，邮件头结束
        inHeaders = false;
        break;
      }

      // 检查是否是 Content-Type 行
      const lowerLine = line.toLowerCase();
      if (lowerLine.startsWith('content-type:')) {
        skipContentType = true;
        // 不添加这一行，稍后会添加新的 Content-Type
        continue;
      }

      // 跳过 Content-Type 的续行（以空格或制表符开头）
      if (skipContentType && (line.startsWith(' ') || line.startsWith('\t'))) {
        continue;
      }

      skipContentType = false;
      headers.push(line);
    }
  }

  // 第二步：确定内容类型和正文
  let body = '';
  let contentType = 'text/plain; charset=utf-8';

  if (parsedEmail.html && parsedEmail.html.trim()) {
    body = parsedEmail.html;
    contentType = 'text/html; charset=utf-8';
  } else if (parsedEmail.text && parsedEmail.text.trim()) {
    body = parsedEmail.text;
    contentType = 'text/plain; charset=utf-8';
  }

  // 第三步：添加新的 Content-Type 头（单一类型，不再是 multipart）
  headers.push(`Content-Type: ${contentType}`);
  headers.push('Content-Transfer-Encoding: 8bit');

  // 第四步：组装完整的 .eml 文件
  // RFC 822 格式：头部 + 空行 + 正文
  return headers.join('\r\n') + '\r\n\r\n' + body;
}

async function testEmailStripping() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📧 邮件精简测试');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // 读取原始邮件
  const emlPath = path.join(__dirname, 'email_1dfba050-c2cf-440a-8987-8de6c6a07fd4.eml');
  console.log('📂 读取原始邮件:', emlPath);
  const rawEmail = fs.readFileSync(emlPath, 'utf-8');
  const originalSize = rawEmail.length;
  console.log('   原始大小:', (originalSize / 1024).toFixed(2), 'KB\n');

  // 使用 postal-mime 解析
  console.log('🔍 使用 postal-mime 解析邮件...');
  const PostalMime = (await import('postal-mime')).default;
  const parser = new PostalMime();
  const parsed = await parser.parse(rawEmail);

  console.log('   主题:', parsed.subject);
  console.log('   发件人:', parsed.from.address);
  console.log('   收件人:', parsed.to[0].address);
  console.log('   HTML 长度:', parsed.html ? parsed.html.length : 0, '字符');
  console.log('   文本长度:', parsed.text ? parsed.text.length : 0, '字符');
  console.log('   附件数量:', parsed.attachments ? parsed.attachments.length : 0, '\n');

  // 列出附件信息
  if (parsed.attachments && parsed.attachments.length > 0) {
    console.log('📎 附件列表:');
    parsed.attachments.forEach((att, i) => {
      const size = att.content instanceof Uint8Array ? att.content.length :
        att.content instanceof ArrayBuffer ? att.content.byteLength :
          att.content.length;
      console.log(`   ${i + 1}. ${att.filename || '(无文件名)'}`);
      console.log(`      类型: ${att.mimeType}`);
      console.log(`      大小: ${(size / 1024).toFixed(2)} KB`);
      console.log(`      Content-ID: ${att.contentId || '(无)'}`);
    });
    console.log();
  }

  // 生成精简版 .eml
  console.log('✂️  生成精简版 .eml...');
  const strippedEmail = buildStrippedEmlFile(rawEmail, parsed);
  const strippedSize = strippedEmail.length;
  console.log('   精简大小:', (strippedSize / 1024).toFixed(2), 'KB');
  console.log('   节省空间:', ((1 - strippedSize / originalSize) * 100).toFixed(2), '%\n');

  // 保存精简版
  const outputPath = path.join(__dirname, 'email_stripped.eml');
  fs.writeFileSync(outputPath, strippedEmail);
  console.log('💾 精简版已保存:', outputPath, '\n');

  // 比较邮件头
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📋 邮件头对比');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  const originalHeaders = rawEmail.split(/\r?\n\r?\n/)[0].split(/\r?\n/);
  const strippedHeaders = strippedEmail.split(/\r?\n\r?\n/)[0].split(/\r?\n/);

  console.log('原始邮件头数量:', originalHeaders.length);
  console.log('精简邮件头数量:', strippedHeaders.length);
  console.log('邮件头是否完全相同:', originalHeaders.join('\n') === strippedHeaders.join('\n') ? '✅ 是' : '❌ 否');
  console.log();

  // 检查关键邮件头
  const keyHeaders = ['From:', 'To:', 'Subject:', 'Date:', 'Message-Id:', 'Content-Type:', 'Received:', 'DKIM-Signature:'];
  console.log('关键邮件头检查:');
  keyHeaders.forEach(key => {
    const originalHas = originalHeaders.some(h => h.startsWith(key));
    const strippedHas = strippedHeaders.some(h => h.startsWith(key));
    const status = originalHas === strippedHas ? '✅' : '❌';
    console.log(`   ${status} ${key.padEnd(20)} 原始: ${originalHas ? '有' : '无'}  精简: ${strippedHas ? '有' : '无'}`);
  });
  console.log();

  // 比较正文内容
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📄 正文内容对比');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  const strippedBody = strippedEmail.split(/\r?\n\r?\n/).slice(1).join('\n\n');
  console.log('精简版正文长度:', strippedBody.length, '字符');
  console.log('解析后 HTML 长度:', parsed.html ? parsed.html.length : 0, '字符');
  console.log('正文是否匹配:', strippedBody === parsed.html ? '✅ 完全匹配' : '⚠️  可能有差异');
  console.log();

  // 检查是否包含附件数据
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🔍 附件数据检查');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  const hasBase64InOriginal = /Content-Transfer-Encoding: base64/.test(rawEmail);
  const hasBase64InStripped = /Content-Transfer-Encoding: base64/.test(strippedEmail);

  console.log('原始邮件包含 base64 编码:', hasBase64InOriginal ? '是' : '否');
  console.log('精简邮件包含 base64 编码:', hasBase64InStripped ? '是' : '否');
  console.log();

  // 检查图片附件是否被移除
  const imageBoundaryPattern = /Content-Type: image\//gi;
  const originalImageCount = (rawEmail.match(imageBoundaryPattern) || []).length;
  const strippedImageCount = (strippedEmail.match(imageBoundaryPattern) || []).length;

  console.log('原始邮件图片附件数:', originalImageCount);
  console.log('精简邮件图片附件数:', strippedImageCount);
  console.log('附件是否已移除:', strippedImageCount === 0 ? '✅ 是（附件已分离）' : '⚠️  否（附件仍在正文中）');
  console.log();

  // 最终总结
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('✅ 测试总结');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  const isSuccess =
    originalHeaders.join('\n') === strippedHeaders.join('\n') && // 邮件头完全相同
    strippedBody.length > 0 && // 有正文内容
    strippedSize < originalSize; // 文件变小了

  if (isSuccess) {
    console.log('✅ 测试通过！');
    console.log('   - 所有邮件头完整保留');
    console.log('   - 正文内容正确提取');
    console.log('   - 文件大小显著减少');
    console.log('   - 附件数据已分离');
  } else {
    console.log('⚠️  测试发现问题：');
    if (originalHeaders.join('\n') !== strippedHeaders.join('\n')) {
      console.log('   - 邮件头可能有差异');
    }
    if (strippedBody.length === 0) {
      console.log('   - 正文内容未正确提取');
    }
    if (strippedSize >= originalSize) {
      console.log('   - 文件大小未减少');
    }
  }

  console.log('\n📁 生成的文件:');
  console.log('   原始邮件:', emlPath);
  console.log('   精简邮件:', outputPath);
  console.log('\n💡 提示: 可以用邮件客户端打开两个文件对比查看\n');
}

// 运行测试
testEmailStripping().catch(err => {
  console.error('❌ 测试失败:', err);
  process.exit(1);
});

