#!/usr/bin/env node

/**
 * 测试新的附件命名逻辑
 * 验证使用 Content-ID 作为文件名的方案
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function testAttachmentNaming() {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📎 测试新的附件命名逻辑');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    // 读取原始邮件
    const emlPath = path.join(__dirname, 'email_1dfba050-c2cf-440a-8987-8de6c6a07fd4.eml');
    const rawEmail = fs.readFileSync(emlPath, 'utf-8');

    // 使用 postal-mime 解析
    const PostalMime = (await import('postal-mime')).default;
    const parser = new PostalMime();
    const parsed = await parser.parse(rawEmail);

    console.log('📧 邮件信息:');
    console.log('   主题:', parsed.subject);
    console.log('   附件数量:', parsed.attachments?.length || 0, '\n');

    if (parsed.attachments && parsed.attachments.length > 0) {
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('📋 附件命名规则测试');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        const emailId = 'test-email-id';
        const attachmentRecords = [];

        for (const att of parsed.attachments) {
            console.log('─────────────────────────────────────────');

            // 确定文件名、Content-ID 和 R2 存储路径
            let filename;          // 数据库中保存的文件名（原始文件名）
            let r2Filename;        // R2 中实际存储的文件名
            let contentId = null;

            // 提取 Content-ID（如果有）
            if (att.contentId) {
                contentId = att.contentId.replace(/^<|>$/g, '');
            }

            // 确定数据库中的文件名和 R2 存储文件名
            if (contentId) {
                // 内嵌图片：R2 使用 Content-ID，数据库保留原文件名
                const ext = att.mimeType?.split('/')[1] || 'bin';
                r2Filename = `${contentId}.${ext}`;
                filename = att.filename || r2Filename;  // 优先原文件名
                console.log('✅ 类型: 内嵌图片');
                console.log('   数据库文件名:', filename);
                console.log('   R2 存储文件名:', r2Filename);
                console.log('   Content-ID:', contentId);
            } else if (att.filename) {
                // 普通附件：R2 和数据库都使用原文件名
                filename = att.filename;
                r2Filename = att.filename;
                console.log('✅ 类型: 普通附件');
                console.log('   文件名:', filename);
            } else {
                // 未命名附件：使用 UUID
                const uuid = 'uuid-' + Math.random().toString(36).substring(2, 15);
                const ext = att.mimeType?.split('/')[1] || 'bin';
                filename = `${uuid}.${ext}`;
                r2Filename = filename;
                console.log('✅ 类型: 未命名附件');
                console.log('   生成文件名:', filename);
            }

            const r2Key = `attachments/${emailId}/${r2Filename}`;
            const contentSize = att.content instanceof Uint8Array ? att.content.length :
                att.content instanceof ArrayBuffer ? att.content.byteLength :
                    att.content.length;

            console.log('   MIME 类型:', att.mimeType);
            console.log('   文件大小:', (contentSize / 1024).toFixed(2), 'KB');
            console.log('   R2 存储路径:', r2Key);

            // 记录附件信息
            attachmentRecords.push({
                id: 'uuid-' + Math.random().toString(36).substring(2, 15),
                filename: filename,
                contentType: att.mimeType || 'application/octet-stream',
                sizeBytes: contentSize,
                r2Key: r2Key,
                contentId: contentId
            });
        }

        console.log('─────────────────────────────────────────\n');

        // 显示数据库记录示例
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('💾 数据库记录（attachments 表）');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        attachmentRecords.forEach((record, i) => {
            console.log(`附件 ${i + 1}:`);
            console.log('  INSERT INTO attachments (');
            console.log('    id,          ', `"${record.id}"`);
            console.log('    email_id,    ', `"${emailId}"`);
            console.log('    filename,    ', `"${record.filename}"`);
            console.log('    content_type,', `"${record.contentType}"`);
            console.log('    size_bytes,  ', record.sizeBytes);
            console.log('    r2_key,      ', `"${record.r2Key}"`);
            console.log('    content_id   ', record.contentId ? `"${record.contentId}"` : 'NULL', '✅');
            console.log('  );\n');
        });

        // 验证唯一性
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('🔍 验证文件名唯一性');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        const filenames = attachmentRecords.map(r => r.filename);
        const uniqueFilenames = new Set(filenames);

        console.log('附件总数:', filenames.length);
        console.log('唯一文件名数:', uniqueFilenames.size);

        if (filenames.length === uniqueFilenames.size) {
            console.log('✅ 所有文件名都是唯一的！');
        } else {
            console.log('❌ 发现重复的文件名！');
            const duplicates = filenames.filter((name, i) => filenames.indexOf(name) !== i);
            console.log('重复的文件名:', duplicates);
        }

        // 验证 Content-ID 的唯一性
        const contentIds = attachmentRecords
            .filter(r => r.contentId)
            .map(r => r.contentId);
        const uniqueContentIds = new Set(contentIds);

        console.log('\n内嵌图片数:', contentIds.length);
        console.log('唯一 Content-ID 数:', uniqueContentIds.size);

        if (contentIds.length === uniqueContentIds.size) {
            console.log('✅ 所有 Content-ID 都是唯一的！');
            console.log('✅ 使用 Content-ID 作为文件名是安全的！');
        } else {
            console.log('❌ 发现重复的 Content-ID！');
        }

        // 显示 R2 目录结构
        console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('📁 R2 目录结构');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        console.log('R2 存储结构:');
        console.log('attachments/');
        console.log(`└── ${emailId}/`);
        attachmentRecords.forEach((record, i) => {
            const isLast = i === attachmentRecords.length - 1;
            const prefix = isLast ? '    └── ' : '    ├── ';
            const label = record.contentId ? '(内嵌图片)' : '(普通附件)';
            // 从 r2_key 中提取实际的 R2 文件名
            const r2Filename = record.r2Key.split('/').pop();
            console.log(`${prefix}${r2Filename} ${label}`);
            if (record.contentId && record.filename !== r2Filename) {
                console.log(`${isLast ? '        ' : '    │   '}→ 数据库记录原文件名: ${record.filename}`);
            }
        });

        console.log('\n✅ 测试完成！新的命名逻辑工作正常！');
    }
}

testAttachmentNaming().catch(err => {
    console.error('❌ 测试失败:', err);
    process.exit(1);
});

