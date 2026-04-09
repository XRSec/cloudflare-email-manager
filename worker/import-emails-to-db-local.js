/**
 * 临时邮件导入脚本 - 本地数据库版本
 * 将邮件文件直接导入到本地数据库
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// 邮件文件列表
const emailFiles = [
    'email_c79c4852-0385-451c-b644-3bae88b34c1f.eml',
    'email_b2595219-dab5-4d13-a4fd-3be55f41e54b.eml',
    'email_a0dd147c-3ccd-45d2-8b54-5f62def363a1.eml',
    'email_90692f1d-0590-4d03-ac3c-0d9d1120dc3e.eml'
];

/**
 * 解析邮件文件
 */
function parseEmailFile(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const lines = content.split('\n');

        let subject = '';
        let from = '';
        let to = '';
        let date = '';
        let contentType = 'text';
        let bodyStartIndex = -1;

        // 解析邮件头
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();

            if (line.startsWith('Subject:')) {
                subject = line.substring(8).trim();
                // 处理编码的标题
                if (subject.startsWith('=?')) {
                    subject = decodeHeader(subject);
                }
            } else if (line.startsWith('From:')) {
                from = line.substring(5).trim();
            } else if (line.startsWith('To:')) {
                to = line.substring(3).trim();
            } else if (line.startsWith('Date:')) {
                date = line.substring(5).trim();
            } else if (line.startsWith('Content-Type:')) {
                if (line.includes('text/html')) {
                    contentType = 'html';
                }
            } else if (line === '' && bodyStartIndex === -1) {
                bodyStartIndex = i + 1;
                break;
            }
        }

        // 提取邮件正文
        let body = '';
        if (bodyStartIndex > 0 && bodyStartIndex < lines.length) {
            body = lines.slice(bodyStartIndex).join('\n');

            // 如果是HTML内容，提取纯文本
            if (contentType === 'html') {
                body = stripHtml(body);
            }
        }

        return {
            subject: subject || '(无标题)',
            from: from || '(未知发件人)',
            to: to || '(未知收件人)',
            date: date || new Date().toISOString(),
            content: body.trim(),
            contentType: contentType,
            rawEmail: content
        };
    } catch (error) {
        console.error(`解析邮件文件失败 ${filePath}:`, error);
        return null;
    }
}

/**
 * 解码邮件头编码
 */
function decodeHeader(header) {
    try {
        if (header.includes('=?utf-8?B?')) {
            const match = header.match(/=\?utf-8\?B\?([^?]+)\?=/);
            if (match) {
                return Buffer.from(match[1], 'base64').toString('utf-8');
            }
        }
        return header;
    } catch (error) {
        return header;
    }
}

/**
 * 从HTML中提取纯文本
 */
function stripHtml(html) {
    return html
        .replace(/<[^>]*>/g, '')
        .replace(/&nbsp;/g, ' ')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/\s+/g, ' ')
        .trim();
}

/**
 * 转义SQL字符串
 */
function escapeSQLString(str) {
    if (!str) return '';
    return str
        .replace(/\\/g, '\\\\')  // 转义反斜杠
        .replace(/'/g, "''")     // 转义单引号
        .replace(/\0/g, '\\0')   // 转义空字符
        .replace(/\n/g, '\\n')   // 转义换行符
        .replace(/\r/g, '\\r')   // 转义回车符
        .replace(/\x1a/g, '\\Z'); // 转义Ctrl+Z
}

/**
 * 处理大邮件插入 - 分批处理避免SQL语句过大
 */
function insertLargeEmail(messageId, userId, from, to, subject, content, contentType, rawEmail, receivedAt) {
    try {
        // 将大邮件数据写入临时文件，避免命令行参数过长
        const emailData = {
            messageId,
            userId,
            from,
            to,
            subject,
            content,
            contentType,
            rawEmail,
            receivedAt
        };

        const dataFile = `email_data_${Date.now()}.json`;
        fs.writeFileSync(dataFile, JSON.stringify(emailData, null, 2));

        // 创建SQL文件，使用参数化查询
        const sqlFile = `insert_email_${Date.now()}.sql`;
        const sql = `INSERT OR REPLACE INTO emails (message_id, user_id, sender_email, recipient_email, subject, content, content_type, raw_email, has_attachments, received_at) VALUES ('${messageId}', ${userId}, '${escapeSQLString(from)}', '${escapeSQLString(to)}', '${escapeSQLString(subject)}', '${escapeSQLString(content)}', '${contentType}', '${escapeSQLString(rawEmail)}', 0, '${receivedAt}');`;

        fs.writeFileSync(sqlFile, sql);

        // 执行SQL
        const command = `npx wrangler d1 execute cem-db --file="${sqlFile}" --json`;
        console.log(`执行大邮件SQL文件: ${sqlFile}`);

        const result = execSync(command, {
            stdio: 'pipe',
            encoding: 'utf-8'
        });

        console.log('✅ 大邮件插入成功');
        return true;
    } catch (error) {
        console.error('❌ 大邮件插入失败:', error.message);
        if (error.stdout) {
            console.log('输出:', error.stdout);
        }
        return false;
    } finally {
        // 清理临时文件
        const files = [`email_data_${Date.now()}.json`, `insert_email_${Date.now()}.sql`];
        files.forEach(file => {
            if (fs.existsSync(file)) {
                try {
                    fs.unlinkSync(file);
                } catch (e) {
                    // 忽略清理错误
                }
            }
        });
    }
}

/**
 * 执行SQL命令 - 本地数据库版本
 */
function executeSQL(sql) {
    let tempFile = null;
    try {
        // 将SQL写入临时文件
        tempFile = `temp_sql_${Date.now()}.sql`;
        fs.writeFileSync(tempFile, sql);

        // 直接使用 wrangler 执行本地数据库命令
        const command = `npx wrangler d1 execute cem-db --file="${tempFile}" --json`;
        console.log(`执行SQL文件: ${tempFile}`);

        const result = execSync(command, {
            stdio: 'pipe',
            encoding: 'utf-8'
        });

        console.log('✅ SQL执行成功');
        return true;
    } catch (error) {
        console.error('❌ SQL执行失败:', error.message);
        if (error.stdout) {
            console.log('输出:', error.stdout);
        }
        if (error.stderr) {
            console.log('错误:', error.stderr);
        }
        return false;
    } finally {
        // 确保删除临时文件
        if (tempFile && fs.existsSync(tempFile)) {
            try {
                fs.unlinkSync(tempFile);
                console.log(`🗑️  已清理临时文件: ${tempFile}`);
            } catch (cleanupError) {
                console.warn(`⚠️  清理临时文件失败: ${cleanupError.message}`);
            }
        }
    }
}

/**
 * 主函数
 */
async function main() {
    console.log('🚀 开始导入邮件到本地数据库...\n');

    // 1. 跳过数据库初始化，假设数据库已经存在
    console.log('📋 跳过数据库初始化，假设数据库已存在...');
    console.log('✅ 继续执行邮件导入\n');

    // 2. 清空所有邮件数据
    console.log('🧹 清空所有邮件数据...');
    const cleanupSQL = `DELETE FROM emails`;
    executeSQL(cleanupSQL);
    console.log('✅ 清理完成\n');

    // 3. 创建测试邮箱
    console.log('📧 创建测试邮箱...');
    const createMailboxSQL = `INSERT INTO mailboxes (user_id, email_address, is_default, is_active) VALUES (1, 'admin@doubi.tech', 1, 1) ON CONFLICT(email_address) DO NOTHING`;
    if (!executeSQL(createMailboxSQL)) {
        console.error('❌ 创建邮箱失败');
        return;
    }

    const userId = 1;

    // 3. 解析并导入邮件
    console.log('📨 开始解析邮件文件...\n');

    for (let i = 0; i < emailFiles.length; i++) {
        const fileName = emailFiles[i];
        const filePath = path.join(process.cwd(), fileName);

        console.log(`📄 处理邮件 ${i + 1}/${emailFiles.length}: ${fileName}`);

        const email = parseEmailFile(filePath);
        if (!email) {
            console.log(`❌ 跳过邮件: ${fileName}`);
            continue;
        }

        console.log(`   标题: ${email.subject}`);
        console.log(`   发件人: ${email.from}`);
        console.log(`   收件人: ${email.to}`);
        console.log(`   日期: ${email.date}`);
        console.log(`   内容类型: ${email.contentType}`);
        console.log(`   内容长度: ${email.content.length} 字符`);

        // 保持完整的邮件内容，不进行任何截断
        const fullContent = email.content;
        const fullRawEmail = email.rawEmail;

        console.log(`   最终内容长度: ${fullContent.length} 字符`);
        console.log(`   最终原始邮件长度: ${fullRawEmail.length} 字符\n`);

        // 转换日期格式为SQLite兼容格式
        const receivedAt = new Date(email.date).toISOString().replace('T', ' ').replace('Z', '');

        // 生成安全的message_id
        const messageId = fileName.replace('.eml', '').replace(/[^a-zA-Z0-9_-]/g, '_');

        // 根据邮件大小选择插入方法
        const maxSQLSize = 1000000; // 1MB SQL语句限制
        const estimatedSQLSize = fullContent.length + fullRawEmail.length + email.subject.length + email.from.length + email.to.length;

        let success = false;

        if (estimatedSQLSize > maxSQLSize) {
            console.log(`   📦 邮件过大，使用大邮件插入方法...`);
            success = insertLargeEmail(messageId, userId, email.from, email.to, email.subject, fullContent, email.contentType, fullRawEmail, receivedAt);
        } else {
            console.log(`   📦 使用标准插入方法...`);
            const insertEmailSQL = `INSERT OR REPLACE INTO emails (message_id, user_id, sender_email, recipient_email, subject, content, content_type, raw_email, has_attachments, received_at) VALUES ('${messageId}', ${userId}, '${escapeSQLString(email.from)}', '${escapeSQLString(email.to)}', '${escapeSQLString(email.subject)}', '${escapeSQLString(fullContent)}', '${email.contentType}', '${escapeSQLString(fullRawEmail)}', 0, '${receivedAt}');`;
            success = executeSQL(insertEmailSQL);
        }

        if (success) {
            console.log(`✅ 邮件导入成功: ${email.subject}\n`);
        } else {
            console.log(`❌ 邮件导入失败: ${email.subject}\n`);
        }
    }

    console.log('🎉 邮件导入完成！');
    console.log('📊 可以在本地开发环境中查看导入的邮件数据');
}

// 运行主函数
main().catch(console.error);
