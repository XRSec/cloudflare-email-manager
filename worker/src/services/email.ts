/**
 * 邮件服务
 */

import type { D1Database, R2Bucket } from '@cloudflare/workers-types';
import type { Email, Attachment, EmailQueryParams, Env } from '../types';
import { getSystemSetting } from './settings';

/**
 * 创建邮件记录
 */
export async function createEmail(
    db: D1Database,
    emailData: Omit<Email, 'id' | 'created_at' | 'updated_at'>
): Promise<Email> {
    // 生成唯一的邮件ID
    const emailId = `email_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const sql = `
        INSERT INTO emails (
            id, message_id, user_id, subject, from_address, to_address,
            sender_email, recipient_email, reply_to, cc, bcc, content_type, content, raw_content,
            is_read, has_attachments, size_bytes, received_at, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `;

    const bound = [
        emailId,
        emailData.message_id,
        emailData.user_id,
        emailData.subject || null,
        emailData.sender_email, // from_address
        emailData.recipient_email, // to_address
        emailData.sender_email,
        emailData.recipient_email,
        emailData.reply_to || null,
        emailData.cc || null,
        emailData.bcc || null,
        emailData.content_type,
        emailData.content || null,
        emailData.raw_content || null,
        emailData.is_read || 0,
        emailData.has_attachments,
        emailData.raw_content ? new TextEncoder().encode(emailData.raw_content).length : 0,
        emailData.received_at
    ];

    console.log('🐛 [createEmail] SQL:', sql);
    console.log('🐛 [createEmail] BOUND:', bound.map((v, i) => ({ param: i + 1, value: v, type: typeof v })));

    const stmt = db.prepare(sql);
    const result = await stmt.bind(...bound).run();

    if (!result.success) {
        const errorMsg = `Failed to create email; success=${result.success}; meta=${JSON.stringify(result.meta)}; error=${JSON.stringify(result.error || 'undefined')}`;
        console.log('🐛 [createEmail] INSERT_FAILED:', errorMsg);
        throw new Error(errorMsg);
    }

    console.log('🐛 [createEmail] INSERT_OK:', { id: emailId, meta: result.meta });

    const createdEmail = await getEmailById(db, emailId);
    if (!createdEmail) {
        const msg = 'Failed to retrieve created email';
        console.log('🐛 [createEmail] RETRIEVE_FAILED:', msg);
        throw new Error(msg);
    }

    console.log('🐛 [createEmail] RETRIEVE_OK:', { id: createdEmail.id, user_id: createdEmail.user_id });
    return createdEmail;
}

/**
 * 根据ID获取邮件
 */
export async function getEmailById(db: D1Database, id: string): Promise<Email | null> {
    const result = await db.prepare(`
        SELECT id, message_id, user_id, subject, from_address, to_address,
               sender_email, recipient_email, reply_to, cc, bcc, content_type, content, raw_content,
               is_read, has_attachments, size_bytes, received_at, created_at, updated_at
        FROM emails
        WHERE id = ?
    `).bind(id).first();

    if (!result) {
        return null;
    }

    return {
        id: result.id as string,
        message_id: result.message_id as string,
        user_id: result.user_id as number,
        sender_email: result.sender_email as string,
        recipient_email: result.recipient_email as string,
        subject: result.subject as string | undefined,
        content: result.content as string | undefined,
        content_type: result.content_type as 'text' | 'html',
        raw_content: result.raw_content as string | undefined,
        reply_to: result.reply_to as string | undefined,
        cc: result.cc as string | undefined,
        bcc: result.bcc as string | undefined,
        is_read: result.is_read as number,
        has_attachments: result.has_attachments as number,
        received_at: result.received_at as string,
        created_at: result.created_at as string | undefined,
        updated_at: result.updated_at as string | undefined,
    };
}

/**
 * 获取用户邮件列表
 */
export async function getUserEmails(
    db: D1Database,
    userId: number,
    params: EmailQueryParams = {}
): Promise<{ emails: Email[]; total: number }> {
    const {
        page = 1,
        limit = 20,
        search,
        sender,
        subject,
        start_date,
        end_date,
        has_attachments,
        sort = 'received_at',
        order = 'desc'
    } = params;

    const offset = (page - 1) * limit;
    const conditions: string[] = ['user_id = ?'];
    const values: any[] = [userId];

    // 构建查询条件
    if (search) {
        conditions.push('(subject LIKE ? OR content LIKE ? OR sender_email LIKE ?)');
        const searchPattern = `%${search}%`;
        values.push(searchPattern, searchPattern, searchPattern);
    }

    if (sender) {
        conditions.push('sender_email LIKE ?');
        values.push(`%${sender}%`);
    }

    if (subject) {
        conditions.push('subject LIKE ?');
        values.push(`%${subject}%`);
    }

    if (start_date) {
        conditions.push('received_at >= ?');
        values.push(start_date);
    }

    if (end_date) {
        conditions.push('received_at <= ?');
        values.push(end_date);
    }

    if (has_attachments !== undefined) {
        conditions.push('has_attachments = ?');
        values.push(has_attachments ? 1 : 0);
    }

    const whereClause = conditions.join(' AND ');
    const orderClause = `ORDER BY ${sort} ${order.toUpperCase()}`;

    // 获取邮件列表
    const emailsResult = await db.prepare(`
            SELECT id, message_id, user_id, subject, from_address, to_address,
                   sender_email, recipient_email, reply_to, cc, bcc, content_type, content, raw_content,
                   is_read, has_attachments, size_bytes, received_at, created_at, updated_at
            FROM emails
            WHERE ${whereClause}
            ${orderClause}
            LIMIT ? OFFSET ?
        `).bind(...values, limit, offset).all();

    // 获取总数
    const countResult = await db.prepare(`
            SELECT COUNT(*) as total
            FROM emails
            WHERE ${whereClause}
        `).bind(...values).first();

    const emails = emailsResult.results.map(result => ({
        id: result.id as string,
        message_id: result.message_id as string,
        user_id: result.user_id as number,
        sender_email: result.sender_email as string,
        recipient_email: result.recipient_email as string,
        subject: result.subject as string | undefined,
        content: result.content as string | undefined,
        content_type: result.content_type as 'text' | 'html',
        raw_content: undefined, // 列表中不返回原始邮件内容
        reply_to: result.reply_to as string | undefined,
        cc: result.cc as string | undefined,
        bcc: result.bcc as string | undefined,
        is_read: result.is_read as number,
        has_attachments: result.has_attachments as number,
        received_at: result.received_at as string,
        created_at: result.created_at as string | undefined,
        updated_at: result.updated_at as string | undefined,
    }));

    return {
        emails,
        total: countResult?.total as number || 0
    };
}

/**
 * 获取所有邮件（管理员功能）
 */
export async function getAllEmails(
    db: D1Database,
    userId?: number,
    params: EmailQueryParams = {}
): Promise<{ emails: Email[]; total: number }> {
    try {
        console.log('[getAllEmails] 开始执行，参数:', params);

        const {
            page = 1,
            limit = 20,
            search,
            sender,
            subject,
            start_date,
            end_date,
            has_attachments,
            sort = 'received_at',
            order = 'desc'
        } = params;

        const offset = (page - 1) * limit;
        const conditions: string[] = [];
        const values: any[] = [];

        // 如果指定了 userId，只查询该用户的邮件
        if (userId !== undefined) {
            conditions.push('user_id = ?');
            values.push(userId);
        }

        // 构建查询条件
        if (search) {
            conditions.push('(subject LIKE ? OR content LIKE ? OR sender_email LIKE ? OR recipient_email LIKE ?)');
            const searchPattern = `%${search}%`;
            values.push(searchPattern, searchPattern, searchPattern, searchPattern);
        }

        if (sender) {
            conditions.push('sender_email LIKE ?');
            values.push(`%${sender}%`);
        }

        if (subject) {
            conditions.push('subject LIKE ?');
            values.push(`%${subject}%`);
        }

        if (start_date) {
            conditions.push('received_at >= ?');
            values.push(start_date);
        }

        if (end_date) {
            conditions.push('received_at <= ?');
            values.push(end_date);
        }

        if (has_attachments !== undefined) {
            conditions.push('has_attachments = ?');
            values.push(has_attachments ? 1 : 0);
        }

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
        const orderClause = `ORDER BY ${sort} ${order.toUpperCase()}`;

        console.log('[getAllEmails] 查询条件:', { whereClause, orderClause, values, limit, offset });

        // 获取邮件列表
        const emailsResult = await db.prepare(`
            SELECT id, message_id, user_id, subject, from_address, to_address,
                   sender_email, recipient_email, reply_to, cc, bcc, content_type, content, raw_content,
                   is_read, has_attachments, size_bytes, received_at, created_at, updated_at
            FROM emails
            ${whereClause}
            ${orderClause}
            LIMIT ? OFFSET ?
        `).bind(...values, limit, offset).all();

        console.log('[getAllEmails] 邮件查询结果:', emailsResult.results.length, '封邮件');

        // 获取总数
        const countResult = await db.prepare(`
            SELECT COUNT(*) as total
            FROM emails
            ${whereClause}
        `).bind(...values).first();

        console.log('[getAllEmails] 总数查询结果:', countResult?.total);

        const emails = emailsResult.results.map(result => ({
            id: result.id as string,
            message_id: result.message_id as string,
            user_id: result.user_id as number,
            sender_email: result.sender_email as string,
            recipient_email: result.recipient_email as string,
            subject: result.subject as string | undefined,
            content: result.content as string | undefined,
            content_type: result.content_type as 'text' | 'html',
            raw_content: undefined, // 列表中不返回原始邮件内容
            reply_to: result.reply_to as string | undefined,
            cc: result.cc as string | undefined,
            bcc: result.bcc as string | undefined,
            is_read: result.is_read as number,
            has_attachments: result.has_attachments as number,
            received_at: result.received_at as string,
            created_at: result.created_at as string | undefined,
            updated_at: result.updated_at as string | undefined,
        }));

        console.log('[getAllEmails] 返回结果:', { emails: emails.length, total: countResult?.total || 0 });

        return {
            emails,
            total: countResult?.total as number || 0
        };
    } catch (error) {
        console.error('[getAllEmails] 执行失败:', error);
        throw error;
    }
}

/**
 * 删除邮件
 */
export async function deleteEmail(db: D1Database, r2: R2Bucket, emailId: string): Promise<void> {
    // 先获取邮件的附件信息
    const attachments = await getEmailAttachments(db, emailId);

    // 删除 R2 中的附件文件
    for (const attachment of attachments) {
        try {
            await r2.delete(attachment.r2_key);
        } catch (error) {
            console.error(`删除附件文件失败: ${attachment.r2_key}`, error);
        }
    }

    // 删除数据库中的邮件记录（由于外键约束，附件记录会自动删除）
    const result = await db.prepare(`
        DELETE FROM emails WHERE id = ?
    `).bind(emailId).run();

    if (!result.success) {
        throw new Error('Failed to delete email');
    }
}

/**
 * 获取邮件附件列表
 */
export async function getEmailAttachments(db: D1Database, emailId: string): Promise<Attachment[]> {
    const result = await db.prepare(`
        SELECT id, email_id, filename, content_type, size_bytes, r2_key,
               created_at, updated_at
        FROM attachments
        WHERE email_id = ?
        ORDER BY created_at
    `).bind(emailId).all();

    return result.results.map(row => ({
        id: row.id as number,
        email_id: row.email_id as string,
        filename: row.filename as string,
        content_type: row.content_type as string,
        size_bytes: row.size_bytes as number,
        r2_key: row.r2_key as string,
        created_at: row.created_at as string | undefined,
        updated_at: row.updated_at as string | undefined,
    }));
}

/**
 * 创建附件记录
 */
export async function createAttachment(
    db: D1Database,
    attachmentData: Omit<Attachment, 'id' | 'created_at' | 'updated_at'>
): Promise<Attachment> {
    const result = await db.prepare(`
        INSERT INTO attachments (
            email_id, filename, content_type, size_bytes, r2_key,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).bind(
        attachmentData.email_id,
        attachmentData.filename,
        attachmentData.content_type,
        attachmentData.size_bytes,
        attachmentData.r2_key
    ).run();

    if (!result.success) {
        throw new Error('Failed to create attachment');
    }

    const createdAttachment = await db.prepare(`
        SELECT id, email_id, filename, content_type, size_bytes, r2_key,
               created_at, updated_at
        FROM attachments
        WHERE id = ?
    `).bind(result.meta.last_row_id).first();

    if (!createdAttachment) {
        throw new Error('Failed to retrieve created attachment');
    }

    return {
        id: createdAttachment.id as number,
        email_id: createdAttachment.email_id as string,
        filename: createdAttachment.filename as string,
        content_type: createdAttachment.content_type as string,
        size_bytes: createdAttachment.size_bytes as number,
        r2_key: createdAttachment.r2_key as string,
        created_at: createdAttachment.created_at as string | undefined,
        updated_at: createdAttachment.updated_at as string | undefined,
    };
}

/**
 * 根据ID获取附件
 */
export async function getAttachmentById(db: D1Database, id: number): Promise<Attachment | null> {
    const result = await db.prepare(`
        SELECT id, email_id, filename, content_type, size_bytes, r2_key,
               created_at, updated_at
        FROM attachments
        WHERE id = ?
    `).bind(id).first();

    if (!result) {
        return null;
    }

    return {
        id: result.id as number,
        email_id: result.email_id as string,
        filename: result.filename as string,
        content_type: result.content_type as string,
        size_bytes: result.size_bytes as number,
        r2_key: result.r2_key as string,
        created_at: result.created_at as string | undefined,
        updated_at: result.updated_at as string | undefined,
    };
}

/**
 * MIME 邮件解析 - 提取附件
 */
export async function parseEmailAttachments(rawEmail: string, env: Env): Promise<Omit<Attachment, 'id' | 'email_id' | 'created_at' | 'updated_at'>[]> {
    const attachments: Omit<Attachment, 'id' | 'email_id' | 'created_at' | 'updated_at'>[] = [];

    try {
        // 查找boundary
        const boundaryMatch = rawEmail.match(/boundary="?([^"\s;]+)"?/i);
        if (!boundaryMatch) {
            return attachments;
        }

        const boundary = boundaryMatch[1];
        const parts = rawEmail.split(`--${boundary}`);

        for (const part of parts) {
            // 跳过非附件部分
            if (!part.includes('Content-Disposition: attachment') &&
                !part.includes('Content-Disposition: inline')) {
                continue;
            }

            // 提取文件名
            const filenameMatch = part.match(/filename[*]?="?([^";\r\n]+)"?/i);
            if (!filenameMatch) continue;

            const filename = filenameMatch[1];

            // 提取Content-Type
            const contentTypeMatch = part.match(/Content-Type:\s*([^;\r\n]+)/i);
            const contentType = contentTypeMatch ? contentTypeMatch[1].trim() : 'application/octet-stream';

            // 提取编码方式
            const encodingMatch = part.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i);
            const encoding = encodingMatch ? encodingMatch[1].trim().toLowerCase() : '';

            // 提取内容
            const contentStartIndex = part.indexOf('\r\n\r\n');
            if (contentStartIndex === -1) continue;

            let content = part.substring(contentStartIndex + 4);
            content = content.replace(/\r\n$/, ''); // 移除末尾换行

            // 解码内容
            let decodedContent: ArrayBuffer;
            try {
                if (encoding === 'base64') {
                    // Base64解码
                    const binaryString = atob(content.replace(/\s/g, ''));
                    const bytes = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    decodedContent = bytes.buffer;
                } else {
                    // 其他编码方式，暂时按原文处理
                    const encoder = new TextEncoder();
                    decodedContent = encoder.encode(content).buffer;
                }
            } catch (error) {
                console.warn('解码附件内容失败:', filename, error);
                continue;
            }

            // 检查文件大小
            const maxSizeSetting = await getSystemSetting(env.DB, 'max_attachment_size');
            if (!maxSizeSetting) {
                throw new Error('附件大小限制未配置');
            }
            const maxSize = parseInt(maxSizeSetting);
            if (decodedContent.byteLength > maxSize) {
                console.warn(`附件过大，跳过: ${filename} (${decodedContent.byteLength} bytes)`);
                continue;
            }

            // 生成唯一的 R2 key
            const r2Key = `attachments/${Date.now()}-${Math.random().toString(36).substr(2, 9)}-${filename}`;

            // 存储到 R2
            try {
                await env.R2.put(r2Key, decodedContent, {
                    httpMetadata: {
                        contentType: contentType,
                        contentDisposition: `attachment; filename="${filename}"`
                    }
                });

                attachments.push({
                    filename: filename,
                    content_type: contentType,
                    size_bytes: decodedContent.byteLength,
                    r2_key: r2Key
                });
            } catch (error) {
                console.error(`存储附件到R2失败: ${filename}`, error);
                continue;
            }
        }
    } catch (error) {
        console.error('MIME解析失败:', error);
    }

    return attachments;
}

/**
 * 清理旧邮件
 */
export async function cleanupOldEmails(env: Env): Promise<{ deletedEmails: number; deletedAttachments: number }> {
    const cleanupDaysSetting = await getSystemSetting(env.DB, 'cleanup_days');
    if (!cleanupDaysSetting) {
        console.error('清理天数未配置，跳过清理');
        return { deletedEmails: 0, deletedAttachments: 0 };
    }
    const cleanupDays = parseInt(cleanupDaysSetting);
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - cleanupDays);
    const cutoffDateStr = cutoffDate.toISOString();

    // 获取需要清理的邮件及其附件
    const emailsToDelete = await env.DB.prepare(`
        SELECT e.id, a.r2_key
        FROM emails e
        LEFT JOIN attachments a ON e.id = a.email_id
        WHERE e.received_at < ?
    `).bind(cutoffDateStr).all();

    let deletedEmails = 0;
    let deletedAttachments = 0;

    // 删除 R2 中的附件文件
    const r2Keys = new Set<string>();
    for (const row of emailsToDelete.results) {
        if (row.r2_key) {
            r2Keys.add(row.r2_key as string);
        }
    }

    for (const r2Key of r2Keys) {
        try {
            await env.R2.delete(r2Key);
            deletedAttachments++;
        } catch (error) {
            console.error(`删除附件文件失败: ${r2Key}`, error);
        }
    }

    // 删除数据库中的邮件记录
    const deleteResult = await env.DB.prepare(`
        DELETE FROM emails WHERE received_at < ?
    `).bind(cutoffDateStr).run();

    deletedEmails = deleteResult.meta.changes || 0;

    console.log(`清理完成: 删除了 ${deletedEmails} 封邮件和 ${deletedAttachments} 个附件`);

    return { deletedEmails, deletedAttachments };
}

/**
 * 发送邮件
 */
export async function sendEmail(
    env: Env,
    emailData: {
        to: string;
        from: string;
        subject: string;
        content: string;
        content_type: 'text' | 'html' | 'markdown';
    }
): Promise<void> {
    // 这里应该实现实际的邮件发送逻辑
    // 由于 Cloudflare Workers 的限制，可能需要使用第三方邮件服务
    // 或者通过其他 Worker 的 RPC 调用

    console.log('发送邮件:', {
        to: emailData.to,
        from: emailData.from,
        subject: emailData.subject,
        content_type: emailData.content_type
    });

    // 模拟邮件发送成功
    // 在实际实现中，这里应该调用邮件发送服务
    throw new Error('邮件发送功能尚未实现，需要集成邮件发送服务');
}
