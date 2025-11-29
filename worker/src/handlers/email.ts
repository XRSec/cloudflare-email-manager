/**
 * 邮件处理器 - 处理接收到的邮件
 */

import { debugLog, errorLog, infoLog } from '../utils/debug';
import { createEmail, saveRawEmailToR2, extractHeadersFromRawEmail, extractTextFromHtml } from '../services/email';
import { handleEmailForwarding } from '../services/webhook';
import { getSystemSetting } from '../services/settings';
import { retryR2Operation } from '../utils/retry';
import type { Env, Email } from '../types';
import PostalMime from 'postal-mime';

/**
 * 构建去除附件的精简 .eml 文件
 * 保留完整的邮件头和正文内容，只移除附件数据
 *
 * @param rawEmail 原始 .eml 文件内容
 * @param parsedEmail postal-mime 解析结果
 * @returns 精简的 RFC822 格式邮件字符串（去除附件）
 */
function buildStrippedEmlFile(rawEmail: string, parsedEmail: any): string {
    const lines = rawEmail.split(/\r?\n/);
    const headers: string[] = [];
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

    // 优先使用 HTML
    if (parsedEmail.html && parsedEmail.html.trim()) {
        body = parsedEmail.html;
        contentType = 'text/html; charset=utf-8';
    } else if (parsedEmail.text && parsedEmail.text.trim()) {
        body = parsedEmail.text;
        contentType = 'text/plain; charset=utf-8';
    } else {
        // 如果 postal-mime 解析失败，尝试手动提取正文
        const bodyMatch = rawEmail.match(/Content-Type:\s*(text\/(plain|html))[^\r\n]*\r?\n(?:Content-Transfer-Encoding:[^\r\n]*\r?\n)?\r?\n([\s\S]*?)(?=\r?\n--)/);
        if (bodyMatch && bodyMatch[3]) {
            body = bodyMatch[3].trim();
            contentType = bodyMatch[1] + '; charset=utf-8';
        } else {
            body = '[无法提取邮件正文内容]';
            errorLog('[精简邮件] 无法提取邮件正文');
        }
    }

    // 第三步：添加新的 Content-Type 头（单一类型，不再是 multipart）
    headers.push(`Content-Type: ${contentType}`);
    headers.push('Content-Transfer-Encoding: 8bit');

    // 第四步：组装完整的 .eml 文件
    // RFC 822 格式：头部 + 空行 + 正文
    return headers.join('\r\n') + '\r\n\r\n' + body;
}

/**
 * 从 postal-mime 解析结果或 message 对象中提取邮件文本内容
 *
 * @param parsedEmail postal-mime 解析结果或 message 对象
 * @returns 提取的纯文本内容（已截取前1000字符）
 */
async function extractEmailText(parsedEmail: any): Promise<string> {
    let text = '';

    // 优先使用 HTML 并转文本
    if (parsedEmail.html && parsedEmail.html.trim() !== '') {
        try {
            text = await extractTextFromHtml(parsedEmail.html);
        } catch (error) {
            errorLog('[提取文本] HTML 转换失败:', error);
        }
    }

    // 如果 HTML 转换失败或没有 HTML，使用纯文本
    if (!text && parsedEmail.text) {
        text = parsedEmail.text;
    }

    // 如果还是没有内容
    if (!text) {
        return '[无法提取邮件内容预览]';
    }

    // 截取前 100 字符（前端显示优化）
    const PREVIEW_LENGTH = 100;
    if (text.length > PREVIEW_LENGTH) {
        text = text.substring(0, PREVIEW_LENGTH) + '...';
    }

    return text.trim();
}

/**
 * 解析邮件内容（使用 postal-mime 或备用方案）
 *
 * @param rawEmailBytes 原始邮件字节数据
 * @param message Cloudflare message 对象（备用）
 * @returns 解析结果 { subject, messageId, content, images }
 */
async function parseEmailContent(
    rawEmailBytes: Uint8Array | null,
    message: any
): Promise<{
    subject: string;
    messageId: string;
    content: string;
    images: Array<{ contentId?: string | null; filename?: string | null; mimeType?: string; disposition?: string | null; size?: number }>;
}> {
    let subject = '';
    let messageId = '';
    let content = '[无法提取邮件内容预览]';
    let images: Array<any> = [];

    // 尝试使用 postal-mime 解析
    if (rawEmailBytes) {
        try {
            const parser = new PostalMime();
            const parsed = await parser.parse(rawEmailBytes);

            subject = parsed.subject || '';
            messageId = parsed.messageId || '';
            content = await extractEmailText(parsed);

            // 提取图片信息
            if (parsed.attachments?.length > 0) {
                images = parsed.attachments
                    .filter((a: any) => a.mimeType?.startsWith('image/'))
                    .map((a: any) => ({
                        contentId: a.contentId ? a.contentId.replace(/^<|>$/g, '') : null,
                        filename: a.filename,
                        mimeType: a.mimeType,
                        disposition: a.disposition,
                        size: a.content instanceof Uint8Array ? a.content.length : a.content instanceof ArrayBuffer ? a.content.byteLength : undefined
                    }));
            }

            return { subject, messageId, content, images };
        } catch (error) {
            errorLog('[邮件解析] postal-mime 失败，使用备用方案:', error);
        }
    }

    // 备用方案：使用 Cloudflare message API
    try {
        const fallbackParsed = {
            html: message.html ? await message.html() : null,
            text: message.text ? await message.text() : null
        };
        content = await extractEmailText(fallbackParsed);
    } catch (error) {
        errorLog('[邮件解析] 备用方案失败:', error);
    }

    return { subject, messageId, content, images };
}

/**
 * 从 message 对象重新构建原始邮件（RFC 822 格式）
 */
async function reconstructRawEmail(
    message: any,
    messageId: string,
    from: string,
    to: string,
    subject: string
): Promise<string> {
    const headers: string[] = [];

    // 添加基本头部
    headers.push(`From: ${from}`);
    headers.push(`To: ${to}`);
    if (subject) {
        headers.push(`Subject: ${subject}`);
    }
    headers.push(`Message-ID: ${messageId}`);

    // 尝试从 message.headers 获取其他头部
    if (message.headers) {
        if (typeof message.headers.get === 'function') {
            // Headers 对象
            const date = message.headers.get('Date') || new Date().toUTCString();
            const contentType = message.headers.get('Content-Type') || 'text/plain; charset=UTF-8';
            headers.push(`Date: ${date}`);
            headers.push(`MIME-Version: 1.0`);
            headers.push(`Content-Type: ${contentType}`);
        } else if (message.headers instanceof Map) {
            // Map 对象
            for (const [key, value] of message.headers.entries()) {
                if (!['From', 'To', 'Subject', 'Message-ID'].includes(key)) {
                    headers.push(`${key}: ${value}`);
                }
            }
        } else {
            // 普通对象
            for (const [key, value] of Object.entries(message.headers)) {
                if (!['From', 'To', 'Subject', 'Message-ID'].includes(key)) {
                    headers.push(`${key}: ${value}`);
                }
            }
        }
    } else {
        // 如果没有 headers，添加默认值
        headers.push(`Date: ${new Date().toUTCString()}`);
        headers.push(`MIME-Version: 1.0`);
        headers.push(`Content-Type: text/plain; charset=UTF-8`);
    }

    // 获取邮件正文
    let body = '';
    try {
        if (typeof message.html === 'function') {
            const htmlContent = await message.html();
            if (htmlContent) {
                body = htmlContent;
                // 更新 Content-Type
                const contentTypeIndex = headers.findIndex(h => h.startsWith('Content-Type:'));
                if (contentTypeIndex >= 0) {
                    headers[contentTypeIndex] = 'Content-Type: text/html; charset=UTF-8';
                }
            }
        }
        if (!body && typeof message.text === 'function') {
            const textContent = await message.text();
            if (textContent) {
                body = textContent;
            }
        }
    } catch (error) {
        debugLog('[邮件处理] 重新构建邮件正文失败:', error);
    }

    // RFC 822 格式：头部 + 空行 + 正文
    return headers.join('\r\n') + '\r\n\r\n' + body;
}

/**
 * 生成基本的原始邮件格式（当无法获取完整邮件时使用）
 */
function generateBasicRawEmail(
    messageId: string,
    from: string,
    to: string,
    subject: string,
    content: string
): string {
    const now = new Date();
    const dateStr = now.toUTCString();

    const headers = [
        `From: ${from}`,
        `To: ${to}`,
        `Subject: ${subject || ''}`,
        `Date: ${dateStr}`,
        `Message-ID: ${messageId}`,
        `MIME-Version: 1.0`,
        `Content-Type: text/plain; charset=UTF-8`
    ];

    return headers.join('\r\n') + '\r\n\r\n' + content;
}

/**
 * 处理接收到的邮件
 */
export async function handleIncomingEmail(message: any, env: Env, ctx?: any): Promise<void> {
    try {
        // ==================== 变量定义区域 ====================
        // 从 message 对象获取基本信息
        const recipientEmail = message.to || message.rcptTo || '';
        const senderEmail = message.from || message.mailFrom || '';

        // 邮件基本信息
        let messageId = '';
        let subject = '';
        let content = '[无法提取邮件内容预览]';  // 默认值
        let images: Array<{
            contentId?: string | null;
            filename?: string | null;
            mimeType?: string;
            disposition?: string | null;
            size?: number;
        }> = [];

        // 原始邮件数据
        let rawEmailBytes: Uint8Array | null = null;
        let rawEmail: string = '';

        // 邮件ID（使用 UUID）
        const emailId = crypto.randomUUID();

        // ==================== 变量定义区域结束 ====================

        // 验证收件人邮箱格式
        if (!recipientEmail || !recipientEmail.includes('@')) {
            errorLog('[邮件处理] 无效的收件人邮箱格式:', recipientEmail);
            return;
        }

        // 步骤1: 获取原始邮件数据
        if (message.raw) {
            try {
                const rawBuffer = await new Response(message.raw).arrayBuffer();
                rawEmailBytes = new Uint8Array(rawBuffer);
                rawEmail = new TextDecoder('utf-8').decode(rawBuffer);
            } catch (error) {
                errorLog('[邮件处理] 读取原始邮件失败:', error);
            }
        }

        // 如果没有原始邮件，尝试重新构建
        if (!rawEmailBytes) {
            try {
                rawEmail = await reconstructRawEmail(message, messageId, senderEmail, recipientEmail, subject);
                rawEmailBytes = new TextEncoder().encode(rawEmail);
            } catch (error) {
                errorLog('[邮件处理] 重新构建邮件失败:', error);
                rawEmail = generateBasicRawEmail(messageId, senderEmail, recipientEmail, subject, '');
                rawEmailBytes = new TextEncoder().encode(rawEmail);
            }
        }

        // 步骤2: 解析邮件内容（提取 subject, messageId, content, images）
        const parsed = await parseEmailContent(rawEmailBytes, message);
        subject = parsed.subject;
        messageId = parsed.messageId;
        content = parsed.content;
        images = parsed.images;

        debugLog('步骤2 邮件解析完成','主题:' ,subject, '内容:', content.length, '字符', '图片:', images.length, '张');

        // 步骤2.5: 提取并保存所有附件到 R2（统一存储在 attachments/ 目录）
        // 同时生成去除附件的精简 .eml 文件（节省存储空间）
        let strippedRawEmail: string | null = null; // 去除附件的精简 .eml
        let attachmentCount = 0; // 附件计数
        const attachmentRecords: Array<{
            id: string;
            filename: string;
            contentType: string;
            sizeBytes: number;
            r2Key: string;
            contentId: string | null;
        }> = [];

        if (env.R2 && rawEmailBytes) {
            try {
                const parser = new PostalMime();
                const parsedEmail = await parser.parse(rawEmailBytes);

                // 提取并保存所有附件（内嵌图片 + 普通附件）统一存储在 attachments/ 目录
                if (parsedEmail.attachments && parsedEmail.attachments.length > 0) {
                    for (const att of parsedEmail.attachments) {
                        if (!att.content) continue;

                        const contentSize = att.content instanceof Uint8Array ? att.content.length :
                            att.content instanceof ArrayBuffer ? att.content.byteLength :
                                att.content.length;

                        // 确定文件名、Content-ID 和 R2 存储路径
                        let filename: string;          // 数据库中保存的文件名（原始文件名）
                        let r2Filename: string;        // R2 中实际存储的文件名
                        let contentId: string | null = null;

                        // 提取 Content-ID（如果有）
                        if (att.contentId) {
                            contentId = att.contentId.replace(/^<|>$/g, '');
                        }

                        // 确定数据库中的文件名和 R2 存储文件名
                        if (contentId) {
                            // 内嵌图片：R2 使用 Content-ID，数据库保留原文件名
                            const ext = att.mimeType?.split('/')[1] || 'bin';
                            r2Filename = `${contentId}.${ext}`;
                            filename = att.filename || r2Filename;  // 优先原文件名，否则用 Content-ID
                        } else if (att.filename) {
                            // 普通附件：R2 和数据库都使用原文件名
                            filename = att.filename;
                            r2Filename = att.filename;
                        } else {
                            // 未命名附件：使用 UUID
                            const uuid = crypto.randomUUID();
                            const ext = att.mimeType?.split('/')[1] || 'bin';
                            filename = `${uuid}.${ext}`;
                            r2Filename = filename;
                        }

                        // R2 存储路径
                        const r2Key = `attachments/${emailId}/${r2Filename}`;

                        // 保存附件到 R2（带重试机制）
                        await retryR2Operation(`保存附件 ${filename}`, async () => {
                            return await env.R2.put(r2Key, att.content, {
                                httpMetadata: {
                                    contentType: att.mimeType || 'application/octet-stream',
                                    contentDisposition: contentId
                                        ? 'inline'
                                        : `attachment; filename="${encodeURIComponent(filename)}"`,
                                    cacheControl: 'public, max-age=31536000'
                                },
                                customMetadata: {
                                    emailId: emailId,
                                    filename: filename,
                                    contentId: contentId || '',
                                    savedAt: new Date().toISOString()
                                }
                            });
                        });

                        // 记录附件信息（保存到数据库）
                        attachmentRecords.push({
                            id: crypto.randomUUID(),
                            filename: filename,
                            contentType: att.mimeType || 'application/octet-stream',
                            sizeBytes: contentSize,
                            r2Key: r2Key,
                            contentId: contentId  // ✅ Content-ID 保存到数据库
                        });

                        attachmentCount++;

                        const typeLabel = contentId ? '内嵌图片' : '普通附件';
                        debugLog(`步骤2.5 保存${typeLabel}`, r2Filename, `(${(contentSize / 1024).toFixed(2)} KB)`);
                    }
                }

                // 生成去除附件的精简 .eml 文件（保留完整邮件头和正文，只移除附件）
                const decoder = new TextDecoder('utf-8');
                const originalRawEmail = decoder.decode(rawEmailBytes);
                strippedRawEmail = buildStrippedEmlFile(originalRawEmail, parsedEmail);
                debugLog('[步骤2.5] 附件处理完成');
            } catch (error) {
                errorLog('[步骤2.5] 附件处理失败:', error);
                // 不影响邮件保存，继续处理
            }
        }

        // 步骤3: 提取邮件头信息
        const headersObj = rawEmail ? extractHeadersFromRawEmail(rawEmail) : {};
        const extractedDate = headersObj['date'] || new Date().toUTCString();
        const extractedReplyTo = headersObj['reply-to'] || null;
        const extractedCc = headersObj['cc'] || null;
        const extractedBcc = headersObj['bcc'] || null;
        const extractedContentType = headersObj['content-type'] || null;

        // 步骤4: 创建邮件记录
        const emailRecord: Omit<Email, 'id' | 'created_at' | 'updated_at'> = {
            subject: subject || null,
            from_address: senderEmail || null,
            to_address: recipientEmail || null,
            content: content, // 已经截取过的内容（100字符）
            is_read: 0,
            attachment_count: attachmentCount, // 使用实际附件数量
            message_id: messageId || null,
            headers_json: JSON.stringify(headersObj),
            size_bytes: rawEmailBytes ? rawEmailBytes.byteLength : null,
            date: extractedDate,
            reply_to: extractedReplyTo,
            cc: extractedCc,
            bcc: extractedBcc,
            content_type: extractedContentType,
            received_at: new Date().toISOString()
        };

        // 步骤5: 保存邮件记录到数据库
        const savedEmail = await createEmail(env.DB, emailRecord, emailId);
        debugLog('步骤5 邮件记录已保存', '主题:', subject);

        // 步骤5.5: 保存附件记录到数据库
        if (attachmentRecords.length > 0) {
            try {
                const insertStmt = env.DB.prepare(`
                    INSERT INTO attachments (id, email_id, filename, content_type, size_bytes, r2_key, content_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `);

                // 批量插入附件记录
                const batch = attachmentRecords.map(att =>
                    insertStmt.bind(
                        att.id,
                        savedEmail.id,
                        att.filename,
                        att.contentType,
                        att.sizeBytes,
                        att.r2Key,
                        att.contentId
                    )
                );

                await env.DB.batch(batch);
                debugLog('步骤5.5 附件记录已保存 - 数量:', attachmentRecords.length);
            } catch (error) {
                errorLog('[步骤5.5] 保存附件记录失败:', error);
            }
        }

        // 步骤6: 保存精简版邮件到 R2（优先使用去除附件的版本，节省存储）
        if (env.R2) {
            try {
                const r2Key = `email:${savedEmail.id}.eml`;

                // 优先使用精简版 .eml（已移除附件，节省存储空间）
                if (strippedRawEmail) {
                    const strippedBytes = new TextEncoder().encode(strippedRawEmail);
                    await retryR2Operation('保存精简版邮件', async () => {
                        return await env.R2.put(r2Key, strippedBytes, {
                            httpMetadata: {
                                contentType: 'message/rfc822',
                                contentDisposition: `attachment; filename="email_${savedEmail.id}.eml"`
                            },
                            customMetadata: {
                                emailId: savedEmail.id,
                                messageId: messageId || '',
                                savedAt: new Date().toISOString(),
                                format: 'RFC822-stripped',
                                note: 'Attachments removed to save storage'
                            }
                        });
                    });
                    debugLog('步骤6 精简版邮件已保存', r2Key, `(${(strippedBytes.length / 1024).toFixed(2)} KB)`);
                }
                // 如果没有精简版，使用原始邮件
                else if (rawEmailBytes) {
                    await retryR2Operation('保存原始邮件', async () => {
                        return await env.R2.put(r2Key, rawEmailBytes, {
                            httpMetadata: {
                                contentType: 'message/rfc822',
                                contentDisposition: `attachment; filename="email_${savedEmail.id}.eml"`
                            },
                            customMetadata: {
                                emailId: savedEmail.id,
                                messageId: messageId || '',
                                savedAt: new Date().toISOString(),
                                format: 'RFC822'
                            }
                        });
                    });
                    debugLog('步骤6 原始邮件已保存到 R2 - Key:', r2Key, `(${(rawEmailBytes.length / 1024).toFixed(2)} KB)`);
                }
            } catch (r2Error) {
                errorLog('[步骤6] 保存到 R2 失败:', r2Error);
            }
        }

        // 步骤7: 处理邮件转发（单用户模式：不需要用户ID）
        try {
            await handleEmailForwarding(savedEmail, null, env.DB);
            debugLog('[步骤7] 邮件转发处理完成');
        } catch (error) {
            errorLog('[步骤7] 邮件转发失败:', error);
        }

        debugLog('✅ 邮件处理完成','ID:', savedEmail.id);

    } catch (error) {
        errorLog('[邮件处理] 处理邮件时发生错误:', error);
        throw error;
    }
}


/**
 * 邮件路由处理器 - Cloudflare Email Routing 入口点
 */
export default {
    async email(message: any, env: Env, ctx: any) {
        try {
            // 记录基本信息
            if (message) {
                debugLog('[邮件路由] 收到新邮件:', `${message.from} -> ${message.to} ${(message as any).rawSize}}`);
            }

            await handleIncomingEmail(message, env, ctx);
        } catch (error) {
            errorLog('[邮件路由] ========== 处理失败 ==========');
            errorLog('[邮件路由] 错误类型:', error instanceof Error ? error.constructor.name : typeof error);
            errorLog('[邮件路由] 错误消息:', error instanceof Error ? error.message : String(error));
            errorLog('[邮件路由] 错误堆栈:', error instanceof Error ? error.stack : '无堆栈信息');
            errorLog('[邮件路由] 完整错误对象:', JSON.stringify(error, Object.getOwnPropertyNames(error), 2));
            // 不抛出错误，避免影响邮件路由
        }
    }
};
