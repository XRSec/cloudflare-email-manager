/**
 * 工具相关路由（统一管理调试/工具功能）
 * 所有工具相关的 API 统一在 /api/tools/* 下
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware } from '../middleware/auth';
import emailHandler from '../handlers/email';
import PostalMime from 'postal-mime';
import { extractHeadersFromRawEmail, extractTextFromHtml } from '../services/email';
import type { Env, ApiResponse } from '../types';

// 导入子路由
import { d1Routes } from './database';
import { kvRouter } from './kv';

const toolsRoutes = new Hono<{ Bindings: Env }>();

// 所有路由需要认证（不再要求工具模式）
toolsRoutes.use('*', jwtAuthMiddleware);

// 挂载子路由（统一接口路径）
toolsRoutes.route('/d1', d1Routes);
toolsRoutes.route('/kv', kvRouter);

const EMAIL_R2_KEY_PATTERN = /^email:([^/]+)\.eml$/;

function formatMailboxAddress(value: any): string {
  if (!value) return '';
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    return value.map(formatMailboxAddress).filter(Boolean).join(', ');
  }

  const address = value.address || value.email || '';
  const name = value.name || '';
  if (address && name) return `${name} <${address}>`;
  return address || name || '';
}

function normalizeDate(value: unknown, fallback: Date = new Date()): string {
  if (typeof value === 'string' || value instanceof Date) {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) {
      return date.toISOString();
    }
  }
  return fallback.toISOString();
}

async function buildEmailPreview(parsedEmail: any): Promise<string> {
  if (parsedEmail.html && parsedEmail.html.trim()) {
    return (await extractTextFromHtml(parsedEmail.html)).slice(0, 1000);
  }

  if (parsedEmail.text && parsedEmail.text.trim()) {
    return parsedEmail.text.trim().slice(0, 1000);
  }

  return '[无法提取邮件内容预览]';
}

async function restoreAttachmentsFromR2(env: Env, emailId: string): Promise<number> {
  let restored = 0;
  let cursor: string | undefined;

  do {
    const listResult = await env.R2.list({
      prefix: `attachments/${emailId}/`,
      limit: 1000,
      cursor
    } as any);

    for (const obj of listResult.objects || []) {
      const filename = obj.customMetadata?.filename || obj.key.split('/').pop() || obj.key;
      const contentId = obj.customMetadata?.contentId || null;
      const contentType = obj.httpMetadata?.contentType || 'application/octet-stream';

      const result = await env.DB.prepare(`
        INSERT OR IGNORE INTO attachments (
          id, email_id, filename, content_type, size_bytes, r2_key, content_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).bind(
        crypto.randomUUID(),
        emailId,
        filename,
        contentType,
        obj.size || 0,
        obj.key,
        contentId
      ).run();

      if ((result.meta as any)?.changes > 0) {
        restored++;
      }
    }

    cursor = (listResult as any).cursor;
  } while (cursor);

  return restored;
}

/**
 * 从 R2 恢复邮件索引
 * POST /api/tools/r2/restore-emails
 */
toolsRoutes.post('/r2/restore-emails', async (c) => {
  try {
    if (!c.env.R2) {
      throw new HTTPException(500, { message: 'R2 存储不可用' });
    }

    const body = await c.req.json().catch(() => ({}));
    const requestedMaxFiles = parseInt(String(body.maxFiles || '100'));
    const maxFiles = Number.isNaN(requestedMaxFiles)
      ? 100
      : Math.max(1, Math.min(requestedMaxFiles, 1000));
    const restoreAttachments = body.restoreAttachments !== false;
    const errors: string[] = [];
    let scanned = 0;
    let restored = 0;
    let skipped = 0;
    let failed = 0;
    let attachmentsRestored = 0;
    let cursor: string | undefined = typeof body.cursor === 'string' ? body.cursor : undefined;

    while (scanned < maxFiles) {
      const listResult = await c.env.R2.list({
        prefix: 'email:',
        limit: Math.min(1000, maxFiles - scanned),
        cursor
      } as any);

      for (const obj of listResult.objects || []) {
        if (scanned >= maxFiles) break;

        const match = obj.key.match(EMAIL_R2_KEY_PATTERN);
        if (!match) continue;

        scanned++;
        const emailId = match[1];

        try {
          const existing = await c.env.DB.prepare('SELECT id FROM emails WHERE id = ?').bind(emailId).first();
          if (existing) {
            if (restoreAttachments) {
              const restoredAttachments = await restoreAttachmentsFromR2(c.env, emailId);
              if (restoredAttachments > 0) {
                const countResult = await c.env.DB.prepare('SELECT COUNT(*) as count FROM attachments WHERE email_id = ?').bind(emailId).first();
                await c.env.DB.prepare('UPDATE emails SET attachment_count = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
                  .bind((countResult?.count as number) || restoredAttachments, emailId)
                  .run();
                attachmentsRestored += restoredAttachments;
              }
            }
            skipped++;
            continue;
          }

          const object = await c.env.R2.get(obj.key);
          if (!object) {
            failed++;
            errors.push(`${obj.key}: R2 对象不存在`);
            continue;
          }

          const rawEmailBytes = new Uint8Array(await object.arrayBuffer());
          const rawEmail = new TextDecoder('utf-8').decode(rawEmailBytes);
          const headers = extractHeadersFromRawEmail(rawEmail);
          const parser = new PostalMime();
          const parsedEmail = await parser.parse(rawEmailBytes);
          const content = await buildEmailPreview(parsedEmail);
          const receivedAt = normalizeDate(headers.date || (parsedEmail as any).date, obj.uploaded || new Date());
          const parsedAttachmentCount = parsedEmail.attachments?.length || 0;

          await c.env.DB.prepare(`
            INSERT INTO emails (
              id, subject, from_address, to_address, content,
              is_read, attachment_count, message_id, headers_json, size_bytes,
              date, reply_to, cc, bcc, content_type,
              received_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
          `).bind(
            emailId,
            parsedEmail.subject || headers.subject || null,
            formatMailboxAddress(parsedEmail.from) || headers.from || null,
            formatMailboxAddress(parsedEmail.to) || headers.to || null,
            content,
            parsedAttachmentCount,
            parsedEmail.messageId || headers['message-id'] || null,
            JSON.stringify(headers),
            obj.size || rawEmailBytes.byteLength,
            headers.date || null,
            headers['reply-to'] || null,
            headers.cc || null,
            headers.bcc || null,
            headers['content-type'] || null,
            receivedAt
          ).run();

          const attachmentCount = restoreAttachments
            ? await restoreAttachmentsFromR2(c.env, emailId)
            : parsedAttachmentCount;

          if (restoreAttachments) {
            await c.env.DB.prepare('UPDATE emails SET attachment_count = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
              .bind(attachmentCount, emailId)
              .run();
          }

          restored++;
          attachmentsRestored += attachmentCount;
        } catch (error) {
          failed++;
          errors.push(`${obj.key}: ${(error as Error).message}`);
        }
      }

      cursor = (listResult as any).cursor;
      if (!listResult.truncated || !cursor) break;
    }

    return c.json({
      success: true,
      message: `R2 邮件索引恢复完成：新增 ${restored} 封，跳过 ${skipped} 封，失败 ${failed} 封`,
      data: {
        scanned,
        restored,
        skipped,
        failed,
        attachmentsRestored,
        maxFiles,
        hasMore: Boolean(cursor),
        cursor: cursor || null,
        errors
      }
    });
  } catch (error) {
    console.error('从 R2 恢复邮件索引失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '从 R2 恢复邮件索引失败: ' + (error as Error).message });
  }
});

/**
 * 获取 R2 文件列表
 * GET /api/tools/r2
 */
toolsRoutes.get('/r2', async (c) => {
  try {
    // 获取查询参数
    const prefix = c.req.query('prefix') || ''
    const limit = parseInt(c.req.query('limit') || '100')
    const cursor = c.req.query('cursor') || undefined

    // 检查 R2 是否可用
    if (!c.env.R2) {
      throw new HTTPException(500, { message: 'R2 存储不可用' })
    }

    // 列出 R2 文件
    const listOptions: any = {
      limit: Math.min(limit, 1000), // 最大限制 1000
    }

    if (prefix) {
      listOptions.prefix = prefix
    }

    if (cursor) {
      listOptions.cursor = cursor
    }

    const result = await c.env.R2.list(listOptions)

    // 处理所有文件
    const files = []
    for (const obj of result.objects || []) {
      const fileInfo: any = {
        key: obj.key,
        size: obj.size,
        etag: obj.etag,
        uploaded: obj.uploaded ? new Date(obj.uploaded).toISOString() : null,
        httpEtag: obj.httpEtag,
        httpMetadata: obj.httpMetadata ? {
          contentType: obj.httpMetadata.contentType,
          contentLanguage: obj.httpMetadata.contentLanguage,
          contentEncoding: obj.httpMetadata.contentEncoding,
          contentDisposition: obj.httpMetadata.contentDisposition,
          cacheControl: obj.httpMetadata.cacheControl,
          cacheExpiry: obj.httpMetadata.cacheExpiry,
        } : null,
        customMetadata: obj.customMetadata || {},
      }

      files.push(fileInfo)
    }

    return c.json({
      success: true,
      data: {
        files,
        truncated: result.truncated || false,
        cursor: (result as any).cursor || null,
        delimitedPrefixes: result.delimitedPrefixes || [],
      }
    })
  } catch (error) {
    console.error('获取 R2 文件列表失败:', error)
    if (error instanceof HTTPException) {
      throw error
    }
    throw new HTTPException(500, { message: '获取 R2 文件列表失败: ' + (error as Error).message })
  }
})

/**
 * 批量删除 R2 文件
 * DELETE /api/tools/r2
 */
toolsRoutes.delete('/r2', async (c) => {
  try {
    const body = await c.req.json()
    const keys = body.keys || []

    if (!Array.isArray(keys) || keys.length === 0) {
      throw new HTTPException(400, { message: '请提供要删除的文件列表' })
    }

    // 检查 R2 是否可用
    if (!c.env.R2) {
      throw new HTTPException(500, { message: 'R2 存储不可用' })
    }

    let deletedCount = 0
    let deletedDbRecords = 0
    const errors: string[] = []

    // 批量删除文件
    for (const key of keys) {
      try {
        // 删除主文件
        await c.env.R2.delete(key)
        deletedCount++

        // 如果是邮件文件，检查是否有对应的数据库记录，如果有则删除
        if (key.startsWith('email:') && key.endsWith('.eml')) {
          try {
            // 从 key 中提取 emailId: email:{id}.eml -> {id}
            const emailId = key.replace('email:', '').replace('.eml', '')

            // 检查数据库中是否存在该邮件
            const email = await c.env.DB.prepare(`
              SELECT id FROM emails WHERE id = ?
            `).bind(emailId).first()

            if (email) {
              // 如果存在，删除数据库记录和附件
              const attachments = await c.env.DB.prepare(`
                SELECT r2_key FROM attachments WHERE email_id = ?
              `).bind(email.id).all()

              // 删除附件文件
              for (const att of attachments.results) {
                try {
                  await c.env.R2.delete(att.r2_key as string)
                } catch (attError) {
                  console.warn(`删除附件失败: ${att.r2_key}`, attError)
                }
              }

              // 删除数据库记录
              await c.env.DB.prepare(`DELETE FROM emails WHERE id = ?`).bind(email.id).run()
              deletedDbRecords++
            }
          } catch (dbError) {
            console.warn(`删除数据库记录失败: ${key}`, dbError)
            // 不抛出错误，文件已删除
          }
        }
      } catch (error) {
        const errorMsg = `删除文件失败: ${key} - ${(error as Error).message}`
        console.error(errorMsg, error)
        errors.push(errorMsg)
      }
    }

    return c.json({
      success: true,
      message: `成功删除 ${deletedCount} 个文件${deletedDbRecords > 0 ? `，${deletedDbRecords} 条数据库记录` : ''}${errors.length > 0 ? `，${errors.length} 个失败` : ''}`,
      data: {
        deletedCount,
        deletedDbRecords,
        errors: errors.length > 0 ? errors : undefined
      }
    })
  } catch (error) {
    console.error('批量删除 R2 文件失败:', error)
    if (error instanceof HTTPException) {
      throw error
    }
    throw new HTTPException(500, { message: '批量删除 R2 文件失败: ' + (error as Error).message })
  }
})

/**
 * 模拟邮件接收接口
 * POST /api/tools/simulate-email
 */
toolsRoutes.post('/simulate-email', async (c: any) => {
  try {
    // 解析 multipart/form-data
    const formData = await c.req.formData();

    const to = formData.get('to') as string;
    const from = formData.get('from') as string;
    const subject = formData.get('subject') as string;
    const content = formData.get('content') as string;
    const content_type = formData.get('content_type') as string;

    if (!to || !from) {
      return c.json({
        success: false,
        error: '收件人和发件人不能为空'
      }, 400);
    }

    const emailContent = content || '这是一封测试邮件';
    const contentType = (content_type || 'text') as 'text' | 'html';

    // 处理附件
    const attachments: Array<{ filename: string; content: ArrayBuffer; contentType: string }> = [];
    const attachmentFiles = formData.getAll('attachments');

    for (const file of attachmentFiles) {
      if (file instanceof File) {
        const arrayBuffer = await file.arrayBuffer();
        attachments.push({
          filename: file.name,
          content: arrayBuffer,
          contentType: file.type || 'application/octet-stream'
        });
      }
    }

    // 生成符合 RFC 822 标准的原始邮件（包含附件）
    const rawEmail = generateRFC822RawEmail(from, to, subject || '测试邮件', emailContent, contentType, attachments);

    // 构造模拟邮件对象
    const rawEmailBytes = new TextEncoder().encode(rawEmail);
    const contentTypeHeader = attachments.length > 0
      ? rawEmail.match(/Content-Type:\s*(.+)/)?.[1] || 'text/plain; charset=UTF-8'
      : (contentType === 'html' ? 'text/html; charset=UTF-8' : 'text/plain; charset=UTF-8');

    const mockMessage = {
      skipDebugRawEmail: true,
      to,
      from,
      rawSize: rawEmailBytes.length,
      headers: new Map([
        ['Subject', subject || '测试邮件'],
        ['Message-ID', rawEmail.match(/Message-ID:\s*(.+)/)?.[1] || `test-${Date.now()}@tools.local`],
        ['Date', rawEmail.match(/Date:\s*(.+)/)?.[1] || new Date().toUTCString()],
        ['Content-Type', contentTypeHeader],
        ['X-CEM-Simulated', '1']
      ]),
      text: () => Promise.resolve(contentType === 'text' ? emailContent : ''),
      html: () => Promise.resolve(contentType === 'html' ? emailContent : ''),
      raw: new ReadableStream({
        start(controller) {
          controller.enqueue(rawEmailBytes);
          controller.close();
        }
      })
    };

    await emailHandler.email(mockMessage, c.env, {});

    return c.json({
      success: true,
      message: `模拟邮件发送成功${attachments.length > 0 ? `，包含 ${attachments.length} 个附件` : ''}`,
      attachments_count: attachments.length
    });

  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : '模拟邮件发送失败'
    }, 500);
  }
});

// 辅助函数：生成 RFC 822 格式邮件
function generateRFC822RawEmail(
  from: string,
  to: string,
  subject: string,
  content: string,
  contentType: 'text' | 'html' = 'text',
  attachments: Array<{ filename: string; content: ArrayBuffer; contentType: string }> = []
): string {
  const now = new Date();
  const messageId = `<test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@tools.local>`;

  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const dayName = days[now.getUTCDay()];
  const monthName = months[now.getUTCMonth()];
  const day = String(now.getUTCDate()).padStart(2, '0');
  const hours = String(now.getUTCHours()).padStart(2, '0');
  const minutes = String(now.getUTCMinutes()).padStart(2, '0');
  const seconds = String(now.getUTCSeconds()).padStart(2, '0');
  const year = now.getUTCFullYear();
  const dateStr = `${dayName}, ${day} ${monthName} ${year} ${hours}:${minutes}:${seconds} +0000`;

  if (attachments.length === 0) {
    const headers = [
      `From: ${from}`,
      `To: ${to}`,
      `Subject: ${subject || '测试邮件'}`,
      `Date: ${dateStr}`,
      `Message-ID: ${messageId}`,
      `MIME-Version: 1.0`,
      `Content-Type: ${contentType === 'html' ? 'text/html' : 'text/plain'}; charset=UTF-8`,
      `Content-Transfer-Encoding: 8bit`
    ];
    return headers.join('\r\n') + '\r\n\r\n' + content;
  }

  const boundary = `----=_Part_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  const headers = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject || '测试邮件'}`,
    `Date: ${dateStr}`,
    `Message-ID: ${messageId}`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/mixed; boundary="${boundary}"`
  ];

  const parts: string[] = [];
  const preamble = 'This is a multi-part message in MIME format.\r\n';

  const actualContent = content || '(邮件正文为空)';
  let textPart = `--${boundary}\r\n`;
  textPart += `Content-Type: ${contentType === 'html' ? 'text/html' : 'text/plain'}; charset=UTF-8\r\n`;
  textPart += `Content-Transfer-Encoding: 8bit\r\n`;
  textPart += `\r\n`;
  textPart += actualContent + '\r\n';
  parts.push(textPart);

  for (const attachment of attachments) {
    let attPart = `--${boundary}\r\n`;
    attPart += `Content-Type: ${attachment.contentType}\r\n`;
    attPart += `Content-Transfer-Encoding: base64\r\n`;
    attPart += `Content-Disposition: attachment; filename="${attachment.filename}"\r\n`;
    attPart += `\r\n`;

    const bytes = new Uint8Array(attachment.content);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    const base64WithLineBreaks = base64.match(/.{1,76}/g)?.join('\r\n') || base64;
    attPart += base64WithLineBreaks + '\r\n';

    parts.push(attPart);
  }

  const epilogue = `--${boundary}--\r\n`;

  return headers.join('\r\n') + '\r\n\r\n' + preamble + parts.join('') + epilogue;
}

export { toolsRoutes };
