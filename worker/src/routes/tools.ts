/**
 * 工具相关路由（统一管理调试/工具功能）
 * 所有工具相关的 API 统一在 /api/tools/* 下
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware } from '../middleware/auth';
import PostalMime from 'postal-mime';
import { extractHeadersFromRawEmail, extractTextFromHtml } from '../services/email';
import type { Env, ApiResponse } from '../types';

// 导入子路由
import { d1Routes } from './database';

const toolsRoutes = new Hono<{ Bindings: Env }>();

// 所有路由需要认证(不再要求工具模式)
toolsRoutes.use('*', jwtAuthMiddleware);

// 挂载子路由(统一接口路径)
toolsRoutes.route('/d1', d1Routes);

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

    // 批量处理，防止过多导致超时或超过限制
    const chunkSize = 100;
    for (let i = 0; i < keys.length; i += chunkSize) {
      const chunkKeys = keys.slice(i, i + chunkSize);
      
      try {
        // 收集所有需要从 R2 删除的 Key
        const allR2KeysToDel = new Set<string>(chunkKeys);
        
        // 筛选出疑似邮件主文件的 emailId
        const emailIds = chunkKeys
          .filter(k => k.startsWith('email:') && k.endsWith('.eml'))
          .map(k => k.replace('email:', '').replace('.eml', ''));
          
        if (emailIds.length > 0) {
          try {
            const placeholders = emailIds.map(() => '?').join(',');
            
            // 查询关联的附件
            const attachments = await c.env.DB.prepare(`
              SELECT r2_key FROM attachments WHERE email_id IN (${placeholders})
            `).bind(...emailIds).all<{ r2_key: string }>();
            
            for (const att of attachments.results || []) {
              if (att.r2_key) {
                allR2KeysToDel.add(att.r2_key);
              }
            }
            
            // 批量删除附件记录
            await c.env.DB.prepare(`
              DELETE FROM attachments WHERE email_id IN (${placeholders})
            `).bind(...emailIds).run();
            
            // 批量删除邮件记录
            const deleteResult = await c.env.DB.prepare(`
              DELETE FROM emails WHERE id IN (${placeholders})
            `).bind(...emailIds).run();
            
            if (deleteResult.meta && deleteResult.meta.changes) {
              deletedDbRecords += deleteResult.meta.changes;
            }
          } catch (dbError) {
            console.warn(`批量删除数据库记录失败`, dbError);
          }
        }
        
        // 分批删除收集到的所有 R2 对象（防止单次提交超过 500 个）
        const r2KeysArray = Array.from(allR2KeysToDel);
        for (let j = 0; j < r2KeysArray.length; j += 500) {
          const r2Chunk = r2KeysArray.slice(j, j + 500);
          await c.env.R2.delete(r2Chunk);
          // 为了统计主 keys 的数量，这里不全部加，仅算我们要求删的（原始请求包含的）
        }
        
        deletedCount += chunkKeys.length;
      } catch (error) {
        const errorMsg = `批量删除文件失败: 批次 ${i} - ${(error as Error).message}`;
        console.error(errorMsg, error);
        errors.push(errorMsg);
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

export { toolsRoutes };
