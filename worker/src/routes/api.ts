/**
 * 统一API路由 - 符合 api-doc.yml 规范
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware } from '../middleware/auth';
import { getPaginationParams } from '../config/constants';
import { debugLog, errorLog } from '../utils/debug';
import { handleR2ObjectCache, handleTextContentCache } from '../utils/cache';
import { KVCacheService } from '../services/kvCache';
import { retryR2Operation } from '../utils/retry';

// 导入各个功能模块
import { authRoutes } from './auth';
import { userRoutes } from './user';
import { systemRoutes } from './system';
import { databaseRoutes } from './database';
import testEmailRoutes from './test-email';
import { kvCacheRouter } from './kv-cache';

// 导入服务
import {
  getAllEmails,
  getEmailById,
  deleteEmail,
  batchDeleteEmails,
  updateEmailReadStatus,
  batchUpdateEmailReadStatus,
  getEmailAttachments,
  getAttachmentById,
  sendEmail,
  getRawEmailFromR2,
  replaceCidReferencesInHtml
} from '../services/email';
import PostalMime from 'postal-mime';
import { getSystemConfig } from '../services/settings';

import type { Env, ApiResponse, EmailQueryParams } from '../types';

const api = new Hono<{ Bindings: Env }>();

// ==================== 认证相关 ====================
api.route('/auth', authRoutes);

// ==================== 用户相关 ====================
api.route('/users', userRoutes);

// ==================== 邮件相关 ====================
/**
 * 获取邮件列表
 * GET /api/emails
 * 
 * 单用户模式：系统中只有一个管理员用户，所有邮件都关联到该管理员。
 * 不再支持 scope=all 参数，所有查询都返回管理员的邮件。
 */
api.get('/emails', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');

    // 解析查询参数
    const queryParams: EmailQueryParams = {
      ...getPaginationParams(c.req.query()),
      search: c.req.query('search'),
      status: c.req.query('status')
      // 注意：已移除 scope 参数，单用户模式下不再需要
    };

    // 单用户模式：所有邮件都不绑定用户ID，直接查询所有邮件
    const result = await getAllEmails(c.env.DB, queryParams);

    // 转换字段名以匹配前端期望的格式
    const items = result.emails.map(email => ({
      ...email,
      from: email.from_address || '',
      to: email.to_address || '',
      status: email.is_read ? 'read' : 'unread',
      owner_username: (email as any).owner_username || null,
      // 保留原始字段以便向后兼容
      from_address: email.from_address,
      to_address: email.to_address
    }));

    return c.json<ApiResponse>({
      success: true,
      data: {
        total: result.total,
        items
      }
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[邮件列表] 获取失败:', error);
    throw new HTTPException(500, { message: '获取邮件列表失败' });
  }
});

/**
 * 获取邮件详情（包含完整内容和附件）
 * GET /api/emails/{id}
 */
api.get('/emails/:id', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const emailId = c.req.param('id');

    const email = await getEmailById(c.env.DB, emailId);
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }

    // 自动标记为已读（如果当前是未读状态）
    if (email.is_read === 0) {
      try {
        await updateEmailReadStatus(c.env.DB, emailId, true);
        debugLog('[邮件详情] 自动标记为已读');
        // 更新 email 对象
        email.is_read = 1;
      } catch (error) {
        debugLog('[邮件详情] 自动标记为已读失败:', error);
        // 不影响继续返回邮件详情
      }
    }

    // 获取附件列表
    const attachments = await getEmailAttachments(c.env.DB, emailId);

    // 调试：打印附件信息
    debugLog(`[邮件详情] 邮件ID: ${emailId}`);
    debugLog(`[邮件详情] 从数据库获取到的附件数量: ${attachments.length}`);
    if (attachments.length > 0) {
      attachments.forEach((att, index) => {
        debugLog(`[邮件详情] 附件 ${index + 1}:`, {
          id: att.id,
          filename: att.filename,
          content_type: att.content_type,
          size_bytes: att.size_bytes,
          r2_key: att.r2_key
        });
      });
    } else {
      debugLog(`[邮件详情] 未找到附件，检查数据库中是否存在附件记录`);
    }

    // 从 R2 读取精简版 .eml 并动态解析
    let fullContent = email.content || ''; // 默认使用数据库中的预览内容
    let fullContentType = 'text';

    try {
      // 从 R2 读取精简版 .eml 文件
      const rawEmail = await getRawEmailFromR2(c.env.R2, emailId);

      if (rawEmail) {
        debugLog('[邮件详情] 🐛 从 R2 读取的 .eml 前500字符:', rawEmail.substring(0, 500));

        // 使用 postal-mime 解析邮件
        const encoder = new TextEncoder();
        const rawEmailBytes = encoder.encode(rawEmail);
        const parser = new PostalMime();
        const parsedEmail = await parser.parse(rawEmailBytes);

        debugLog('[邮件详情] 🐛 parsedEmail.text:', parsedEmail.text ? parsedEmail.text.substring(0, 200) : 'null');
        debugLog('[邮件详情] 🐛 parsedEmail.html:', parsedEmail.html ? parsedEmail.html.substring(0, 200) : 'null');

        // 提取内容
        if (parsedEmail.html && parsedEmail.html.trim()) {
          fullContent = parsedEmail.html;
          fullContentType = 'html';
          debugLog('[邮件详情] 解析 HTML 内容，长度:', fullContent.length);

          // 查询该邮件的所有附件（包括内嵌图片）
          const attachments = await c.env.DB.prepare(`
            SELECT id, filename, content_id, r2_key, content_type
            FROM attachments
            WHERE email_id = ?
          `).bind(emailId).all();

          // 替换 HTML 中的 cid: 引用为 worker API 链接
          if (attachments.results && attachments.results.length > 0) {
            for (const att of attachments.results) {
              if (att.content_id) {
                // 内嵌图片：替换 cid: 为 API 链接
                const escapedCid = (att.content_id as string).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const cidPattern = new RegExp(`cid:${escapedCid}`, 'gi');
                const imageUrl = `/api/emails/${emailId}/attachments/${att.id}`;
                fullContent = fullContent.replace(cidPattern, imageUrl);
                debugLog('[邮件详情] 替换 cid:', att.content_id, '→', imageUrl);
              }
            }
          }
        } else if (parsedEmail.text && parsedEmail.text.trim()) {
          fullContent = parsedEmail.text;
          fullContentType = 'text';
          debugLog('[邮件详情] 使用纯文本内容，长度:', fullContent.length);
        } else {
          debugLog('[邮件详情] ⚠️ parsedEmail 没有 text 也没有 html！');
          debugLog('[邮件详情] 🐛 parsedEmail 完整对象:', JSON.stringify(parsedEmail, null, 2).substring(0, 1000));
        }
      } else {
        debugLog('[邮件详情] 未找到 .eml 文件，使用数据库预览');
      }
    } catch (error) {
      debugLog('[邮件详情] 解析 .eml 失败，使用数据库预览:', error);
    }

    // 转换字段名以匹配前端期望的格式
    // 过滤掉没有 ID 的附件
    const validAttachments = attachments.filter(att => {
      const hasId = att.id != null && att.id !== '';
      if (!hasId) {
        debugLog(`[邮件详情] 过滤掉无效附件（ID为空）:`, {
          filename: att.filename
        });
      }
      return hasId;
    });

    debugLog(`[邮件详情] 过滤后的有效附件数量: ${validAttachments.length}`);

    const emailData = {
      ...email,
      from: email.from_address || '',
      to: email.to_address || '',
      status: email.is_read ? 'read' : 'unread',
      attachments: validAttachments.map(att => {
        const attachmentData = {
          ...att,
          // 生成附件访问 URL
          url: `/api/emails/${emailId}/attachments/${att.id}`
        };
        debugLog(`[邮件详情] 返回附件数据:`, {
          id: attachmentData.id,
          filename: attachmentData.filename,
          r2_key: attachmentData.r2_key,
          url: attachmentData.url
        });
        return attachmentData;
      }),
      // 完整内容
      full_content: fullContent,
      full_content_type: fullContentType,
      // 保留原始字段以便向后兼容
      from_address: email.from_address,
      to_address: email.to_address
    };

    debugLog(`[邮件详情] 最终返回的附件数量: ${emailData.attachments.length}`);

    return c.json<ApiResponse>({
      success: true,
      data: emailData
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[邮件详情] 获取失败:', error);
    throw new HTTPException(500, { message: '获取邮件详情失败' });
  }
});

/**
 * 获取邮件的原始内容（Raw Email）
 * GET /api/emails/{id}/raw
 * 
 * @description
 * 支持三层缓存机制：
 * 1. 浏览器缓存（HTTP 缓存头）- ETag、Cache-Control、304 响应
 * 2. KV 缓存（后端缓存）- TTL 7天
 * 3. R2 存储（源数据）- 最终数据源
 * 
 * 返回剔除附件后的完整邮件（RFC 822 格式，包含邮件头和正文）
 */
api.get('/emails/:id/raw', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const emailId = c.req.param('id');

    const email = await getEmailById(c.env.DB, emailId);
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }

    let rawEmail: string | null = null;

    // 如果有 KV，尝试从 KV 缓存读取
    if (c.env.KV) {
      const kvCache = new KVCacheService(c.env.KV);
      const cacheKey = KVCacheService.getEmailRawKey(emailId);
      rawEmail = await kvCache.get<string>(cacheKey);

      if (rawEmail) {
        debugLog(`[原始邮件] 从 KV 缓存读取: ${emailId}`);
      } else {
        debugLog(`[原始邮件] KV 缓存未命中，从 R2 读取: ${emailId}`);
      }
    }

    // 如果 KV 中没有，从 R2 读取（带重试机制）
    if (!rawEmail && c.env.R2) {
      rawEmail = await retryR2Operation(`读取原始邮件 ${emailId}`, async () => {
        return await getRawEmailFromR2(c.env.R2, email.id);
      });

      // 如果从 R2 读取成功，写入 KV 缓存（异步，不阻塞响应）
      if (rawEmail && c.env.KV) {
        c.executionCtx?.waitUntil((async () => {
          try {
            const kvCache = new KVCacheService(c.env.KV);
            const cacheKey = KVCacheService.getEmailRawKey(emailId);
            await kvCache.set(cacheKey, rawEmail, KVCacheService.ATTACHMENT_CONFIG.TTL);
            debugLog(`[原始邮件] 写入 KV 缓存成功: ${emailId}`);
          } catch (err) {
            errorLog(`[原始邮件] 写入 KV 缓存失败: ${emailId}`, err);
          }
        })());
      }
    }

    // 如果 R2 中也没有
    if (!rawEmail) {
      debugLog('[原始邮件] R2 中不存在 .eml 文件，邮件内容可能已丢失');
      throw new HTTPException(404, { message: '原始邮件内容不存在' });
    }

    // 使用 emailId 作为文件名
    const filename = `email_${emailId}.eml`;

    // 使用邮件的 updated_at 作为 lastModified
    const lastModified = email.updated_at ? new Date(email.updated_at) : undefined;

    // 返回带缓存的响应
    return handleTextContentCache(c, rawEmail, {
      contentType: 'message/rfc822',
      contentDisposition: `attachment; filename="${filename}"`,
      identifier: emailId,
      lastModified,
      immutable: true // 邮件内容不会改变
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[原始邮件] 获取失败:', error);
    throw new HTTPException(500, { message: '获取原始邮件失败' });
  }
});

/**
 * 批量更新邮件已读状态
 * PATCH /api/emails/batch/read-status
 */
api.patch('/emails/batch/read-status', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const { emailIds, is_read } = await c.req.json();

    if (!Array.isArray(emailIds) || emailIds.length === 0) {
      throw new HTTPException(400, { message: 'emailIds 必须是非空数组' });
    }

    if (typeof is_read !== 'boolean') {
      throw new HTTPException(400, { message: 'is_read 参数必须是布尔值' });
    }

    // 单管理员模式：所有用户都是管理员，可以批量更新所有邮件

    const updatedCount = await batchUpdateEmailReadStatus(c.env.DB, emailIds, is_read);

    return c.json<ApiResponse>({
      success: true,
      message: `已成功将 ${updatedCount} 封邮件标记为${is_read ? '已读' : '未读'}`
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[批量更新邮件已读状态] 失败:', error);
    throw new HTTPException(500, { message: '批量更新邮件已读状态失败' });
  }
});

/**
 * 更新邮件已读状态
 * PATCH /api/emails/{id}/read-status
 */
api.patch('/emails/:id/read-status', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const emailId = c.req.param('id');
    const { is_read } = await c.req.json();

    if (typeof is_read !== 'boolean') {
      throw new HTTPException(400, { message: 'is_read 参数必须是布尔值' });
    }

    const email = await getEmailById(c.env.DB, emailId);
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }

    await updateEmailReadStatus(c.env.DB, emailId, is_read);

    return c.json<ApiResponse>({
      success: true,
      message: `邮件已标记为${is_read ? '已读' : '未读'}`
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[更新邮件已读状态] 失败:', error);
    throw new HTTPException(500, { message: '更新邮件已读状态失败' });
  }
});

/**
 * 批量删除邮件
 * DELETE /api/emails/batch
 */
api.delete('/emails/batch', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const { emailIds } = await c.req.json();

    if (!Array.isArray(emailIds) || emailIds.length === 0) {
      throw new HTTPException(400, { message: 'emailIds 必须是非空数组' });
    }

    // 单管理员模式：所有用户都是管理员，可以批量删除所有邮件

    const result = await batchDeleteEmails(c.env.DB, c.env.R2, emailIds);

    return c.json<ApiResponse>({
      success: true,
      message: `批量删除成功，已删除 ${result.deletedFiles} 个邮件文件和 ${result.deletedAttachments} 个附件`
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[批量删除邮件] 失败:', error);
    throw new HTTPException(500, { message: '批量删除邮件失败' });
  }
});

/**
 * 删除邮件
 * DELETE /api/emails/{id}
 */
api.delete('/emails/:id', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const emailId = c.req.param('id');

    const email = await getEmailById(c.env.DB, emailId);
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }

    const result = await deleteEmail(c.env.DB, c.env.R2, emailId);

    return c.json<ApiResponse>({
      success: true,
      message: `邮件删除成功，已删除 ${result.deletedFiles} 个邮件文件和 ${result.deletedAttachments} 个附件`
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[删除邮件] 失败:', error);
    throw new HTTPException(500, { message: '删除邮件失败' });
  }
});


/**
 * 下载邮件附件
 * GET /api/emails/{id}/attachments/{attachmentId}
 * 
 * @description
 * 支持三层缓存机制：
 * 1. 浏览器缓存（HTTP 缓存头）- ETag、Cache-Control、304 响应
 * 2. KV 缓存（后端缓存）- 只缓存 < 1MB 的附件，TTL 7天
 * 3. R2 存储（源数据）- 最终数据源
 * 
 * 缓存策略：
 * - 小文件（< 1MB）：浏览器缓存 + KV 缓存 + R2
 * - 大文件（≥ 1MB）：浏览器缓存 + R2
 */
api.get('/emails/:id/attachments/:attachmentId', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const emailId = c.req.param('id');
    const attachmentId = c.req.param('attachmentId');

    const email = await getEmailById(c.env.DB, emailId);
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }

    const attachment = await getAttachmentById(c.env.DB, attachmentId);
    if (!attachment) {
      throw new HTTPException(404, { message: '附件不存在' });
    }

    debugLog(`[下载附件] 附件ID: ${attachmentId}, 文件名: ${attachment.filename}, 大小: ${attachment.size_bytes} bytes`);

    // 检查是否有 If-None-Match 头（条件请求）
    const ifNoneMatch = c.req.header('If-None-Match');
    if (ifNoneMatch) {
      debugLog(`[下载附件] 收到条件请求，If-None-Match: ${ifNoneMatch}`);
    }

    // 判断 Content-Disposition
    let contentDisposition = `attachment; filename="${encodeURIComponent(attachment.filename)}"`;
    if (attachment.content_id || attachment.content_type.startsWith('image/')) {
      contentDisposition = `inline; filename="${encodeURIComponent(attachment.filename)}"`;
    }

    let fileData: ArrayBuffer | ReadableStream;
    let r2Object: any = null;

    // 如果有 KV，尝试从 KV 缓存读取（只缓存小于 1MB 的附件）
    if (c.env.KV && attachment.size_bytes < KVCacheService.ATTACHMENT_CONFIG.MAX_SIZE) {
      const kvCache = new KVCacheService(c.env.KV);
      const cacheKey = KVCacheService.getAttachmentKey(attachmentId);
      const cached = await kvCache.getBinary(cacheKey);

      if (cached) {
        debugLog(`[下载附件] 从 KV 缓存读取: ${attachmentId}`);
        fileData = cached.data;

        // 使用缓存的元数据创建响应
        return handleR2ObjectCache(c, {
          body: fileData,
          size: parseInt(cached.metadata.size || String(attachment.size_bytes)),
          uploaded: attachment.updated_at || attachment.created_at,
          etag: cached.metadata.etag
        }, {
          contentType: attachment.content_type,
          contentDisposition,
          identifier: attachmentId,
          immutable: true
        });
      }

      debugLog(`[下载附件] KV 缓存未命中，从 R2 读取: ${attachmentId}`);
    }

    // 从 R2 读取文件（带重试机制）
    r2Object = await retryR2Operation(`读取附件 ${attachmentId}`, async () => {
      return await c.env.R2.get(attachment.r2_key);
    });
    if (!r2Object) {
      throw new HTTPException(404, { message: '附件文件不存在' });
    }

    // 如果有 KV 且文件小于 1MB，写入 KV 缓存（后台异步写入，不阻塞响应）
    let bodyStream = r2Object.body;
    if (c.env.KV && attachment.size_bytes < KVCacheService.ATTACHMENT_CONFIG.MAX_SIZE) {
      // 克隆 stream 用于缓存
      const [stream1, stream2] = r2Object.body.tee();
      bodyStream = stream1;
      fileData = stream1;

      // 异步写入 KV 缓存（不等待完成）
      c.executionCtx?.waitUntil((async () => {
        try {
          const kvCache = new KVCacheService(c.env.KV);
          const cacheKey = KVCacheService.getAttachmentKey(attachmentId);
          await kvCache.setBinary(cacheKey, stream2, {
            contentType: attachment.content_type,
            filename: attachment.filename,
            etag: r2Object.etag || ''
          });
          debugLog(`[下载附件] 写入 KV 缓存成功: ${attachmentId}`);
        } catch (err) {
          errorLog(`[下载附件] 写入 KV 缓存失败: ${attachmentId}`, err);
        }
      })());
    }

    // 使用 HTTP 缓存处理，传入自定义 body
    return handleR2ObjectCache(c, r2Object, {
      contentType: attachment.content_type,
      contentDisposition,
      identifier: attachmentId,
      immutable: true, // 附件内容不会改变
      body: bodyStream // 传入 tee 后的 stream
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[下载附件] 失败:', error);
    throw new HTTPException(500, { message: '下载附件失败' });
  }
});

/**
 * 下载附件（简洁路径别名）
 * GET /api/attachments/{attachmentId}
 * 
 * @description
 * 这是 /api/emails/:id/attachments/:attachmentId 的简洁版本
 * 通过附件 ID 直接访问，自动查询关联的邮件并检查权限
 */
api.get('/attachments/:attachmentId', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const attachmentId = c.req.param('attachmentId');

    // 从数据库获取附件信息（包括关联的邮件 ID）
    const attachment = await getAttachmentById(c.env.DB, attachmentId);
    if (!attachment) {
      throw new HTTPException(404, { message: '附件不存在' });
    }

    // 通过附件的 email_id 查询邮件
    const email = await getEmailById(c.env.DB, attachment.email_id);
    if (!email) {
      throw new HTTPException(404, { message: '关联的邮件不存在' });
    }

    debugLog(`[下载附件-简洁路径] 附件ID: ${attachmentId}, 文件名: ${attachment.filename}, 邮件ID: ${attachment.email_id}`);

    // 检查是否有 If-None-Match 头（条件请求）
    const ifNoneMatch = c.req.header('If-None-Match');
    if (ifNoneMatch) {
      debugLog(`[下载附件-简洁路径] 收到条件请求，If-None-Match: ${ifNoneMatch}`);
    }

    // 判断 Content-Disposition
    let contentDisposition = `attachment; filename="${encodeURIComponent(attachment.filename)}"`;
    if (attachment.content_id || attachment.content_type.startsWith('image/')) {
      contentDisposition = `inline; filename="${encodeURIComponent(attachment.filename)}"`;
    }

    let fileData: ArrayBuffer | ReadableStream;
    let r2Object: any = null;

    // 如果有 KV，尝试从 KV 缓存读取（只缓存小于 1MB 的附件）
    if (c.env.KV && attachment.size_bytes < KVCacheService.ATTACHMENT_CONFIG.MAX_SIZE) {
      const kvCache = new KVCacheService(c.env.KV);
      const cacheKey = KVCacheService.getAttachmentKey(attachmentId);
      const cached = await kvCache.getBinary(cacheKey);

      if (cached) {
        debugLog(`[下载附件-简洁路径] 从 KV 缓存读取: ${attachmentId}`);
        fileData = cached.data;

        // 使用缓存的元数据创建响应
        return handleR2ObjectCache(c, {
          body: fileData,
          size: parseInt(cached.metadata.size || String(attachment.size_bytes)),
          uploaded: attachment.updated_at || attachment.created_at,
          etag: cached.metadata.etag
        }, {
          contentType: attachment.content_type,
          contentDisposition,
          identifier: attachmentId,
          immutable: true
        });
      }

      debugLog(`[下载附件-简洁路径] KV 缓存未命中，从 R2 读取: ${attachmentId}`);
    }

    // 从 R2 读取文件（带重试机制）
    r2Object = await retryR2Operation(`读取附件 ${attachmentId}`, async () => {
      return await c.env.R2.get(attachment.r2_key);
    });
    if (!r2Object) {
      throw new HTTPException(404, { message: '附件文件不存在' });
    }

    // 如果有 KV 且文件小于 1MB，写入 KV 缓存（后台异步写入，不阻塞响应）
    let bodyStream = r2Object.body;
    if (c.env.KV && attachment.size_bytes < KVCacheService.ATTACHMENT_CONFIG.MAX_SIZE) {
      // 克隆 stream 用于缓存
      const [stream1, stream2] = r2Object.body.tee();
      bodyStream = stream1;
      fileData = stream1;

      // 异步写入 KV 缓存（不等待完成）
      c.executionCtx?.waitUntil((async () => {
        try {
          const kvCache = new KVCacheService(c.env.KV);
          const cacheKey = KVCacheService.getAttachmentKey(attachmentId);
          await kvCache.setBinary(cacheKey, stream2, {
            contentType: attachment.content_type,
            filename: attachment.filename,
            etag: r2Object.etag || ''
          });
          debugLog(`[下载附件-简洁路径] 写入 KV 缓存成功: ${attachmentId}`);
        } catch (err) {
          errorLog(`[下载附件-简洁路径] 写入 KV 缓存失败: ${attachmentId}`, err);
        }
      })());
    }

    // 使用 HTTP 缓存处理，传入自定义 body
    return handleR2ObjectCache(c, r2Object, {
      contentType: attachment.content_type,
      contentDisposition,
      identifier: attachmentId,
      immutable: true, // 附件内容不会改变
      body: bodyStream // 传入 tee 后的 stream
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[下载附件-简洁路径] 失败:', error);
    throw new HTTPException(500, { message: '下载附件失败' });
  }
});

/**
 * 发送邮件
 * POST /api/emails/send
 */
api.post('/emails/send', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const { to, from, subject, content, content_type = 'markdown' } = await c.req.json();

    if (!to || !subject || !content) {
      throw new HTTPException(400, { message: '收件人、主题和内容不能为空' });
    }

    // 单管理员模式：所有用户都是管理员，可以发送邮件

    // 发送邮件（使用默认域名）
    await sendEmail(c.env, {
      to,
      from: from || 'noreply@example.com',
      subject,
      content,
      content_type
    });

    return c.json<ApiResponse>({
      success: true,
      message: '邮件发送成功'
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[发送邮件] 失败:', error);
    throw new HTTPException(500, { message: '发送邮件失败' });
  }
});

// ==================== 系统相关 ====================
api.route('/system', systemRoutes);

// ==================== 数据库管理 ====================
api.route('/database', databaseRoutes);

// ==================== KV 缓存管理 ====================
api.route('/kv-cache', kvCacheRouter);

// ==================== 测试端点（仅开发环境）====================
api.route('/test', testEmailRoutes);

export { api };
