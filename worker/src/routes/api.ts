/**
 * 统一 API 路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware } from '../middleware/auth';
import { getPaginationParams } from '../config/constants';
import { debugLog, errorLog } from '../utils/debug';
import { handleR2ObjectCache, handleTextContentCache } from '../utils/cache';
import { retryR2Operation } from '../utils/retry';

// 导入各个功能模块
import { authRoutes } from './auth';
import { userRoutes } from './user';
import { systemRoutes } from './system';
import { dashboardRoutes } from './dashboard';
import { toolsRoutes } from './tools';

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
  createEmail,
  copyEmailAttachments,
  buildForwardedEmailBody,
  saveRawEmailToR2,
  getRawEmailFromR2,
  getRawEmailBytesFromR2,
  replaceCidReferencesInHtml
} from '../services/email';
import PostalMime from 'postal-mime';
import { getSystemConfig } from '../services/settings';
import { logForwardResult, sendWebhook, ensureRoutingRulesActionColumn } from '../services/webhook';
import { bumpChangeSignals } from '../services/changeSignals';

import type { Env, ApiResponse, EmailQueryParams, D1Database } from '../types';

const api = new Hono<{ Bindings: Env }>();

type RouteParamContext = {
  req: {
    param: (name: string) => string | undefined;
  };
};

function getRequiredParam(c: RouteParamContext, name: string, label: string): string {
  const value = c.req.param(name);
  if (!value) {
    throw new HTTPException(400, { message: `${label}不能为空` });
  }
  return value;
}

function parseEmailHeaders(headersJson?: string | null): Record<string, string> {
  if (!headersJson) {
    return {};
  }

  try {
    const parsed = JSON.parse(headersJson);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function formatAddressDisplay(name?: string | null, address?: string | null): string {
  const cleanAddress = (address || '').trim();
  const cleanName = (name || '').trim() || (cleanAddress.includes('@') ? cleanAddress.split('@')[0] : '');

  if (!cleanName) {
    return cleanAddress;
  }

  return cleanAddress ? `${cleanName} <${cleanAddress}>` : cleanName;
}

function decodeMimeHeaderValue(value: string): string {
  return value.replace(/=\?([^?]+)\?([bqBQ])\?([^?]+)\?=/g, (_match, charset, encoding, encoded) => {
    try {
      const normalizedCharset = String(charset || 'utf-8').toLowerCase();
      const bytes = String(encoding).toLowerCase() === 'b'
        ? Uint8Array.from(atob(String(encoded).replace(/\s/g, '')), char => char.charCodeAt(0))
        : decodeQuotedPrintableHeader(String(encoded));
      return new TextDecoder(normalizedCharset).decode(bytes);
    } catch {
      return String(encoded);
    }
  }).trim();
}

function decodeQuotedPrintableHeader(value: string): Uint8Array {
  const normalized = value.replace(/_/g, ' ');
  const bytes: number[] = [];
  for (let i = 0; i < normalized.length; i++) {
    if (normalized[i] === '=' && /^[0-9a-fA-F]{2}$/.test(normalized.slice(i + 1, i + 3))) {
      bytes.push(parseInt(normalized.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(normalized.charCodeAt(i));
    }
  }
  return new Uint8Array(bytes);
}

function parseAddressHeader(value?: string | null): { name: string; address: string } {
  const source = (value || '').trim();
  if (!source) return { name: '', address: '' };

  const bracketMatch = source.match(/^(.*?)<([^<>@\s]+@[^<>\s]+)>/);
  if (bracketMatch) {
    return {
      name: decodeMimeHeaderValue(bracketMatch[1].trim().replace(/^"|"$/g, '')),
      address: bracketMatch[2].trim()
    };
  }

  const emailMatch = source.match(/([^\s<>@]+@[^\s<>]+)/);
  return {
    name: '',
    address: emailMatch?.[1]?.trim() || source
  };
}

function buildOutgoingRawEmail(params: {
  from: string;
  to: string;
  subject: string;
  content: string;
  contentType: string;
  messageId: string;
  replyTo?: string;
}): string {
  return [
    `From: ${params.from}`,
    `To: ${params.to}`,
    `Subject: ${params.subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: ${params.messageId}`,
    ...(params.replyTo ? [`Reply-To: ${params.replyTo}`] : []),
    `MIME-Version: 1.0`,
    `Content-Type: ${params.contentType}; charset=UTF-8`,
    `Content-Transfer-Encoding: 8bit`,
    ``,
    params.content
  ].join('\r\n');
}

function getEmailAddressDomain(address: string): string {
  const normalized = address.trim().toLowerCase();
  const atIndex = normalized.lastIndexOf('@');
  if (atIndex < 0 || atIndex === normalized.length - 1) {
    return '';
  }
  return normalized.slice(atIndex + 1);
}

function stripHtmlForOutgoingPreview(content: string): string {
  return content
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|td|h[1-6]|li)>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_match, dec) => String.fromCharCode(parseInt(dec, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_match, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\n\s*\n\s*\n/g, '\n\n')
    .replace(/[ \t]+/g, ' ')
    .trim();
}

function buildOutgoingEmailPreview(content: string, contentType: 'text' | 'html'): string {
  if (contentType === 'text') {
    return (content.trim() || '[无内容预览]').slice(0, 1000);
  }

  return (stripHtmlForOutgoingPreview(content) || '[无内容预览]').slice(0, 1000);
}

function getEmailFromDisplay(email: { from_address?: string | null; headers_json?: string | null }): string {
  const headers = parseEmailHeaders(email.headers_json);
  const rawFrom = parseAddressHeader(headers.from || '');
  const parsedAddress = headers.parsed_from_address || rawFrom.address || email.from_address || '';
  const parsedName = headers.parsed_from_name || rawFrom.name || '';
  const display = formatAddressDisplay(parsedName, parsedAddress);

  if (display) {
    return display;
  }

  return headers.from?.includes('<') ? headers.from : (email.from_address || '');
}

function toPublicEmail(email: any) {
  const { headers_json, ...publicEmail } = email;
  return publicEmail;
}

function containsCjk(text: string): boolean {
  return /[\u3400-\u9fff]/.test(text);
}

function isLikelyCorruptParsedContent(parsed: string, fallback: string): boolean {
  const parsedText = parsed.trim();
  const fallbackText = fallback.trim();

  if (!parsedText) {
    return true;
  }

  if (parsedText.includes('\uFFFD')) {
    return true;
  }

  if (fallbackText.length >= 20 && parsedText.length <= 8) {
    return true;
  }

  if (containsCjk(fallbackText) && !containsCjk(parsedText) && parsedText.length < fallbackText.length / 2) {
    return true;
  }

  return false;
}

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
    const hasAttachmentsQuery = c.req.query('has_attachments');
    const hasAttachments = hasAttachmentsQuery === 'true'
      ? true
      : hasAttachmentsQuery === 'false'
        ? false
        : undefined;

    // 解析查询参数
    const queryParams: EmailQueryParams = {
      ...getPaginationParams(c.req.query()),
      folder: c.req.query('folder') === 'sent' ? 'sent' : 'inbox',
      recipient_domain: c.req.query('recipient_domain')?.trim() || undefined,
      recipient_mailbox: c.req.query('recipient_mailbox')?.trim() || undefined,
      sender_mailbox: c.req.query('sender_mailbox')?.trim() || undefined,
      recipient: c.req.query('recipient')?.trim() || undefined,
      search: c.req.query('search')?.trim() || undefined,
      status: c.req.query('status')?.trim() || undefined,
      sender: c.req.query('sender')?.trim() || undefined,
      subject: c.req.query('subject')?.trim() || undefined,
      start_date: c.req.query('start_date')?.trim() || undefined,
      end_date: c.req.query('end_date')?.trim() || undefined,
      has_attachments: hasAttachments,
      sort: c.req.query('sort')?.trim() || undefined,
      order: c.req.query('order')?.trim() as 'asc' | 'desc' | undefined
    };

    // 单用户模式:所有邮件都不绑定用户ID,直接查询所有邮件
    const result = await getAllEmails(c.env.DB, queryParams);

    // 转换字段名以匹配前端期望的格式
    const items = result.emails.map(email => ({
      ...toPublicEmail(email),
      from: getEmailFromDisplay(email),
      to: email.to_address || '',
      status: email.is_read ? 'read' : 'unread',
      owner_username: (email as any).owner_username || null,
      // 保留原始字段以便向后兼容
      from_address: email.from_address,
      to_address: email.to_address
    }));

    const data = {
      total: result.total,
      items,
      groups: result.groups || [],
      hierarchyGroups: result.hierarchyGroups || []
    };

    return c.json<ApiResponse>({
      success: true,
      data
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
    const emailId = getRequiredParam(c, 'id', '邮件ID');

    const email = await getEmailById(c.env.DB, emailId);
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }

    // 自动标记为已读（如果当前是未读状态）
    if (email.is_read === 0) {
      try {
        const updatedEmail = await updateEmailReadStatus(c.env.DB, emailId, true);
        await bumpChangeSignals(c.env.DB, ['emails', 'dashboard']);
        debugLog('[邮件详情] 自动标记为已读');
        // 更新 email 对象
        Object.assign(email, updatedEmail || { is_read: 1 });
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
      // 从 R2 读取精简版 .eml 文件。解析时保留原始字节，避免非 UTF-8 内容被提前损坏。
      const rawEmailBytes = await getRawEmailBytesFromR2(c.env.R2, emailId);

      if (rawEmailBytes) {
        // 使用 postal-mime 解析邮件
        const parser = new PostalMime();
        const parsedEmail = await parser.parse(rawEmailBytes);

        // 提取内容
        if (parsedEmail.html && parsedEmail.html.trim()) {
          if (!isLikelyCorruptParsedContent(parsedEmail.html, email.content || '')) {
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
          } else {
            debugLog('[邮件详情] HTML 内容疑似编码损坏，使用数据库预览');
          }
        } else if (parsedEmail.text && parsedEmail.text.trim()) {
          if (!isLikelyCorruptParsedContent(parsedEmail.text, email.content || '')) {
            fullContent = parsedEmail.text;
            fullContentType = 'text';
            debugLog('[邮件详情] 使用纯文本内容，长度:', fullContent.length);
          } else {
            debugLog('[邮件详情] 纯文本内容疑似编码损坏，使用数据库预览');
          }
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
      ...toPublicEmail(email),
      from: getEmailFromDisplay(email),
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
 * 支持两层缓存机制:
 * 1. 浏览器缓存(HTTP 缓存头)- ETag、Cache-Control、304 响应
 * 2. R2 存储(源数据)- 最终数据源
 * 
 * 返回剔除附件后的完整邮件(RFC 822 格式,包含邮件头和正文)
 */
api.get('/emails/:id/raw', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const emailId = getRequiredParam(c, 'id', '邮件ID');

    const email = await getEmailById(c.env.DB, emailId);
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }

    let rawEmail: string | null = null;

    // 从 R2 读取(带重试机制)
    if (c.env.R2) {
      rawEmail = await retryR2Operation(`读取原始邮件 ${emailId}`, async () => {
        return await getRawEmailFromR2(c.env.R2, email.id);
      });
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
    if (updatedCount > 0) {
      await bumpChangeSignals(c.env.DB, ['emails', 'dashboard']);
    }

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
    const emailId = getRequiredParam(c, 'id', '邮件ID');
    const { is_read } = await c.req.json();

    if (typeof is_read !== 'boolean') {
      throw new HTTPException(400, { message: 'is_read 参数必须是布尔值' });
    }

    const email = await getEmailById(c.env.DB, emailId);
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }

    await updateEmailReadStatus(c.env.DB, emailId, is_read);
    await bumpChangeSignals(c.env.DB, ['emails', 'dashboard']);

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
 * 手动转发邮件
 * POST /api/emails/{id}/forward
 */
api.post('/emails/:id/forward', jwtAuthMiddleware, async (c) => {
  try {
    const emailId = getRequiredParam(c, 'id', '邮件ID');
    const body = await c.req.json().catch(() => ({}));
    const mode = body.mode === 'recipient' ? 'recipient' : 'webhook';

    const email = await getEmailById(c.env.DB, emailId);
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }

    if (mode === 'webhook') {
      const channelId = Number(body.channelId);
      if (!Number.isInteger(channelId) || channelId <= 0) {
        throw new HTTPException(400, { message: '请选择 Webhook 通道' });
      }

      const channel = await c.env.DB.prepare(`
        SELECT id, name, enabled, channel_type, channel_url, channel_secret
        FROM routing_rules
        WHERE category = 'channel'
          AND id = ?
        LIMIT 1
      `).bind(channelId).first();

      const url = (channel?.channel_url as string | undefined)?.trim();
      if (!channel || !url) {
        throw new HTTPException(400, { message: 'Webhook 通道不存在' });
      }

      const channelType = channel.channel_type as string | undefined;
      const type = channelType === 'feishu' || channelType === 'bark'
        ? channelType
        : 'dingtalk';
      const result = await sendWebhook(url, email, (channel.channel_secret as string) || undefined, type);
      await logForwardResult(c.env.DB, email.id, url, result);

      return c.json<ApiResponse>({
        success: result.success,
        message: result.success ? 'Webhook 转发成功' : `Webhook 转发失败：${result.errorMessage || '未知错误'}`,
        data: {
          mode,
          target: url,
          responseCode: result.responseCode || null
        }
      }, result.success ? 200 : 502);
    }

    const targetEmail = typeof body.targetEmail === 'string' ? body.targetEmail.trim().toLowerCase() : '';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(targetEmail)) {
      throw new HTTPException(400, { message: '转发收件邮箱格式无效' });
    }

    const targetDomain = targetEmail.split('@').pop() || '';
    const config = await getSystemConfig(c.env.DB);
    const localDomains = Array.isArray(config.supported_emails) ? config.supported_emails : [];
    const targetForwardType = ['internal', 'cf', 'resend'].includes(body.targetForwardType) ? body.targetForwardType : 'internal';
    const isLocalDomain = localDomains.includes(targetDomain);
    const targetFromAddress = typeof body.from === 'string' ? body.from.trim() : '';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(targetFromAddress)) {
      throw new HTTPException(400, { message: '转发发件人邮箱格式无效' });
    }
    const originalReplyTo = email.reply_to || email.from_address || undefined;
    const forwardedBy = 'cloudflare-email-manager';
    const forwardSubject = `Fwd: ${email.subject || '(无主题)'}`;
    const forwardedBody = await buildForwardedEmailBody(email, { forwardedBy }, c.env.R2);
    const mimeContentType = forwardedBody.contentType === 'html' ? 'text/html' : 'text/plain';

    try {
      if (targetForwardType === 'internal') {
        if (!isLocalDomain) {
          throw new HTTPException(400, { message: '站内转发目标域名不在系统配置中' });
        }

        const fromAddress = targetFromAddress;
        const forwardedEmailId = crypto.randomUUID();
        const now = new Date().toISOString();
        const messageId = `<forward-${forwardedEmailId}@${targetDomain}>`;
        const rawEmail = [
          `From: ${fromAddress}`,
          `To: ${targetEmail}`,
          `Subject: ${forwardSubject}`,
          `Date: ${new Date().toUTCString()}`,
          `Message-ID: ${messageId}`,
          `X-CEM-Forwarded: 1`,
          `X-CEM-Forwarded-By: ${forwardedBy}`,
          `X-CEM-Original-From: ${email.from_address || ''}`,
          `X-CEM-Original-To: ${email.to_address || ''}`,
          `MIME-Version: 1.0`,
          `Content-Type: ${mimeContentType}; charset=UTF-8`,
          `Content-Transfer-Encoding: 8bit`,
          ``,
          forwardedBody.content
        ].join('\r\n');

        const forwardedEmail = await createEmail(c.env.DB, {
          subject: forwardSubject,
          from_address: fromAddress,
          to_address: targetEmail,
          content: forwardedBody.preview.slice(0, 1000),
          is_read: 1,
          attachment_count: c.env.R2 ? email.attachment_count || 0 : 0,
          message_id: messageId,
          headers_json: JSON.stringify({
            from: fromAddress,
            to: targetEmail,
            subject: forwardSubject,
            date: now,
            'message-id': messageId,
            'x-cem-forwarded': '1',
            'x-cem-forwarded-by': forwardedBy,
            'x-cem-original-from': email.from_address || '',
            'x-cem-original-to': email.to_address || ''
          }),
          size_bytes: new TextEncoder().encode(rawEmail).byteLength,
          date: now,
          reply_to: email.reply_to || email.from_address,
          cc: null,
          bcc: null,
          content_type: `${mimeContentType}; charset=UTF-8`,
          folder: 'sent',
          received_at: now
        }, forwardedEmailId);

        if (c.env.R2) {
          await saveRawEmailToR2(c.env.R2, rawEmail, messageId, forwardedEmail.id, fromAddress, targetEmail);
          const copiedAttachmentCount = await copyEmailAttachments(c.env.DB, c.env.R2, email.id, forwardedEmail.id);
          if (copiedAttachmentCount !== (email.attachment_count || 0)) {
            await c.env.DB.prepare(`
              UPDATE emails
              SET attachment_count = ?, updated_at = CURRENT_TIMESTAMP
              WHERE id = ?
            `).bind(copiedAttachmentCount, forwardedEmail.id).run();
          }
        }

        await logForwardResult(c.env.DB, email.id, `mailto:${targetEmail}`, {
          success: true,
          responseCode: 200
        }, { from: fromAddress, to: targetEmail });

        await bumpChangeSignals(c.env.DB, ['emails', 'dashboard']);

        return c.json<ApiResponse>({
          success: true,
          message: '邮件转发已投递到本地域',
          data: { mode, target: targetEmail, local: true, forwardedEmailId: forwardedEmail.id }
        });
      }

      const sendResult = await sendEmail(c.env, {
        to: targetEmail,
        from: targetFromAddress,
        reply_to: originalReplyTo,
        subject: forwardSubject,
        content: forwardedBody.content,
        content_type: forwardedBody.contentType,
        delivery_method: targetForwardType
      });

      await logForwardResult(c.env.DB, email.id, `mailto:${targetEmail}`, {
        success: true,
        responseCode: 200
      }, { from: targetFromAddress, to: targetEmail });

      const sentEmailId = crypto.randomUUID();
      const now = new Date().toISOString();
      const sentMessageId = sendResult.messageId
        ? `<${sendResult.messageId}@${targetForwardType}.forward>`
        : `<forward-sent-${sentEmailId}@${targetDomain}>`;
      const rawEmail = buildOutgoingRawEmail({
        from: targetFromAddress,
        to: targetEmail,
        subject: forwardSubject,
        content: forwardedBody.content,
        contentType: mimeContentType,
        messageId: sentMessageId,
        replyTo: originalReplyTo
      });

      const sentEmail = await createEmail(c.env.DB, {
        subject: forwardSubject,
        from_address: targetFromAddress,
        to_address: targetEmail,
        content: forwardedBody.preview.slice(0, 1000),
        is_read: 1,
        attachment_count: c.env.R2 ? email.attachment_count || 0 : 0,
        message_id: sentMessageId,
        headers_json: JSON.stringify({
          from: targetFromAddress,
          to: targetEmail,
          subject: forwardSubject,
          date: now,
          'message-id': sentMessageId,
          'x-cem-forwarded': '1',
          'x-cem-forwarded-by': forwardedBy,
          'x-cem-original-from': email.from_address || '',
          'x-cem-original-to': email.to_address || ''
        }),
        size_bytes: new TextEncoder().encode(rawEmail).byteLength,
        date: now,
        reply_to: originalReplyTo || null,
        cc: null,
        bcc: null,
        content_type: `${mimeContentType}; charset=UTF-8`,
        folder: 'sent',
        resend_email_id: targetForwardType === 'resend' ? sendResult.messageId || null : null,
        received_at: now
      }, sentEmailId);

      if (c.env.R2) {
        await saveRawEmailToR2(c.env.R2, rawEmail, sentMessageId, sentEmail.id, targetFromAddress, targetEmail);
        const copiedAttachmentCount = await copyEmailAttachments(c.env.DB, c.env.R2, email.id, sentEmail.id);
        if (copiedAttachmentCount !== (email.attachment_count || 0)) {
          await c.env.DB.prepare(`
            UPDATE emails
            SET attachment_count = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `).bind(copiedAttachmentCount, sentEmail.id).run();
        }
      }

      await bumpChangeSignals(c.env.DB, ['emails', 'dashboard']);

      return c.json<ApiResponse>({
        success: true,
        message: '邮件转发已提交投递',
        data: {
          mode,
          target: targetEmail,
          local: false,
          targetForwardType,
          messageId: sendResult.messageId || null,
          sentEmailId: sentEmail.id
        }
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : '邮件转发失败';
      await logForwardResult(c.env.DB, email.id, `mailto:${targetEmail}`, {
        success: false,
        errorMessage: message
      }, { from: targetFromAddress || null, to: targetEmail });
      throw new HTTPException(502, { message });
    }
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[手动转发邮件] 失败:', error);
    throw new HTTPException(500, { message: '手动转发邮件失败' });
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
    if (result.deletedEmails > 0) {
      await bumpChangeSignals(c.env.DB, ['emails', 'dashboard']);
    }

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
    const emailId = getRequiredParam(c, 'id', '邮件ID');

    const email = await getEmailById(c.env.DB, emailId);
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }

    const result = await deleteEmail(c.env.DB, c.env.R2, emailId);
    await bumpChangeSignals(c.env.DB, ['emails', 'dashboard']);

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
 * 支持两层缓存机制:
 * 1. 浏览器缓存(HTTP 缓存头)- ETag、Cache-Control、304 响应
 * 2. R2 存储(源数据)- 最终数据源
 */
api.get('/emails/:id/attachments/:attachmentId', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const emailId = getRequiredParam(c, 'id', '邮件ID');
    const attachmentId = getRequiredParam(c, 'attachmentId', '附件ID');

    const email = await getEmailById(c.env.DB, emailId);
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }

    const attachment = await getAttachmentById(c.env.DB, attachmentId);
    if (!attachment) {
      throw new HTTPException(404, { message: '附件不存在' });
    }
    if (attachment.deleted_at) {
      throw new HTTPException(410, { message: '附件不存在或已删除' });
    }

    debugLog(`[下载附件] 附件ID: ${attachmentId}, 文件名: ${attachment.filename}, 大小: ${attachment.size_bytes} bytes`);

    // 检查是否有 If-None-Match 头(条件请求)
    const ifNoneMatch = c.req.header('If-None-Match');
    if (ifNoneMatch) {
      debugLog(`[下载附件] 收到条件请求,If-None-Match: ${ifNoneMatch}`);
    }

    // 判断 Content-Disposition
    let contentDisposition = `attachment; filename="${encodeURIComponent(attachment.filename)}"`;
    if (attachment.content_id || attachment.content_type.startsWith('image/')) {
      contentDisposition = `inline; filename="${encodeURIComponent(attachment.filename)}"`;
    }

    // 从 R2 读取文件(带重试机制)
    const r2Object = await retryR2Operation(`读取附件 ${attachmentId}`, async () => {
      return await c.env.R2.get(attachment.r2_key);
    });
    if (!r2Object) {
      await c.env.DB.prepare(`
        UPDATE attachments
        SET deleted_at = COALESCE(deleted_at, CURRENT_TIMESTAMP),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(attachmentId).run();
      throw new HTTPException(410, { message: '附件不存在或已删除' });
    }

    // 使用 HTTP 缓存处理
    return handleR2ObjectCache(c, r2Object, {
      contentType: attachment.content_type,
      contentDisposition,
      identifier: attachmentId,
      immutable: true // 附件内容不会改变
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
    const attachmentId = getRequiredParam(c, 'attachmentId', '附件ID');

    // 从数据库获取附件信息（包括关联的邮件 ID）
    const attachment = await getAttachmentById(c.env.DB, attachmentId);
    if (!attachment) {
      throw new HTTPException(404, { message: '附件不存在' });
    }
    if (attachment.deleted_at) {
      throw new HTTPException(410, { message: '附件不存在或已删除' });
    }

    // 通过附件的 email_id 查询邮件
    const email = await getEmailById(c.env.DB, attachment.email_id);
    if (!email) {
      throw new HTTPException(404, { message: '关联的邮件不存在' });
    }

    debugLog(`[下载附件-简洁路径] 附件ID: ${attachmentId}, 文件名: ${attachment.filename}, 邮件ID: ${attachment.email_id}`);

    // 检查是否有 If-None-Match 头(条件请求)
    const ifNoneMatch = c.req.header('If-None-Match');
    if (ifNoneMatch) {
      debugLog(`[下载附件-简洁路径] 收到条件请求,If-None-Match: ${ifNoneMatch}`);
    }

    // 判断 Content-Disposition
    let contentDisposition = `attachment; filename="${encodeURIComponent(attachment.filename)}"`;
    if (attachment.content_id || attachment.content_type.startsWith('image/')) {
      contentDisposition = `inline; filename="${encodeURIComponent(attachment.filename)}"`;
    }

    // 从 R2 读取文件(带重试机制)
    const r2Object = await retryR2Operation(`读取附件 ${attachmentId}`, async () => {
      return await c.env.R2.get(attachment.r2_key);
    });
    if (!r2Object) {
      await c.env.DB.prepare(`
        UPDATE attachments
        SET deleted_at = COALESCE(deleted_at, CURRENT_TIMESTAMP),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(attachmentId).run();
      throw new HTTPException(410, { message: '附件不存在或已删除' });
    }

    // 使用 HTTP 缓存处理
    return handleR2ObjectCache(c, r2Object, {
      contentType: attachment.content_type,
      contentDisposition,
      identifier: attachmentId,
      immutable: true // 附件内容不会改变
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
    const { to, from, subject, content, content_type, delivery_method } = await c.req.json();

    if (!to || !from || !subject || !content) {
      throw new HTTPException(400, { message: '发件人、收件人、主题和内容不能为空' });
    }

    if (!['internal', 'cf', 'resend'].includes(delivery_method)) {
      throw new HTTPException(400, { message: '发送类型必须是 internal、cf 或 resend' });
    }

    if (!['text', 'html'].includes(content_type)) {
      throw new HTTPException(400, { message: '内容格式必须是 text 或 html' });
    }

    const method = delivery_method as 'internal' | 'cf' | 'resend';
    const normalizedContentType = content_type as 'text' | 'html';
    const sendResult = method === 'internal'
      ? { messageId: undefined }
      : await sendEmail(c.env, {
        to,
        from,
        subject,
        content,
        content_type: normalizedContentType,
        delivery_method: method
      });

    const sentEmailId = crypto.randomUUID();
    const now = new Date().toISOString();
    const targetDomain = String(to).split('@').pop() || 'sent.local';
    const messageId = sendResult.messageId
      ? `<${sendResult.messageId}@${method}.send>`
      : `<sent-${sentEmailId}@${targetDomain}>`;
    const rawEmail = buildOutgoingRawEmail({
      from,
      to,
      subject,
      content,
      contentType: normalizedContentType === 'html' ? 'text/html' : 'text/plain',
      messageId
    });
    const previewContent = buildOutgoingEmailPreview(String(content), normalizedContentType);

    const sentEmail = await createEmail(c.env.DB, {
      subject,
      from_address: from,
      to_address: to,
      content: previewContent,
      is_read: 1,
      attachment_count: 0,
      message_id: messageId,
      headers_json: JSON.stringify({
        from,
        to,
        subject,
        date: now,
        'message-id': messageId
      }),
      size_bytes: new TextEncoder().encode(rawEmail).byteLength,
      date: now,
      reply_to: null,
      cc: null,
      bcc: null,
      content_type: `${normalizedContentType === 'html' ? 'text/html' : 'text/plain'}; charset=UTF-8`,
      folder: 'sent',
      resend_email_id: method === 'resend' ? sendResult.messageId || null : null,
      received_at: now
    }, sentEmailId);

    if (c.env.R2) {
      await saveRawEmailToR2(c.env.R2, rawEmail, messageId, sentEmail.id, from, to);
    }

    let inboxEmailId: string | null = null;
    const config = await getSystemConfig(c.env.DB);
    const localDomains = Array.isArray(config.supported_emails) ? config.supported_emails : [];
    const localTargetDomain = getEmailAddressDomain(String(to));
    const isLocalRecipient = method === 'internal' && localDomains.includes(localTargetDomain);

    if (isLocalRecipient) {
      inboxEmailId = crypto.randomUUID();
      const inboxEmail = await createEmail(c.env.DB, {
        subject,
        from_address: from,
        to_address: to,
        content: previewContent,
        is_read: 0,
        attachment_count: 0,
        message_id: messageId,
        headers_json: JSON.stringify({
          from,
          to,
          subject,
          date: now,
          'message-id': messageId,
          'x-cem-local-delivery': '1',
          'x-cem-sent-email-id': sentEmail.id
        }),
        size_bytes: new TextEncoder().encode(rawEmail).byteLength,
        date: now,
        reply_to: from,
        cc: null,
        bcc: null,
        content_type: `${normalizedContentType === 'html' ? 'text/html' : 'text/plain'}; charset=UTF-8`,
        folder: 'inbox',
        resend_email_id: null,
        received_at: now
      }, inboxEmailId);

      if (c.env.R2) {
        await saveRawEmailToR2(c.env.R2, rawEmail, messageId, inboxEmail.id, from, to);
      }
    }

    await bumpChangeSignals(c.env.DB, ['emails', 'dashboard']);

    return c.json<ApiResponse>({
      success: true,
      message: isLocalRecipient ? '邮件已发送并投递到站内收件箱' : '邮件已提交投递',
      data: {
        target: to,
        messageId: sendResult.messageId || null,
        deliveryMethod: method,
        localDelivered: isLocalRecipient,
        inboxEmailId,
        sentEmailId: sentEmail.id
      }
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[发送邮件] 失败:', error);
    const message = error instanceof Error ? error.message : '发送邮件失败';
    throw new HTTPException(500, { message });
  }
});

// ==================== 消息路由相关 ====================
const parseJsonNumberArray = (value: unknown): number[] => {
  if (typeof value !== 'string' || !value.trim()) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed)
      ? parsed.map((item) => Number(item)).filter((item) => Number.isInteger(item))
      : [];
  } catch {
    return [];
  }
};

const selectRoutingRows = async (db: D1Database) => {
  const result = await db.prepare(`
    SELECT
      id,
      category,
      name,
      enabled,
      match_mode,
      action,
      sender_pattern,
      recipient_pattern,
      subject_pattern,
      content_pattern,
      target_channel_ids,
      target_email,
      target_from_address,
      target_forward_type,
      is_default,
      default_mode,
      channel_type,
      channel_url,
      channel_secret
    FROM routing_rules
    ORDER BY id ASC
  `).all();

  return result.results || [];
};

const buildRoutingPayload = (rows: any[]) => {
  const maskSecretValue = (secret: string) => {
    if (!secret || secret.length <= 8) return '****';
    return `${secret.slice(0, 4)}${'*'.repeat(Math.max(4, secret.length - 8))}${secret.slice(-4)}`;
  };

  const mapped = rows.map((row) => ({
    id: Number(row.id),
    category: row.category,
    name: row.name || '',
    enabled: row.enabled === 1,
    matchMode: row.match_mode === 'any' ? 'any' : 'all',
    action: row.action === 'ignore' ? 'ignore' : 'send',
    senderPattern: row.sender_pattern || '',
    recipientPattern: row.recipient_pattern || '',
    subjectPattern: row.subject_pattern || '',
    contentPattern: row.content_pattern || '',
    targetChannelIds: parseJsonNumberArray(row.target_channel_ids),
    targetEmail: row.target_email || '',
    targetFromAddress: row.target_from_address || '',
    targetForwardType: ['cf', 'resend'].includes(row.target_forward_type) ? row.target_forward_type : 'internal',
    isDefault: row.is_default === 1,
    defaultMode: row.default_mode === 'always' ? 'always' : 'unmatched',
    channelType: row.channel_type || 'dingtalk',
    channelUrl: row.channel_url || '',
    channelSecret: row.channel_secret || ''
  }));

  return {
    channels: mapped
      .filter((item) => item.category === 'channel')
      .map(({ category, matchMode, senderPattern, recipientPattern, subjectPattern, contentPattern, targetChannelIds, targetEmail, targetFromAddress, targetForwardType, isDefault, defaultMode, channelType, channelUrl, channelSecret, ...item }) => ({
        ...item,
        type: channelType,
        url: channelUrl,
        secret: channelSecret
      })),
    mailChannels: mapped
      .filter((item) => item.category === 'mail_channel')
      .map(({ category, enabled, matchMode, senderPattern, recipientPattern, subjectPattern, contentPattern, targetChannelIds, targetEmail, targetFromAddress, targetForwardType, isDefault, defaultMode, channelType, channelUrl, channelSecret, ...item }) => ({
        ...item,
        type: 'resend',
        domain: channelUrl,
        token: maskSecretValue(channelSecret)
      })),
    webhookRules: mapped
      .filter((item) => item.category === 'webhook' && !item.isDefault)
      .map(({ category, targetEmail, targetFromAddress, targetForwardType, isDefault, defaultMode, channelType, channelUrl, channelSecret, ...item }) => item),
    emailForwardRules: mapped
      .filter((item) => item.category === 'email_forward' && !item.isDefault)
      .map(({ category, targetChannelIds, isDefault, defaultMode, channelType, channelUrl, channelSecret, ...item }) => item),
    defaultWebhookRule: mapped
      .filter((item) => item.category === 'webhook' && item.isDefault)
      .map(({ category, targetEmail, targetFromAddress, targetForwardType, isDefault, channelType, channelUrl, channelSecret, ...item }) => item)[0] || null,
    defaultEmailForwardRule: mapped
      .filter((item) => item.category === 'email_forward' && item.isDefault)
      .map(({ category, targetChannelIds, isDefault, channelType, channelUrl, channelSecret, ...item }) => item)[0] || null
  };
};

const normalizeRoutingItem = (item: any) => {
  const category = item.category;
  if (!['channel', 'mail_channel', 'webhook', 'email_forward'].includes(category)) {
    throw new HTTPException(400, { message: '配置类型无效' });
  }

  const name = typeof item.name === 'string' ? item.name.trim() : '';
  if (!name) {
    throw new HTTPException(400, { message: '名称不能为空' });
  }

  const isChannel = category === 'channel';
  const isMailChannel = category === 'mail_channel';
  const channelUrl = isChannel && typeof item.url === 'string' ? item.url.trim() : '';
  const mailChannelDomain = isMailChannel && typeof item.domain === 'string'
    ? item.domain.trim().toLowerCase().replace(/^@+/, '')
    : '';
  const mailChannelToken = isMailChannel && typeof item.token === 'string' ? item.token.trim() : '';
  if (isChannel && !channelUrl) {
    throw new HTTPException(400, { message: '通道 URL 不能为空' });
  }
  if (isMailChannel && !/^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(mailChannelDomain)) {
    throw new HTTPException(400, { message: '邮件通道发件域名无效' });
  }
  if (isMailChannel && !mailChannelToken) {
    throw new HTTPException(400, { message: '邮件通道 API Key 不能为空' });
  }

  const targetChannelIds = category === 'webhook'
    ? (Array.isArray(item.targetChannelIds) ? item.targetChannelIds.map(Number).filter(Number.isInteger) : [])
    : [];
  const action = category === 'webhook' && item.action === 'ignore' ? 'ignore' : 'send';
  const targetEmail = category === 'email_forward' && typeof item.targetEmail === 'string' ? item.targetEmail.trim() : '';
  const targetFromAddress = category === 'email_forward' && typeof item.targetFromAddress === 'string' ? item.targetFromAddress.trim() : '';
  const targetForwardType = category === 'email_forward' && ['internal', 'cf', 'resend'].includes(item.targetForwardType)
    ? item.targetForwardType
    : 'internal';

  if (
    category === 'webhook' &&
    action === 'send' &&
    (!item.isDefault || item.enabled !== false) &&
    targetChannelIds.length === 0
  ) {
    throw new HTTPException(400, { message: '至少选择一个 Webhook 通道' });
  }
  if (category === 'email_forward' && !targetEmail) {
    throw new HTTPException(400, { message: '转发邮箱不能为空' });
  }
  if (category === 'email_forward' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(targetFromAddress)) {
    throw new HTTPException(400, { message: '转发发件人邮箱格式无效' });
  }

  return {
    clientId: Number(item.id),
    category,
    name,
    enabled: item.enabled === false ? 0 : 1,
    matchMode: item.matchMode === 'any' ? 'any' : 'all',
    action,
    senderPattern: typeof item.senderPattern === 'string' ? item.senderPattern.trim() : '',
    recipientPattern: typeof item.recipientPattern === 'string' ? item.recipientPattern.trim() : '',
    subjectPattern: typeof item.subjectPattern === 'string' ? item.subjectPattern.trim() : '',
    contentPattern: typeof item.contentPattern === 'string' ? item.contentPattern.trim() : '',
    targetChannelIds,
    targetEmail,
    targetFromAddress,
    targetForwardType,
    isDefault: item.isDefault ? 1 : 0,
    defaultMode: item.isDefault ? (item.defaultMode === 'always' ? 'always' : 'unmatched') : null,
    channelType: isChannel && ['dingtalk', 'feishu', 'bark'].includes(item.type)
      ? item.type
      : isMailChannel ? 'resend' : null,
    channelUrl: isMailChannel ? mailChannelDomain : channelUrl,
    channelSecret: isMailChannel ? mailChannelToken : (isChannel && typeof item.secret === 'string' ? item.secret.trim() : '')
  };
};

type NormalizedRoutingItem = ReturnType<typeof normalizeRoutingItem>;

const routingItemColumns = [
  'category',
  'name',
  'enabled',
  'match_mode',
  'action',
  'sender_pattern',
  'recipient_pattern',
  'subject_pattern',
  'content_pattern',
  'target_channel_ids',
  'target_email',
  'target_from_address',
  'target_forward_type',
  'is_default',
  'default_mode',
  'channel_type',
  'channel_url',
  'channel_secret'
];

const buildRoutingItemValues = (item: NormalizedRoutingItem, targetChannelIds?: number[]) => [
  item.category,
  item.name,
  item.enabled,
  item.matchMode,
  item.action,
  item.senderPattern,
  item.recipientPattern,
  item.subjectPattern,
  item.contentPattern,
  JSON.stringify(targetChannelIds || item.targetChannelIds),
  item.targetEmail,
  item.targetFromAddress,
  item.targetForwardType,
  item.isDefault,
  item.defaultMode,
  item.channelType,
  item.channelUrl,
  item.channelSecret
];

const upsertRoutingItem = async (
  db: D1Database,
  item: NormalizedRoutingItem,
  targetChannelIds?: number[]
) => {
  const values = buildRoutingItemValues(item, targetChannelIds);

  if (!Number.isInteger(item.clientId) || item.clientId <= 0) {
    const placeholders = routingItemColumns.map(() => '?').join(', ');
    const result = await db.prepare(`
      INSERT INTO routing_rules (${routingItemColumns.join(', ')})
      VALUES (${placeholders})
    `).bind(...values).run();

    return Number(result.meta?.last_row_id);
  }

  const placeholders = ['?', ...routingItemColumns.map(() => '?')].join(', ');
  const updateAssignments = routingItemColumns
    .map((column) => `${column} = excluded.${column}`)
    .join(', ');

  await db.prepare(`
    INSERT INTO routing_rules (
      id,
      ${routingItemColumns.join(', ')}
    ) VALUES (${placeholders})
    ON CONFLICT(id) DO UPDATE SET
      ${updateAssignments}
  `).bind(
    item.clientId,
    ...values
  ).run();

  return item.clientId;
};

const saveRoutingItem = async (db: D1Database, item: NormalizedRoutingItem, targetChannelIds?: number[]) => {
  const values = buildRoutingItemValues(item, targetChannelIds);

  if (Number.isInteger(item.clientId) && item.clientId > 0) {
    const assignments = routingItemColumns.map((column) => `${column} = ?`).join(', ');
    await db.prepare(`
      UPDATE routing_rules
      SET ${assignments}
      WHERE id = ?
    `).bind(...values, item.clientId).run();

    return item.clientId;
  }

  const placeholders = routingItemColumns.map(() => '?').join(', ');
  const result = await db.prepare(`
    INSERT INTO routing_rules (${routingItemColumns.join(', ')})
    VALUES (${placeholders})
  `).bind(...values).run();

  return Number(result.meta?.last_row_id);
};

api.post('/routing', jwtAuthMiddleware, async (c) => {
  try {
    await ensureRoutingRulesActionColumn(c.env.DB);
    const body = await c.req.json().catch(() => ({}));
    const action = body.action || 'list';

    if (action === 'list') {
      return c.json<ApiResponse>({
        success: true,
        data: buildRoutingPayload(await selectRoutingRows(c.env.DB))
      });
    }

    if (action === 'delete') {
      const id = Number(body.id);
      if (!Number.isInteger(id)) {
        throw new HTTPException(400, { message: 'ID无效' });
      }

      await c.env.DB.prepare('DELETE FROM routing_rules WHERE id = ?').bind(id).run();
      await bumpChangeSignals(c.env.DB, ['routing_config', 'dashboard']);
      return c.json<ApiResponse>({
        success: true,
        message: '消息路由配置已删除',
        data: buildRoutingPayload(await selectRoutingRows(c.env.DB))
      });
    }

    if (action === 'replace') {
      const config = body.config || {};
      const channels: NormalizedRoutingItem[] = Array.isArray(config.channels)
        ? config.channels.map((item: any) => normalizeRoutingItem({ ...item, category: 'channel' }))
        : [];
      const mailChannels: NormalizedRoutingItem[] = Array.isArray(config.mailChannels)
        ? config.mailChannels.map((item: any) => normalizeRoutingItem({ ...item, category: 'mail_channel' }))
        : [];
      const existingRoutingRows = await selectRoutingRows(c.env.DB);
      const existingMailChannelSecrets = new Map(
        existingRoutingRows
          .filter((row: any) => row.category === 'mail_channel')
          .map((row: any) => [Number(row.id), String(row.channel_secret || '')])
      );
      const existingMailChannelSecretsByDomain = new Map(
        existingRoutingRows
          .filter((row: any) => row.category === 'mail_channel' && row.channel_type === 'resend')
          .map((row: any) => [String(row.channel_url || '').trim().toLowerCase(), String(row.channel_secret || '')])
      );
      mailChannels.forEach((channel) => {
        if (channel.channelSecret.includes('*')) {
          const existingSecret = existingMailChannelSecrets.get(channel.clientId) || existingMailChannelSecretsByDomain.get(channel.channelUrl);
          if (!existingSecret) {
            throw new HTTPException(400, { message: `邮件通道 ${channel.name} 的 API Key 已脱敏，请重新输入完整 API Key` });
          }
          channel.channelSecret = existingSecret;
        }
      });
      const webhookRules: NormalizedRoutingItem[] = Array.isArray(config.webhookRules)
        ? config.webhookRules.map((item: any) => normalizeRoutingItem({ ...item, category: 'webhook' }))
        : [];
      const emailForwardRules: NormalizedRoutingItem[] = Array.isArray(config.emailForwardRules)
        ? config.emailForwardRules.map((item: any) => normalizeRoutingItem({ ...item, category: 'email_forward' }))
        : [];
      const defaultWebhookRule = config.defaultWebhookRule
        ? normalizeRoutingItem({ ...config.defaultWebhookRule, category: 'webhook', isDefault: true })
        : null;
      const defaultEmailForwardRule = config.defaultEmailForwardRule
        ? normalizeRoutingItem({ ...config.defaultEmailForwardRule, category: 'email_forward', isDefault: true })
        : null;

      const requiresWebhookChannel = Boolean(defaultWebhookRule?.enabled) || webhookRules.some(
        (rule) => rule.enabled === 1 && rule.action === 'send'
      );
      if (channels.length === 0 && requiresWebhookChannel) {
        throw new HTTPException(400, { message: '至少保留一个 Webhook 通道' });
      }

      const channelClientIds = new Set(channels.map((item) => item.clientId).filter(Number.isInteger));
      const assertKnownChannelIds = (ids: number[]) => {
        if (ids.some((id) => !channelClientIds.has(id))) {
          throw new HTTPException(400, { message: '规则引用了不存在的 Webhook 通道' });
        }
      };

      webhookRules
        .filter((rule) => rule.enabled === 1 && rule.action === 'send')
        .forEach((rule) => assertKnownChannelIds(rule.targetChannelIds));
      if (defaultWebhookRule && (defaultWebhookRule.enabled === 1 || defaultWebhookRule.targetChannelIds.length > 0)) {
        assertKnownChannelIds(defaultWebhookRule.targetChannelIds);
      }

      const channelIdMap = new Map<number, number>();
      const retainedIds: number[] = [];
      for (const channel of channels) {
        const savedId = await upsertRoutingItem(c.env.DB, channel);
        channelIdMap.set(channel.clientId, savedId);
        retainedIds.push(savedId);
      }
      for (const channel of mailChannels) {
        retainedIds.push(await upsertRoutingItem(c.env.DB, channel));
      }

      const remapChannelIds = (ids: number[]) => ids.map((id) => channelIdMap.get(id)).filter((id): id is number => Number.isInteger(id));

      if (defaultWebhookRule) {
        retainedIds.push(await upsertRoutingItem(c.env.DB, defaultWebhookRule, remapChannelIds(defaultWebhookRule.targetChannelIds)));
      }
      if (defaultEmailForwardRule) {
        retainedIds.push(await upsertRoutingItem(c.env.DB, defaultEmailForwardRule));
      }
      for (const rule of webhookRules) {
        retainedIds.push(await upsertRoutingItem(c.env.DB, rule, remapChannelIds(rule.targetChannelIds)));
      }
      for (const rule of emailForwardRules) {
        retainedIds.push(await upsertRoutingItem(c.env.DB, rule));
      }

      const uniqueRetainedIds = Array.from(new Set(retainedIds)).filter((id) => Number.isInteger(id) && id > 0);
      if (uniqueRetainedIds.length > 0) {
        const placeholders = uniqueRetainedIds.map(() => '?').join(',');
        await c.env.DB.prepare(`DELETE FROM routing_rules WHERE id NOT IN (${placeholders})`).bind(...uniqueRetainedIds).run();
      }

      await bumpChangeSignals(c.env.DB, ['routing_config', 'dashboard']);
      return c.json<ApiResponse>({
        success: true,
        message: '消息路由配置已保存',
        data: buildRoutingPayload(await selectRoutingRows(c.env.DB))
      });
    }

    if (action === 'save') {
      const item = body.item || {};
      const normalized = normalizeRoutingItem(item);

      if (normalized.category === 'mail_channel' && normalized.channelSecret.includes('*')) {
        const existing = await c.env.DB.prepare(`
          SELECT channel_secret
          FROM routing_rules
          WHERE id = ?
            AND category = 'mail_channel'
          LIMIT 1
        `).bind(normalized.clientId).first();
        const existingSecret = typeof existing?.channel_secret === 'string' ? existing.channel_secret.trim() : '';
        if (!existingSecret) {
          throw new HTTPException(400, { message: '邮件通道 API Key 已脱敏，请重新输入完整 API Key' });
        }
        normalized.channelSecret = existingSecret;
      }

      await saveRoutingItem(c.env.DB, normalized);
      await bumpChangeSignals(c.env.DB, ['routing_config', 'dashboard']);
      return c.json<ApiResponse>({
        success: true,
        message: '消息路由配置已保存',
        data: buildRoutingPayload(await selectRoutingRows(c.env.DB))
      });
    }

    throw new HTTPException(400, { message: '操作无效' });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[消息路由] 统一接口失败:', error);
    throw new HTTPException(500, { message: '消息路由操作失败' });
  }
});

// ==================== 系统相关 ====================
api.route('/system', systemRoutes);

// ==================== 仪表板和转发日志 ====================
api.route('/dashboard', dashboardRoutes);

// ==================== 工具相关（统一管理调试/工具功能） ====================
api.route('/tools', toolsRoutes);

export { api };
