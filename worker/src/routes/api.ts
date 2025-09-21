/**
 * 统一API路由 - 符合 api-doc.yml 规范
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware, adminAuthMiddleware } from '../middleware/auth';
import { getPaginationParams } from '../config/constants';
import { debugLog, errorLog } from '../utils/debug';

// 导入各个功能模块
import { authRoutes } from './auth';
import { userRoutes } from './user';
import { adminRoutes } from './admin';
import { systemRoutes } from './system';
import { mailboxRoutes } from './mailbox';
import { forwardRuleRoutes } from './forward-rules';
import mailboxHistoryRoutes from './mailbox-history';
import userInfoRoutes from './user-info';
import securityAuditRoutes from './security-audit';
import { cache } from './cache';
import { databaseRoutes } from './database';

// 导入服务
import {
  getAllEmails,
  getEmailById,
  deleteEmail,
  getEmailAttachments,
  getAttachmentById,
  sendEmail
} from '../services/email';
import { findUserById } from '../services/user';
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
 */
api.get('/emails', jwtAuthMiddleware, async (c) => {
  try {
    const payload = c.get('jwtPayload');

    // 解析查询参数
    const queryParams: EmailQueryParams = {
      ...getPaginationParams(c.req.query()),
      search: c.req.query('search'),
      status: c.req.query('status'),
      scope: c.req.query('scope')
    };

    // 检查权限：普通用户只能获取自己的邮件，管理员可以获取全部
    const isAdmin = payload.user_type === 'admin';
    const scope = queryParams.scope;

    if (scope === 'all' && !isAdmin) {
      throw new HTTPException(403, { message: '权限不足' });
    }

    // 根据权限和scope决定查询范围
    const userId = scope === 'all' && isAdmin ? undefined : payload.user_id;
    const result = await getAllEmails(c.env.DB, userId, queryParams);

    return c.json<ApiResponse>({
      success: true,
      data: {
        total: result.total,
        items: result.emails
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
 * 获取邮件详情
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

    // 检查权限：普通用户只能查看自己的邮件
    if (payload.user_type !== 'admin' && email.user_id !== payload.user_id) {
      throw new HTTPException(403, { message: '无权访问此邮件' });
    }

    // 获取附件列表
    const attachments = await getEmailAttachments(c.env.DB, parseInt(emailId));

    return c.json<ApiResponse>({
      success: true,
      data: {
        ...email,
        attachments
      }
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

    // 检查权限：普通用户只能删除自己的邮件
    if (payload.user_type !== 'admin' && email.user_id !== payload.user_id) {
      throw new HTTPException(403, { message: '无权删除此邮件' });
    }

    await deleteEmail(c.env.DB, c.env.R2, parseInt(emailId));

    return c.json<ApiResponse>({
      success: true,
      message: '邮件删除成功'
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

    // 检查权限：普通用户只能下载自己邮件的附件
    if (payload.user_type !== 'admin' && email.user_id !== payload.user_id) {
      throw new HTTPException(403, { message: '无权下载此附件' });
    }

    const attachment = await getAttachmentById(c.env.DB, parseInt(attachmentId));
    if (!attachment) {
      throw new HTTPException(404, { message: '附件不存在' });
    }

    // 从R2获取文件
    const object = await c.env.R2.get(attachment.r2_key);
    if (!object) {
      throw new HTTPException(404, { message: '附件文件不存在' });
    }

    return new Response(object.body as any, {
      headers: {
        'Content-Type': attachment.content_type,
        'Content-Disposition': `attachment; filename="${encodeURIComponent(attachment.filename)}"`,
        'Content-Length': attachment.size_bytes.toString(),
      }
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

    // 检查是否允许用户发送邮件
    const config = await getSystemConfig(c.env.DB);
    if (payload.user_type !== 'admin' && !config.allow_user_send) {
      throw new HTTPException(403, { message: '系统不允许普通用户发送邮件' });
    }

    // 发送邮件
    const { getPrimaryDomain } = await import('../services/settings');
    const primaryDomain = await getPrimaryDomain(c.env.DB);
    await sendEmail(c.env, {
      to,
      from: from || config.admin_email || 'noreply@' + primaryDomain,
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

// ==================== 邮箱相关 ====================
api.route('/mailboxes', mailboxRoutes);

// ==================== 邮箱历史相关 ====================
api.route('/mailbox-history', mailboxHistoryRoutes);

// ==================== 用户信息相关 ====================
api.route('/user-info', userInfoRoutes);

// ==================== 安全审计相关 ====================
api.route('/security-audit', securityAuditRoutes);

// ==================== 转发规则相关 ====================
api.route('/forward-rules', forwardRuleRoutes);

// ==================== 系统相关 ====================
api.route('/system', systemRoutes);

// ==================== 管理员相关 ====================
api.route('/admin', adminRoutes);


// ==================== 缓存管理 ====================
api.route('/cache', cache);

// ==================== 数据库管理 ====================
api.route('/database', databaseRoutes);

export { api };
