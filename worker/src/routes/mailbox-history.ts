/**
 * 邮箱历史记录 API 路由
 */

import { Hono } from 'hono';
import { jwtAuthMiddleware } from '../middleware/auth';
import { getMailboxHistory, getUserMailboxHistory, getAllMailboxHistory } from '../services/mailbox-history';
import type { Env } from '../types';

const app = new Hono<{ Bindings: Env }>();

// 应用 JWT 中间件
app.use('*', jwtAuthMiddleware);

/**
 * 获取指定邮箱的历史记录
 */
app.get('/:mailboxId', async (c) => {
  try {
    const mailboxId = parseInt(c.req.param('mailboxId'));
    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '20');

    if (isNaN(mailboxId)) {
      return c.json({ success: false, message: '无效的邮箱ID' }, 400);
    }

    const result = await getMailboxHistory(c.env.DB, mailboxId, page, limit);

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('[邮箱历史API] 获取邮箱历史失败:', error);
    return c.json({ success: false, message: '获取邮箱历史失败' }, 500);
  }
});

/**
 * 获取当前用户的邮箱历史记录
 */
app.get('/user/me', async (c) => {
  try {
    const userId = c.get('jwtPayload').user_id;
    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '20');

    const result = await getUserMailboxHistory(c.env.DB, userId, page, limit);

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('[邮箱历史API] 获取用户邮箱历史失败:', error);
    return c.json({ success: false, message: '获取用户邮箱历史失败' }, 500);
  }
});

/**
 * 获取所有邮箱历史记录（管理员功能）
 */
app.get('/admin/all', async (c) => {
  try {
    const userType = c.get('jwtPayload').user_type;

    if (userType !== 'admin') {
      return c.json({ success: false, message: '权限不足' }, 403);
    }

    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '20');

    const result = await getAllMailboxHistory(c.env.DB, page, limit);

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('[邮箱历史API] 获取所有邮箱历史失败:', error);
    return c.json({ success: false, message: '获取所有邮箱历史失败' }, 500);
  }
});

export default app;
