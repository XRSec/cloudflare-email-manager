/**
 * 用户信息查询 API 路由
 */

import { Hono } from 'hono';
import { jwtAuthMiddleware } from '../middleware/auth';
import type { Env } from '../types';

const app = new Hono<{ Bindings: Env }>();

// 应用 JWT 中间件
app.use('*', jwtAuthMiddleware);

/**
 * 根据用户ID获取用户名
 */
app.get('/username/:userId', async (c) => {
  try {
    const userId = parseInt(c.req.param('userId'));

    if (isNaN(userId)) {
      return c.json({ success: false, message: '无效的用户ID' }, 400);
    }

    const result = await c.env.DB.prepare(`
            SELECT id, username, user_type
            FROM users 
            WHERE id = ? AND status = 1
        `).bind(userId).first();

    if (!result) {
      return c.json({ success: false, message: '用户不存在' }, 404);
    }

    return c.json({
      success: true,
      data: {
        id: (result as any).id,
        username: (result as any).username,
        user_type: (result as any).user_type
      }
    });
  } catch (error) {
    const { errorLog } = await import('../utils/debug');
    errorLog('用户信息API', '获取用户名失败:', error);
    return c.json({ success: false, message: '获取用户名失败' }, 500);
  }
});

/**
 * 批量获取用户名
 */
app.post('/usernames', async (c) => {
  try {
    const { user_ids } = await c.req.json();

    if (!Array.isArray(user_ids) || user_ids.length === 0) {
      return c.json({ success: false, message: '用户ID列表不能为空' }, 400);
    }

    // 验证所有用户ID都是数字
    const validUserIds = user_ids.filter(id => !isNaN(parseInt(id)));
    if (validUserIds.length !== user_ids.length) {
      return c.json({ success: false, message: '包含无效的用户ID' }, 400);
    }

    const placeholders = validUserIds.map(() => '?').join(',');
    const result = await c.env.DB.prepare(`
            SELECT id, username, user_type
            FROM users 
            WHERE id IN (${placeholders}) AND status = 1
        `).bind(...validUserIds).all();

    const userMap: Record<number, any> = {};
    result.results.forEach((user: any) => {
      userMap[user.id] = {
        id: user.id,
        username: user.username,
        user_type: user.user_type
      };
    });

    return c.json({
      success: true,
      data: userMap
    });
  } catch (error) {
    const { errorLog } = await import('../utils/debug');
    errorLog('用户信息API', '批量获取用户名失败:', error);
    return c.json({ success: false, message: '批量获取用户名失败' }, 500);
  }
});

export default app;
