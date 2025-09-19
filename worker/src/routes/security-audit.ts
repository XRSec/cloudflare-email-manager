/**
 * 安全审计 API 路由
 */

import { Hono } from 'hono';
import { jwtAuthMiddleware, adminAuthMiddleware } from '../middleware/auth';
import { getSecurityAuditRecords, getAttackStats } from '../services/security-audit';
import type { Env } from '../types';

const app = new Hono<{ Bindings: Env }>();

// 应用 JWT 中间件
app.use('*', jwtAuthMiddleware);

/**
 * 获取安全审计记录（管理员专用）
 */
app.get('/records', adminAuthMiddleware, async (c) => {
  try {
    const {
      user_id,
      action_type,
      attack_type,
      start_date,
      end_date,
      page = '1',
      limit = '20'
    } = c.req.query();

    const params = {
      user_id: user_id ? parseInt(user_id) : undefined,
      action_type,
      attack_type,
      start_date,
      end_date,
      page: parseInt(page),
      limit: parseInt(limit)
    };

    const result = await getSecurityAuditRecords(c.env.DB, params);

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('[安全审计API] 获取记录失败:', error);
    return c.json({ success: false, message: '获取安全审计记录失败' }, 500);
  }
});

/**
 * 获取攻击统计（管理员专用）
 */
app.get('/attack-stats', adminAuthMiddleware, async (c) => {
  try {
    const { days = '7' } = c.req.query();
    const daysNum = parseInt(days);

    if (isNaN(daysNum) || daysNum < 1 || daysNum > 30) {
      return c.json({ success: false, message: '天数参数无效，范围1-30天' }, 400);
    }

    const stats = await getAttackStats(c.env.DB, daysNum);

    return c.json({
      success: true,
      data: stats
    });
  } catch (error) {
    console.error('[安全审计API] 获取攻击统计失败:', error);
    return c.json({ success: false, message: '获取攻击统计失败' }, 500);
  }
});

/**
 * 获取用户的安全审计记录（用户只能看自己的）
 */
app.get('/user-records', async (c) => {
  try {
    const payload = c.get('jwtPayload');
    if (!payload) {
      return c.json({ success: false, message: '未提供认证令牌' }, 401);
    }

    const {
      action_type,
      attack_type,
      start_date,
      end_date,
      page = '1',
      limit = '20'
    } = c.req.query();

    const params = {
      user_id: payload.user_id,
      action_type,
      attack_type,
      start_date,
      end_date,
      page: parseInt(page),
      limit: parseInt(limit)
    };

    const result = await getSecurityAuditRecords(c.env.DB, params);

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('[安全审计API] 获取用户记录失败:', error);
    return c.json({ success: false, message: '获取用户安全记录失败' }, 500);
  }
});

export default app;
