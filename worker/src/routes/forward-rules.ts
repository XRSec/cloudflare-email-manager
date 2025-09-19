/**
 * 转发规则相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware, adminAuthMiddleware } from '../middleware/auth';
import { getPaginationParams } from '../config/constants';
import { debugLog, errorLog } from '../utils/debug';
import {
  getForwardRules,
  getForwardRuleById,
  createForwardRule,
  updateForwardRule,
  deleteForwardRule
} from '../services/webhook';
import { findMailboxesByUserId } from '../services/mailbox';
import type { Env, ApiResponse, ForwardRule } from '../types';

const forwardRuleRoutes = new Hono<{ Bindings: Env }>();

// 应用JWT认证中间件
forwardRuleRoutes.use('*', jwtAuthMiddleware);

/**
 * 获取转发规则列表
 * GET /api/forward-rules
 */
forwardRuleRoutes.get('/', async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const queryParams = getPaginationParams(c.req.query());

    const rules = await getForwardRules(c.env.DB, queryParams);

    // 普通用户只能看到与自己邮箱相关的规则
    if (payload.user_type !== 'admin') {
      const userMailboxes = await findMailboxesByUserId(c.env.DB, payload.user_id);
      const userEmails = userMailboxes.map(mb => mb.email_address);

      const userRules = rules.filter(rule => {
        // 如果规则有收件人过滤，检查是否包含用户的邮箱
        if (rule.recipient_filter) {
          return userEmails.some(email => email.includes(rule.recipient_filter!));
        }
        return true; // 没有收件人过滤的规则，用户可以看到
      });

      return c.json<ApiResponse>({
        success: true,
        data: {
          total: userRules.length,
          items: userRules
        }
      });
    }

    return c.json<ApiResponse>({
      success: true,
      data: {
        total: rules.length,
        items: rules
      }
    });
  } catch (error) {
    errorLog('[转发规则列表] 获取失败:', error);
    throw new HTTPException(500, { message: '获取转发规则失败' });
  }
});

/**
 * 创建转发规则
 * POST /api/forward-rules
 */
forwardRuleRoutes.post('/', async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const ruleData = await c.req.json() as Omit<ForwardRule, 'id' | 'created_at' | 'updated_at'>;

    // 验证必填字段
    if (!ruleData.rule_name || !ruleData.webhook_url) {
      throw new HTTPException(400, { message: '规则名称和Webhook URL不能为空' });
    }

    // 普通用户需要验证收件人过滤是否包含自己的邮箱
    if (payload.user_type !== 'admin' && ruleData.recipient_filter) {
      const userMailboxes = await findMailboxesByUserId(c.env.DB, payload.user_id);
      const userEmails = userMailboxes.map(mb => mb.email_address);
      const hasUserEmail = userEmails.some(email => email.includes(ruleData.recipient_filter!));

      if (!hasUserEmail) {
        throw new HTTPException(400, { message: '收件人过滤必须包含您的邮箱地址' });
      }
    }

    const rule = await createForwardRule(c.env.DB, ruleData);

    return c.json<ApiResponse>({
      success: true,
      message: '转发规则创建成功',
      data: { rule }
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[创建转发规则] 失败:', error);
    throw new HTTPException(500, { message: '创建转发规则失败' });
  }
});

/**
 * 获取转发规则详情
 * GET /api/forward-rules/{id}
 */
forwardRuleRoutes.get('/:id', async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const ruleId = parseInt(c.req.param('id'));

    if (isNaN(ruleId)) {
      throw new HTTPException(400, { message: '无效的规则ID' });
    }

    const rule = await getForwardRuleById(c.env.DB, ruleId);
    if (!rule) {
      throw new HTTPException(404, { message: '转发规则不存在' });
    }

    // 普通用户需要验证权限
    if (payload.user_type !== 'admin' && rule.recipient_filter) {
      const userMailboxes = await findMailboxesByUserId(c.env.DB, payload.user_id);
      const userEmails = userMailboxes.map(mb => mb.email_address);
      const hasUserEmail = userEmails.some(email => email.includes(rule.recipient_filter!));

      if (!hasUserEmail) {
        throw new HTTPException(403, { message: '您没有权限访问此转发规则' });
      }
    }

    return c.json<ApiResponse>({
      success: true,
      data: { rule }
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[转发规则详情] 获取失败:', error);
    throw new HTTPException(500, { message: '获取转发规则失败' });
  }
});

/**
 * 更新转发规则
 * PUT /api/forward-rules/{id}
 */
forwardRuleRoutes.put('/:id', async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const ruleId = parseInt(c.req.param('id'));

    if (isNaN(ruleId)) {
      throw new HTTPException(400, { message: '无效的规则ID' });
    }

    const rule = await getForwardRuleById(c.env.DB, ruleId);
    if (!rule) {
      throw new HTTPException(404, { message: '转发规则不存在' });
    }

    // 普通用户需要验证权限
    if (payload.user_type !== 'admin' && rule.recipient_filter) {
      const userMailboxes = await findMailboxesByUserId(c.env.DB, payload.user_id);
      const userEmails = userMailboxes.map(mb => mb.email_address);
      const hasUserEmail = userEmails.some(email => email.includes(rule.recipient_filter!));

      if (!hasUserEmail) {
        throw new HTTPException(403, { message: '您没有权限修改此转发规则' });
      }
    }

    const updates = await c.req.json() as Partial<ForwardRule>;

    // 普通用户需要验证更新后的收件人过滤
    if (payload.user_type !== 'admin' && updates.recipient_filter) {
      const userMailboxes = await findMailboxesByUserId(c.env.DB, payload.user_id);
      const userEmails = userMailboxes.map(mb => mb.email_address);
      const hasUserEmail = userEmails.some(email => email.includes(updates.recipient_filter!));

      if (!hasUserEmail) {
        throw new HTTPException(400, { message: '收件人过滤必须包含您的邮箱地址' });
      }
    }

    await updateForwardRule(c.env.DB, ruleId, updates);

    return c.json<ApiResponse>({
      success: true,
      message: '转发规则更新成功'
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[更新转发规则] 失败:', error);
    throw new HTTPException(500, { message: '更新转发规则失败' });
  }
});

/**
 * 删除转发规则
 * DELETE /api/forward-rules/{id}
 */
forwardRuleRoutes.delete('/:id', async (c) => {
  try {
    const payload = c.get('jwtPayload');
    const ruleId = parseInt(c.req.param('id'));

    if (isNaN(ruleId)) {
      throw new HTTPException(400, { message: '无效的规则ID' });
    }

    const rule = await getForwardRuleById(c.env.DB, ruleId);
    if (!rule) {
      throw new HTTPException(404, { message: '转发规则不存在' });
    }

    // 普通用户需要验证权限
    if (payload.user_type !== 'admin' && rule.recipient_filter) {
      const userMailboxes = await findMailboxesByUserId(c.env.DB, payload.user_id);
      const userEmails = userMailboxes.map(mb => mb.email_address);
      const hasUserEmail = userEmails.some(email => email.includes(rule.recipient_filter!));

      if (!hasUserEmail) {
        throw new HTTPException(403, { message: '您没有权限删除此转发规则' });
      }
    }

    await deleteForwardRule(c.env.DB, ruleId);

    return c.json<ApiResponse>({
      success: true,
      message: '转发规则删除成功'
    });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    errorLog('[删除转发规则] 失败:', error);
    throw new HTTPException(500, { message: '删除转发规则失败' });
  }
});

export { forwardRuleRoutes };
