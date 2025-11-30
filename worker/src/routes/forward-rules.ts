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
import type { Env, ApiResponse, ForwardRule } from '../types';

const forwardRuleRoutes = new Hono<{ Bindings: Env }>();

// 仅允许已认证的管理员访问
forwardRuleRoutes.use('*', jwtAuthMiddleware);
forwardRuleRoutes.use('*', adminAuthMiddleware);

/**
 * 获取转发规则列表
 * GET /api/forward-rules
 */
forwardRuleRoutes.get('/', async (c) => {
  try {
    const queryParams = getPaginationParams(c.req.query());

    const rules = await getForwardRules(c.env.DB, queryParams);

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
    const ruleData = await c.req.json() as Omit<ForwardRule, 'id' | 'created_at' | 'updated_at'>;

    // 验证必填字段
    if (!ruleData.rule_name) {
      throw new HTTPException(400, { message: '规则名称不能为空' });
    }

    // 如果提供了 webhooks，验证每个 webhook 的 URL
    if (ruleData.webhooks && ruleData.webhooks.length > 0) {
      for (const webhook of ruleData.webhooks) {
        if (!webhook.webhook_url) {
          throw new HTTPException(400, { message: 'Webhook URL 不能为空' });
        }
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
 * 获取默认转发渠道配置（从users表读取）
 * GET /api/forward-rules/default-webhook
 * 注意：此路由必须在 /:id 路由之前，否则会被 /:id 捕获
 */
forwardRuleRoutes.get('/default-webhook', async (c) => {
  try {
    const user = c.get('jwtPayload');
    const userId = user.user_id;

    // 直接从 users 表读取 webhook 配置
    const userConfig = await c.env.DB.prepare(`
      SELECT webhook_url, webhook_secret, webhook_type, webhook_custom_message 
      FROM users 
      WHERE id = ?
    `).bind(userId).first();

    return c.json<ApiResponse>({
      success: true,
      data: {
        default_webhook_url: (userConfig?.webhook_url as string) || '',
        default_webhook_secret: (userConfig?.webhook_secret as string) || '',
        default_webhook_type: (userConfig?.webhook_type as string) || 'custom',
        default_webhook_custom_message: (userConfig?.webhook_custom_message as string) || ''
      }
    });
  } catch (error) {
    errorLog('[默认转发渠道] 获取失败:', error);
    throw new HTTPException(500, { message: '获取默认转发渠道配置失败' });
  }
});

/**
 * 更新默认转发渠道配置（更新users表）
 * PUT /api/forward-rules/default-webhook
 * 注意：此路由必须在 /:id 路由之前，否则会被 /:id 捕获
 */
forwardRuleRoutes.put('/default-webhook', async (c) => {
  try {
    const user = c.get('jwtPayload');
    const userId = user.user_id;

    const updates = await c.req.json() as {
      default_webhook_url?: string;
      default_webhook_secret?: string;
      default_webhook_type?: 'dingtalk' | 'feishu' | 'bark' | 'custom';
      default_webhook_custom_message?: string;
    };

    // 直接更新 users 表
    const setParts: string[] = [];
    const values: any[] = [];

    if (updates.default_webhook_url !== undefined) {
      setParts.push('webhook_url = ?');
      values.push(updates.default_webhook_url || null);
    }
    if (updates.default_webhook_secret !== undefined) {
      setParts.push('webhook_secret = ?');
      values.push(updates.default_webhook_secret || null);
    }
    if (updates.default_webhook_type !== undefined) {
      setParts.push('webhook_type = ?');
      values.push(updates.default_webhook_type || 'custom');
    }
    if (updates.default_webhook_custom_message !== undefined) {
      setParts.push('webhook_custom_message = ?');
      values.push(updates.default_webhook_custom_message || null);
    }

    if (setParts.length > 0) {
      setParts.push('updated_at = CURRENT_TIMESTAMP');
      values.push(userId);

      const sql = `UPDATE users SET ${setParts.join(', ')} WHERE id = ?`;
      const result = await c.env.DB.prepare(sql).bind(...values).run();

      if (!result.success) {
        throw new Error('Failed to update default webhook config');
      }
    }

    return c.json<ApiResponse>({
      success: true,
      message: '默认转发渠道配置更新成功'
    });
  } catch (error) {
    errorLog('[默认转发渠道] 更新失败:', error);
    throw new HTTPException(500, { message: '更新默认转发渠道配置失败' });
  }
});

/**
 * 获取转发规则详情
 * GET /api/forward-rules/{id}
 */
forwardRuleRoutes.get('/:id', async (c) => {
  try {
    const ruleId = parseInt(c.req.param('id'));

    if (isNaN(ruleId)) {
      throw new HTTPException(400, { message: '无效的规则ID' });
    }

    const rule = await getForwardRuleById(c.env.DB, ruleId);
    if (!rule) {
      throw new HTTPException(404, { message: '转发规则不存在' });
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
    const ruleId = parseInt(c.req.param('id'));

    if (isNaN(ruleId)) {
      throw new HTTPException(400, { message: '无效的规则ID' });
    }

    const rule = await getForwardRuleById(c.env.DB, ruleId);
    if (!rule) {
      throw new HTTPException(404, { message: '转发规则不存在' });
    }

    const updates = await c.req.json() as Partial<ForwardRule>;

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
    const ruleId = parseInt(c.req.param('id'));

    if (isNaN(ruleId)) {
      throw new HTTPException(400, { message: '无效的规则ID' });
    }

    const rule = await getForwardRuleById(c.env.DB, ruleId);
    if (!rule) {
      throw new HTTPException(404, { message: '转发规则不存在' });
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
