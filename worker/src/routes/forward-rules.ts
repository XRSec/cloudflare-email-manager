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
    if (!ruleData.rule_name || !ruleData.webhook_url) {
      throw new HTTPException(400, { message: '规则名称和Webhook URL不能为空' });
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
