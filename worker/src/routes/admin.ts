/**
 * 管理员相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware, adminAuthMiddleware } from '../middleware/auth';
import { getPaginationParams } from '../config/constants';
import { debugLog, errorLog } from '../utils/debug';
import {
    getAllUsers,
    createUser,
    deleteUser,
    findUserById,
    findUserByUsername,
    updateUserSettings
} from '../services/user';
import { getPrimaryDomain } from '../services/settings';
import {
    getAllEmails,
    getEmailById,
    deleteEmail
} from '../services/email';
import {
    getForwardRules,
    getForwardRuleById,
    createForwardRule,
    updateForwardRule,
    deleteForwardRule
} from '../services/webhook';
import {
    getAllSystemSettings,
    updateSystemConfig,
    getSystemConfig,
    refreshSystemSettings
} from '../services/settings';
import type {
    Env,
    ApiResponse,
    EmailQueryParams,
    ForwardRule,
    SystemConfig
} from '../types';

const adminRoutes = new Hono<{ Bindings: Env }>();

// 应用认证中间件
adminRoutes.use('*', jwtAuthMiddleware);
adminRoutes.use('*', adminAuthMiddleware);

/**
 * 获取所有邮件（管理员专用）
 * GET /api/admin/emails
 */
adminRoutes.get('/emails', async (c) => {
    try {
        const queryParams: EmailQueryParams = {
            ...getPaginationParams(c.req.query()),
            search: c.req.query('search'),
            status: c.req.query('status'),
            sender: c.req.query('sender'),
            subject: c.req.query('subject'),
            start_date: c.req.query('start_date'),
            end_date: c.req.query('end_date'),
            has_attachments: c.req.query('has_attachments') === 'true' ? true :
                c.req.query('has_attachments') === 'false' ? false : undefined,
            sort: c.req.query('sort') || 'received_at',
            order: (c.req.query('order') as 'asc' | 'desc') || 'desc'
        };

        const result = await getAllEmails(c.env.DB, undefined, queryParams);

        return c.json<ApiResponse>({
            success: true,
            data: {
                emails: result.emails,
                total: result.total,
                page: queryParams.page,
                limit: queryParams.limit,
                total_pages: Math.ceil(result.total / queryParams.limit!)
            }
        });
    } catch (error) {
        errorLog('[管理员邮件] 获取失败:', error);
        throw new HTTPException(500, { message: '获取邮件列表失败' });
    }
});

/**
 * 获取所有用户（管理员专用）
 * GET /api/admin/users
 */
adminRoutes.get('/users', async (c) => {
    try {
        const queryParams = getPaginationParams(c.req.query());
        const query = c.req.query('query');

        const result = await getAllUsers(
            c.env.DB,
            queryParams.page,
            queryParams.limit,
            { search: query }
        );

        // 获取主域名
        const primaryDomain = await getPrimaryDomain(c.env.DB);

        return c.json<ApiResponse>({
            success: true,
            data: {
                total: result.total,
                items: result.users.map(user => ({
                    id: user.id,
                    username: user.username,
                    email: user.username + '@' + primaryDomain,
                    user_type: user.user_type,
                    status: user.status,
                    created_at: user.created_at,
                    updated_at: user.updated_at
                })),
                page: queryParams.page,
                limit: queryParams.limit,
                total_pages: Math.ceil(result.total / queryParams.limit)
            }
        });
    } catch (error) {
        errorLog('[管理员用户] 获取失败:', error);
        throw new HTTPException(500, { message: '获取用户列表失败' });
    }
});

/**
 * 创建用户（管理员专用）
 * POST /api/admin/users
 */
adminRoutes.post('/users', async (c) => {
    try {
        const { username, password, email, user_type = 'user' } = await c.req.json();

        if (!username || !password || !email) {
            throw new HTTPException(400, { message: '用户名、密码和邮箱不能为空' });
        }

        if (!['user', 'admin'].includes(user_type)) {
            throw new HTTPException(400, { message: '无效的用户角色' });
        }

        // 检查用户名是否已存在
        const existingUser = await findUserByUsername(c.env.DB, username);
        if (existingUser) {
            throw new HTTPException(409, { message: '用户名已存在' });
        }

        const user = await createUser(c.env.DB, username, password, user_type);

        return c.json<ApiResponse>({
            success: true,
            message: '用户创建成功',
            data: {
                user: {
                    id: user.id,
                    username: user.username,
                    email: email,
                    user_type: user.user_type,
                    created_at: user.created_at
                }
            }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[创建用户] 失败:', error);
        throw new HTTPException(500, { message: '创建用户失败' });
    }
});

/**
 * 删除用户（管理员专用）
 * DELETE /api/admin/users/{id}
 */
adminRoutes.delete('/users/:id', async (c) => {
    try {
        const userId = parseInt(c.req.param('id'));

        if (isNaN(userId)) {
            throw new HTTPException(400, { message: '无效的用户ID' });
        }

        const userData = await findUserById(c.env.DB, userId);
        if (!userData) {
            throw new HTTPException(404, { message: '用户不存在' });
        }

        await deleteUser(c.env.DB, userId);

        return c.json<ApiResponse>({
            success: true,
            message: '用户删除成功'
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[删除用户] 失败:', error);
        throw new HTTPException(500, { message: '删除用户失败' });
    }
});

/**
 * 获取所有转发规则（管理员专用）
 * GET /api/admin/forward-rules
 */
adminRoutes.get('/forward-rules', async (c) => {
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
        errorLog('[管理员转发规则] 获取失败:', error);
        throw new HTTPException(500, { message: '获取转发规则失败' });
    }
});

/**
 * 创建转发规则（管理员专用）
 * POST /api/admin/forward-rules
 */
adminRoutes.post('/forward-rules', async (c) => {
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
 * 更新转发规则（管理员专用）
 * PUT /api/admin/forward-rules/{id}
 */
adminRoutes.put('/forward-rules/:id', async (c) => {
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
 * 删除转发规则（管理员专用）
 * DELETE /api/admin/forward-rules/{id}
 */
adminRoutes.delete('/forward-rules/:id', async (c) => {
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

/**
 * 获取系统设置（管理员专用）
 * GET /api/admin/settings
 */
adminRoutes.get('/settings', async (c) => {
    try {
        const settings = await getAllSystemSettings(c.env.DB);

        return c.json<ApiResponse>({
            success: true,
            data: { settings }
        });
    } catch (error) {
        errorLog('[管理员设置] 获取失败:', error);
        throw new HTTPException(500, { message: '获取系统设置失败' });
    }
});

/**
 * 更新系统设置（管理员专用）
 * PUT /api/admin/settings
 */
adminRoutes.put('/settings', async (c) => {
    try {
        const updates = await c.req.json() as Partial<SystemConfig>;

        await updateSystemConfig(c.env.DB, updates);

        return c.json<ApiResponse>({
            success: true,
            message: '系统设置更新成功'
        });
    } catch (error) {
        errorLog('[管理员设置] 更新失败:', error);
        throw new HTTPException(500, { message: '更新系统设置失败' });
    }
});

/**
 * 刷新系统设置缓存（管理员专用）
 * POST /api/admin/settings/refresh
 */
adminRoutes.post('/settings/refresh', async (c) => {
    try {
        await refreshSystemSettings(c.env.DB);

        return c.json<ApiResponse>({
            success: true,
            message: '系统设置缓存刷新成功'
        });
    } catch (error) {
        errorLog('[刷新设置] 失败:', error);
        throw new HTTPException(500, { message: '刷新系统设置失败' });
    }
});

export { adminRoutes };