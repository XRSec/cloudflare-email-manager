/**
 * 用户相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware, adminAuthMiddleware } from '../middleware/auth';
import { getPaginationParams } from '../config/constants';
import { debugLog, errorLog } from '../utils/debug';
import {
    findUserById,
    updateUserSettings,
    getAllUsers,
    createUser,
    deleteUser
} from '../services/user';
import { getPrimaryDomain } from '../services/settings';
import type { Env, ApiResponse, UserSettingsUpdate } from '../types';

const userRoutes = new Hono<{ Bindings: Env }>();

// 应用JWT认证中间件
userRoutes.use('*', jwtAuthMiddleware);

/**
 * 获取当前用户信息
 * GET /api/users/me
 */
userRoutes.get('/me', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const userData = await findUserById(c.env.DB, payload.user_id);

        if (!userData) {
            throw new HTTPException(404, { message: '用户不存在' });
        }

        return c.json<ApiResponse>({
            success: true,
            data: {
                id: userData.id,
                username: userData.username,
                email: userData.username + '@' + (await getPrimaryDomain(c.env.DB)), // 假设邮箱格式
                user_type: userData.user_type,
                created_at: userData.created_at,
                updated_at: userData.updated_at,
                settings: {
                    webhook_url: userData.webhook_url,
                    webhook_secret: userData.webhook_secret ? '***已设置***' : null
                }
            }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[用户信息] 获取失败:', error);
        throw new HTTPException(500, { message: '获取用户信息失败' });
    }
});

/**
 * 更新当前用户信息
 * PUT /api/users/me
 */
userRoutes.put('/me', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const updates = await c.req.json() as UserSettingsUpdate;

        debugLog('[用户设置] 更新请求:', JSON.stringify(updates, null, 2));

        // 验证输入
        const validatedUpdates: UserSettingsUpdate = {};

        // 处理密码更新
        if (updates.password && updates.password.trim()) {
            if (updates.password.length < 6) {
                throw new HTTPException(400, { message: '密码长度至少为6位' });
            }
            validatedUpdates.password = updates.password;
        }

        // 处理webhook URL更新
        if (updates.webhook_url !== undefined) {
            const webhookUrl = updates.webhook_url.trim();
            if (webhookUrl && !webhookUrl.startsWith('http')) {
                throw new HTTPException(400, { message: 'Webhook URL必须以http或https开头' });
            }
            validatedUpdates.webhook_url = webhookUrl || undefined;
        }

        // 处理webhook secret更新
        if (updates.webhook_secret !== undefined) {
            const webhookSecret = updates.webhook_secret.trim();
            validatedUpdates.webhook_secret = webhookSecret || undefined;
        }

        // 检查是否有需要更新的内容
        if (Object.keys(validatedUpdates).length === 0) {
            throw new HTTPException(400, { message: '没有需要更新的内容' });
        }

        // 执行更新
        await updateUserSettings(c.env.DB, payload.user_id, validatedUpdates);

        debugLog('[用户设置] 更新成功，用户ID:', payload.user_id);

        return c.json<ApiResponse>({
            success: true,
            message: '设置更新成功'
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[用户设置] 更新失败:', error);
        throw new HTTPException(500, { message: '更新设置失败' });
    }
});

/**
 * 获取用户列表（仅管理员）
 * GET /api/users
 */
userRoutes.get('/', adminAuthMiddleware, async (c) => {
    try {
        const queryParams = getPaginationParams(c.req.query());
        const query = c.req.query('query');

        const searchParams = {
            search: query
        };

        const result = await getAllUsers(c.env.DB, queryParams.page, queryParams.limit, searchParams);

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
                }))
            }
        });
    } catch (error) {
        errorLog('[用户列表] 获取失败:', error);
        throw new HTTPException(500, { message: '获取用户列表失败' });
    }
});

/**
 * 管理员创建用户
 * POST /api/users
 */
userRoutes.post('/', adminAuthMiddleware, async (c) => {
    try {
        const { username, password, email, user_type = 'user' } = await c.req.json();

        if (!username || !password || !email) {
            throw new HTTPException(400, { message: '用户名、密码和邮箱不能为空' });
        }

        if (!['user', 'admin'].includes(user_type)) {
            throw new HTTPException(400, { message: '无效的用户角色' });
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
 * 获取指定用户信息（仅管理员）
 * GET /api/users/{id}
 */
userRoutes.get('/:id', adminAuthMiddleware, async (c) => {
    try {
        const userId = parseInt(c.req.param('id'));

        if (isNaN(userId)) {
            throw new HTTPException(400, { message: '无效的用户ID' });
        }

        const userData = await findUserById(c.env.DB, userId);
        if (!userData) {
            throw new HTTPException(404, { message: '用户不存在' });
        }

        return c.json<ApiResponse>({
            success: true,
            data: {
                id: userData.id,
                username: userData.username,
                email: userData.username + '@' + (await getPrimaryDomain(c.env.DB)),
                user_type: userData.user_type,
                created_at: userData.created_at,
                updated_at: userData.updated_at,
                settings: {
                    webhook_url: userData.webhook_url,
                    webhook_secret: userData.webhook_secret ? '***已设置***' : null
                }
            }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[用户详情] 获取失败:', error);
        throw new HTTPException(500, { message: '获取用户详情失败' });
    }
});

/**
 * 删除用户（仅管理员）
 * DELETE /api/users/{id}
 */
userRoutes.delete('/:id', adminAuthMiddleware, async (c) => {
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
 * 切换用户状态（仅管理员）
 * PUT /api/users/{id}/status
 */
userRoutes.put('/:id/status', adminAuthMiddleware, async (c) => {
    try {
        const userId = parseInt(c.req.param('id'));
        const { status } = await c.req.json();

        if (isNaN(userId)) {
            throw new HTTPException(400, { message: '无效的用户ID' });
        }

        if (![1, 2].includes(status)) {
            throw new HTTPException(400, { message: '无效的状态值，必须是1(启用)或2(停用)' });
        }

        const userData = await findUserById(c.env.DB, userId);
        if (!userData) {
            throw new HTTPException(404, { message: '用户不存在' });
        }

        // 直接更新用户状态，不需要转换
        const result = await c.env.DB.prepare(`
            UPDATE users 
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `).bind(status, userId).run();

        if (!result.success) {
            throw new HTTPException(500, { message: '更新用户状态失败' });
        }

        return c.json<ApiResponse>({
            success: true,
            message: `用户已${status === 1 ? '启用' : '停用'}`
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[切换用户状态] 失败:', error);
        throw new HTTPException(500, { message: '切换用户状态失败' });
    }
});

export { userRoutes };