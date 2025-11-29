/**
 * 用户相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware } from '../middleware/auth';
import { debugLog, errorLog } from '../utils/debug';
import { updateUserSettings } from '../services/user';
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

        // 直接查询用户信息
        const result = await c.env.DB.prepare(`
            SELECT id, username, created_at, updated_at
            FROM users
            WHERE id = ? AND status = 1
        `).bind(payload.user_id).first();

        if (!result) {
            throw new HTTPException(404, { message: '用户不存在' });
        }

        return c.json<ApiResponse>({
            success: true,
            data: {
                id: result.id as number,
                username: result.username as string,
                created_at: result.created_at as string | undefined,
                updated_at: result.updated_at as string | undefined
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
        const validatedUpdates: { username?: string; password?: string } = {};

        // 处理用户名更新
        if (updates.username !== undefined) {
            const username = updates.username.trim();
            if (username.length < 3 || username.length > 50) {
                throw new HTTPException(400, { message: '用户名长度必须在3-50个字符之间' });
            }
            validatedUpdates.username = username;
        }

        // 处理密码更新（需要二次验证）
        if (updates.password && updates.password.trim()) {
            if (updates.password.length < 6) {
                throw new HTTPException(400, { message: '密码长度至少为6位' });
            }
            // 检查是否有密码确认
            if (!updates.password_confirm) {
                throw new HTTPException(400, { message: '请确认密码' });
            }
            if (updates.password !== updates.password_confirm) {
                throw new HTTPException(400, { message: '两次输入的密码不一致' });
            }
            // 哈希密码
            const { hashPassword } = await import('../utils/crypto');
            validatedUpdates.password = await hashPassword(updates.password);
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
        const errorMessage = error instanceof Error ? error.message : '更新设置失败';
        throw new HTTPException(500, { message: errorMessage });
    }
});

export { userRoutes };