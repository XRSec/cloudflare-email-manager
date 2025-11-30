/**
 * 用户相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware } from '../middleware/auth';
import { debugLog, errorLog } from '../utils/debug';
import {
    findUserById,
    updateUserSettings
} from '../services/user';
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

        // 获取系统配置以获取域名
        const { getSystemConfig } = await import('../services/settings');
        const config = await getSystemConfig(c.env.DB);

        return c.json<ApiResponse>({
            success: true,
            data: {
                id: userData.id,
                username: userData.username,
                email: userData.username + '@' + (config.supported_domains?.[0] || 'example.com'), // 使用第一个域名
                user_type: userData.user_type,
                created_at: userData.created_at,
                updated_at: userData.updated_at,
                settings: {
                    webhook_url: userData.webhook_url,
                    webhook_secret: userData.webhook_secret ? '***已设置***' : null,
                    webhook_type: userData.webhook_type,
                    webhook_custom_message: userData.webhook_custom_message
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

        // 处理webhook type更新
        if (updates.webhook_type !== undefined) {
            validatedUpdates.webhook_type = updates.webhook_type;
        }

        // 处理webhook custom message更新
        if (updates.webhook_custom_message !== undefined) {
            const webhookCustomMessage = updates.webhook_custom_message.trim();
            validatedUpdates.webhook_custom_message = webhookCustomMessage || undefined;
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

export { userRoutes };