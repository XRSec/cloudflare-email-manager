/**
 * 认证相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { verifyPassword, generateJWT } from '../utils/crypto';
import { errorLog } from '../utils/debug';
import { getSystemSetting, getJWTSecret } from '../services/settings';
import type { Env, ApiResponse } from '../types';

const authRoutes = new Hono<{ Bindings: Env }>();

/**
 * 用户登录
 * POST /api/auth/login
 */
authRoutes.post('/login', async (c) => {
    try {
        const { username, password } = await c.req.json();

        if (!username || !password) {
            throw new HTTPException(400, { message: '用户名和密码不能为空' });
        }

        // 直接查询用户
        const result = await c.env.DB.prepare(`
            SELECT id, username, password, status, created_at
            FROM users
            WHERE username = ? AND status = 1
        `).bind(username).first();

        if (!result) {
            throw new HTTPException(401, { message: '用户不存在或密码错误' });
        }

        const user = {
            id: result.id as number,
            username: result.username as string,
            password: result.password as string,
            created_at: result.created_at as string | undefined
        };

        // 验证密码
        const isPasswordValid = await verifyPassword(password, user.password);
        if (!isPasswordValid) {
            throw new HTTPException(401, { message: '用户不存在或密码错误' });
        }

        // 生成JWT（单管理员模式，不需要 user_type）
        const jwtPayload = {
            user_id: user.id,
            username: user.username
        };

        const jwtSecret = await getJWTSecret(c.env.DB);
        const token = await generateJWT(jwtPayload, jwtSecret);

        // 获取 Cookie 过期时间设置
        const cookieMaxAgeSetting = await getSystemSetting(c.env.DB, 'cookie_max_age');
        if (!cookieMaxAgeSetting) {
            throw new Error('Cookie 过期时间未配置');
        }
        const cookieMaxAge = parseInt(cookieMaxAgeSetting);

        // 设置Cookie和返回响应
        const response = c.json<ApiResponse>({
            success: true,
            message: '登录成功',
            data: {
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    created_at: user.created_at
                }
            }
        });

        // 设置HttpOnly Cookie
        response.headers.set('Set-Cookie',
            `session_cookies=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Max-Age=${cookieMaxAge}; Path=/`
        );

        return response;
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[登录] 登录失败:', error);
        throw new HTTPException(500, { message: '登录失败' });
    }
});

/**
 * 用户登出
 * POST /api/auth/logout
 */
authRoutes.post('/logout', async (c) => {
    const response = c.json<ApiResponse>({
        success: true,
        message: '登出成功'
    });

    // 清除服务端 Cookie
    response.headers.set('Set-Cookie',
        'session_cookies=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/'
    );

    return response;
});

export { authRoutes };