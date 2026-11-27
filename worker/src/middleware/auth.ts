/**
 * 认证中间件
 */

import { Context, Next } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { verifyJWT } from '../utils/crypto';
import { getJWTSecret, getSystemSetting } from '../services/settings';
import type { Env, JWTPayload } from '../types';

/**
 * JWT认证中间件 - 保护所有需要认证的路由
 */
export async function jwtAuthMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
    let token: string | undefined;

    // 首先尝试从 Authorization header 获取 token
    const authHeader = c.req.header('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7).trim();
    } else {
        // 尝试从 URL query 参数获取 token
        const queryToken = c.req.query('token');
        if (queryToken) {
            token = queryToken.trim();
        } else {
            // 如果没有 Authorization header 和 query 参数，尝试从 Cookie 获取
            const cookieHeader = c.req.header('Cookie');
            if (cookieHeader) {
                const cookies = cookieHeader.split(';').reduce((acc: Record<string, string>, cookie) => {
                    const [key, ...valueParts] = cookie.trim().split('=');
                    const value = valueParts.join('='); // 处理值中包含 = 号的情况
                    if (key && value) {
                        acc[key.trim()] = decodeURIComponent(value); // URL 解码
                    }
                    return acc;
                }, {});
                token = cookies.session_cookies;
            }
        }
    }

    if (!token) {
        throw new HTTPException(401, { message: '未提供认证令牌' });
    }

    // 优先检查是否匹配系统 API Token
    try {
        const apiToken = await getSystemSetting(c.env.DB, 'api_token');
        if (apiToken && token === apiToken) {
            const adminUser = await c.env.DB.prepare(`
                SELECT id, username FROM users WHERE status = 1 ORDER BY id ASC LIMIT 1
            `).first<{ id: number; username: string }>();

            const payload: JWTPayload = {
                user_id: adminUser?.id || 1,
                username: adminUser?.username || 'admin',
                iat: Math.floor(Date.now() / 1000),
                exp: 0
            };

            c.set('jwtPayload', payload);
            c.set('user' as any, {
                id: payload.user_id,
                username: payload.username
            });

            await next();
            return;
        }
    } catch {
        // 忽略 API Token 检查异常，继续执行 JWT 验证
    }

    try {
        const jwtSecret = await getJWTSecret(c.env.DB);
        const payload = await verifyJWT(token, jwtSecret) as JWTPayload;

        // 将解码的payload存储在上下文中
        c.set('jwtPayload', payload);

        // 同时设置user对象以保持兼容性
        c.set('user' as any, {
            id: payload.user_id,
            username: payload.username
        });

        await next();
    } catch (error) {
        // 静默抛出 HTTPException，不打印原始错误堆栈
        // 这是预期的业务错误（如令牌过期、无效等），不需要记录堆栈信息
        throw new HTTPException(401, { message: '无效的认证令牌' });
    }
}

/**
 * 简化的认证中间件 - 用于路由装饰器
 */
export const requireAuth = jwtAuthMiddleware;
