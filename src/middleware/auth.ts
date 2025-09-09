/**
 * 认证中间件
 */

import { Context, Next } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { verifyJWT } from '../utils/crypto';
import { debugLog } from '../utils/debug';
import { getJWTSecret } from '../services/settings';
import type { Env, JWTPayload } from '../types';

/**
 * JWT认证中间件 - 保护所有需要认证的路由
 */
export async function jwtAuthMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
    let token: string | undefined;

    debugLog('[JWT中间件] 开始验证认证令牌 - 路径:', c.req.path);

    // 首先尝试从 Authorization header 获取 token
    const authHeader = c.req.header('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
        debugLog('[JWT中间件] 从 Authorization header 获取到 token');
    } else {
        // 如果没有 Authorization header，尝试从 Cookie 获取
        const cookieHeader = c.req.header('Cookie');
        debugLog('[JWT中间件] Cookie header:', cookieHeader);
        if (cookieHeader) {
            const cookies = cookieHeader.split(';').reduce((acc: Record<string, string>, cookie) => {
                const [key, ...valueParts] = cookie.trim().split('=');
                const value = valueParts.join('='); // 处理值中包含 = 号的情况
                if (key && value) {
                    acc[key.trim()] = decodeURIComponent(value); // URL 解码
                }
                return acc;
            }, {});
            debugLog('[JWT中间件] 解析的 cookies:', JSON.stringify(cookies));
            token = cookies.auth_token;
            if (token) {
                debugLog('[JWT中间件] 从 Cookie 获取到 token，长度:', token.length);
            } else {
                debugLog('[JWT中间件] Cookie 中未找到 auth_token，可用的键:', Object.keys(cookies));
            }
        }
    }

    if (!token) {
        debugLog('[JWT中间件] 未找到认证令牌');
        throw new HTTPException(401, { message: '未提供认证令牌' });
    }

    try {
        const jwtSecret = await getJWTSecret(c.env.DB);
        const payload = await verifyJWT(token, jwtSecret) as JWTPayload;
        debugLog('[JWT中间件] 令牌验证成功，用户:', payload.email_prefix, '类型:', payload.user_type);

        // 将解码的payload存储在上下文中
        c.set('jwtPayload', payload);

        await next();
    } catch (error) {
        debugLog('[JWT中间件] 令牌验证失败:', error);
        throw new HTTPException(401, { message: '无效的认证令牌' });
    }
}

/**
 * 管理员权限中间件
 */
export async function adminAuthMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
    const payload = c.get('jwtPayload');

    if (!payload) {
        throw new HTTPException(401, { message: '未提供认证令牌' });
    }

    if (payload.user_type !== 'admin') {
        debugLog('[管理员中间件] 权限不足，用户类型:', payload.user_type);
        throw new HTTPException(403, { message: '需要管理员权限' });
    }

    debugLog('[管理员中间件] 管理员权限验证通过');
    await next();
}

/**
 * 用户权限中间件 - 确保用户只能访问自己的资源
 */
export async function userResourceMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
    const payload = c.get('jwtPayload');

    if (!payload) {
        throw new HTTPException(401, { message: '未提供认证令牌' });
    }

    // 管理员可以访问所有资源
    if (payload.user_type === 'admin') {
        await next();
        return;
    }

    // 普通用户只能访问自己的资源
    // 这里可以根据具体的路由参数进行更细粒度的权限控制
    await next();
}
