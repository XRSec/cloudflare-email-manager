/**
 * 认证相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { generateRandomString, hashPassword, verifyPassword, generateJWT } from '../utils/crypto';
import { debugLog, errorLog } from '../utils/debug';
import { findUserByPrefix, createUser } from '../services/user';
import { getSystemSetting, getJWTSecret } from '../services/settings';
import type { Env, ApiResponse } from '../types';

const auth = new Hono<{ Bindings: Env }>();

/**
 * 用户注册
 */
auth.post('/register', async (c) => {
    try {
        debugLog('[注册] 开始处理用户注册请求');

        // 检查是否允许注册
        const allowRegistration = await getSystemSetting(c.env.DB, 'allow_registration');
        if (allowRegistration !== 'true') {
            debugLog('[注册] 系统不允许用户注册');
            return c.json<ApiResponse>({
                success: false,
                error: '系统当前不允许用户注册'
            }, 403);
        }

        const { email_password } = await c.req.json();

        if (!email_password || email_password.length < 6) {
            return c.json<ApiResponse>({
                success: false,
                error: '密码长度至少为6位'
            }, 400);
        }

        // 生成随机邮件前缀
        let emailPrefix: string;
        let attempts = 0;
        const maxAttempts = 10;

        do {
            emailPrefix = generateRandomString(8);
            attempts++;

            // 检查前缀是否已存在
            const existingUser = await findUserByPrefix(c.env.DB, emailPrefix);
            if (!existingUser) {
                break;
            }

            if (attempts >= maxAttempts) {
                throw new Error('无法生成唯一的邮件前缀');
            }
        } while (true);

        // 哈希密码
        const hashedPassword = await hashPassword(email_password);

        // 创建用户
        const user = await createUser(c.env.DB, emailPrefix, hashedPassword, 'user');

        debugLog('[注册] 用户创建成功:', emailPrefix);

        return c.json<ApiResponse>({
            success: true,
            message: '注册成功',
            data: {
                email_prefix: user.email_prefix,
                user_type: user.user_type,
                created_at: user.created_at
            }
        });

    } catch (error) {
        errorLog('[注册] 注册失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '注册失败'
        }, 500);
    }
});

/**
 * 用户登录
 */
auth.post('/login', async (c) => {
    try {
        debugLog('[登录] 开始处理用户登录请求');

        const { email_prefix, email_password } = await c.req.json();

        if (!email_prefix || !email_password) {
            return c.json<ApiResponse>({
                success: false,
                error: '邮件前缀和密码不能为空'
            }, 400);
        }

        // 查找用户
        const user = await findUserByPrefix(c.env.DB, email_prefix);
        if (!user) {
            debugLog('[登录] 用户不存在:', email_prefix);
            return c.json<ApiResponse>({
                success: false,
                error: '用户不存在或密码错误'
            }, 401);
        }

        // 验证密码
        const isPasswordValid = await verifyPassword(email_password, user.email_password);
        if (!isPasswordValid) {
            debugLog('[登录] 密码错误:', email_prefix);
            return c.json<ApiResponse>({
                success: false,
                error: '用户不存在或密码错误'
            }, 401);
        }

        // 生成JWT
        const jwtPayload = {
            user_id: user.id,
            email_prefix: user.email_prefix,
            user_type: user.user_type
        };

        const jwtSecret = await getJWTSecret(c.env.DB);
        const token = await generateJWT(jwtPayload, jwtSecret);

        debugLog('[登录] 登录成功:', email_prefix, '类型:', user.user_type);

        // 获取 Cookie 过期时间设置
        const cookieMaxAge = parseInt(await getSystemSetting(c.env.DB, 'cookie_max_age') || '604800');

        // 设置Cookie和返回响应
        const response = c.json<ApiResponse>({
            success: true,
            message: '登录成功',
            data: {
                token,
                user: {
                    id: user.id,
                    email_prefix: user.email_prefix,
                    user_type: user.user_type,
                    webhook_url: user.webhook_url,
                    created_at: user.created_at
                }
            }
        });

        // 设置HttpOnly Cookie
        response.headers.set('Set-Cookie',
            `auth_token=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Max-Age=${cookieMaxAge}; Path=/`
        );

        return response;

    } catch (error) {
        errorLog('[登录] 登录失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: '登录失败'
        }, 500);
    }
});

/**
 * 用户登出
 */
auth.post('/logout', async (c) => {
    debugLog('[登出] 处理用户登出请求');

    const response = c.json<ApiResponse>({
        success: true,
        message: '登出成功'
    });

    // 清除Cookie
    response.headers.set('Set-Cookie',
        'auth_token=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/'
    );

    return response;
});

export { auth };
