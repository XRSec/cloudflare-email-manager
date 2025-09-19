/**
 * 认证相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { generateRandomString, hashPassword, verifyPassword, generateJWT } from '../utils/crypto';
import { debugLog, errorLog } from '../utils/debug';
import { findUserByUsername, createUser } from '../services/user';
import { getSystemSetting, getJWTSecret } from '../services/settings';
import { validatePassword } from '../config/constants';
import type { Env, ApiResponse } from '../types';

const authRoutes = new Hono<{ Bindings: Env }>();

/**
 * 用户登录
 * POST /api/auth/login
 */
authRoutes.post('/login', async (c) => {
    try {
        debugLog('[登录] 开始处理用户登录请求');

        const { username, password } = await c.req.json();

        if (!username || !password) {
            throw new HTTPException(400, { message: '用户名和密码不能为空' });
        }

        // 查找用户
        const user = await findUserByUsername(c.env.DB, username);
        if (!user) {
            debugLog('[登录] 用户不存在:', username);
            throw new HTTPException(401, { message: '用户不存在或密码错误' });
        }

        // 验证密码
        const isPasswordValid = await verifyPassword(password, user.password);
        if (!isPasswordValid) {
            debugLog('[登录] 密码错误:', username);
            throw new HTTPException(401, { message: '用户不存在或密码错误' });
        }

        // 生成JWT
        const jwtPayload = {
            user_id: user.id,
            username: user.username,
            user_type: user.user_type
        };

        const jwtSecret = await getJWTSecret(c.env.DB);
        const token = await generateJWT(jwtPayload, jwtSecret);

        debugLog('[登录] 登录成功:', username, '类型:', user.user_type);

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
                    user_type: user.user_type,
                    webhook_url: user.webhook_url,
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
    debugLog('[登出] 处理用户登出请求');

    // 检查是否有认证 cookies
    const cookieHeader = c.req.header('Cookie');
    const hasAuthCookie = cookieHeader && cookieHeader.includes('session_cookies');
    debugLog('[登出] 是否携带认证 cookies:', hasAuthCookie);

    const response = c.json<ApiResponse>({
        success: true,
        message: '登出成功'
    });

    // 清除服务端 Cookie（无论是否携带 cookies 都清除）
    response.headers.set('Set-Cookie',
        'session_cookies=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/'
    );

    debugLog('[登出] 已设置清除 Cookie 响应头');

    return response;
});

/**
 * 用户注册
 * POST /api/auth/register
 */
authRoutes.post('/register', async (c) => {
    try {
        debugLog('[注册] 开始处理用户注册请求');

        // 检查是否允许注册
        const allowRegistration = await getSystemSetting(c.env.DB, 'allow_registration');
        if (allowRegistration !== 'true') {
            debugLog('[注册] 系统不允许用户注册');
            throw new HTTPException(403, { message: '系统当前不允许用户注册' });
        }

        const { username, password, email } = await c.req.json();

        if (!username || !password || !email) {
            throw new HTTPException(400, { message: '用户名、密码和邮箱不能为空' });
        }

        // 验证用户名格式（只允许英文、数字、下划线、连字符）
        const usernameRegex = /^[a-zA-Z0-9_-]+$/;
        if (!usernameRegex.test(username)) {
            throw new HTTPException(400, { message: '用户名只能包含英文字母、数字、下划线和连字符' });
        }

        // 检查用户名是否已存在
        const existingUser = await findUserByUsername(c.env.DB, username);
        if (existingUser) {
            throw new HTTPException(409, { message: '用户名已存在' });
        }

        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
            throw new HTTPException(400, { message: passwordValidation.error! });
        }

        // 哈希密码
        const hashedPassword = await hashPassword(password);

        // 创建用户
        const user = await createUser(c.env.DB, username, hashedPassword, 'user');

        debugLog('[注册] 用户创建成功:', username);

        return c.json<ApiResponse>({
            success: true,
            message: '注册成功',
            data: {
                username: user.username,
                user_type: user.user_type,
                created_at: user.created_at
            }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[注册] 注册失败:', error);
        throw new HTTPException(500, { message: '注册失败' });
    }
});

export { authRoutes };