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

        const { username, password } = await c.req.json();

        if (!username || !password) {
            return c.json<ApiResponse>({
                success: false,
                error: '用户名和密码不能为空'
            }, 400);
        }

        // 验证用户名格式（只允许英文、数字、下划线、连字符）
        const usernameRegex = /^[a-zA-Z0-9_-]+$/;
        if (!usernameRegex.test(username)) {
            return c.json<ApiResponse>({
                success: false,
                error: '用户名只能包含英文字母、数字、下划线和连字符'
            }, 400);
        }

        // 检查用户名是否已存在
        const existingUser = await findUserByUsername(c.env.DB, username);
        if (existingUser) {
            return c.json<ApiResponse>({
                success: false,
                error: '用户名已存在'
            }, 400);
        }

        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
            return c.json<ApiResponse>({
                success: false,
                error: passwordValidation.error!
            }, 400);
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

        const { username, password } = await c.req.json();

        if (!username || !password) {
            return c.json<ApiResponse>({
                success: false,
                error: '用户名和密码不能为空'
            }, 400);
        }

        // 查找用户
        const user = await findUserByUsername(c.env.DB, username);
        if (!user) {
            debugLog('[登录] 用户不存在:', username);
            return c.json<ApiResponse>({
                success: false,
                error: '用户不存在或密码错误'
            }, 401);
        }

        // 验证密码
        const isPasswordValid = await verifyPassword(password, user.password);
        if (!isPasswordValid) {
            debugLog('[登录] 密码错误:', username);
            return c.json<ApiResponse>({
                success: false,
                error: '用户不存在或密码错误'
            }, 401);
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
