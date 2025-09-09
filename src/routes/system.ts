/**
 * 系统配置相关路由（公开访问）
 */

import { Hono } from 'hono';
import { debugLog, errorLog } from '../utils/debug';
import { getSystemConfig } from '../services/settings';
import type { Env, ApiResponse } from '../types';

const system = new Hono<{ Bindings: Env }>();

/**
 * 获取系统公开配置
 * 这个端点不需要认证，前端可以用来获取系统基本配置
 */
system.get('/config', async (c) => {
    try {
        const config = await getSystemConfig(c.env.DB);

        // 只返回前端需要的公开配置
        const publicConfig = {
            allow_registration: config.allow_registration,
            debug_mode: config.debug_mode,
            domains: config.domains,
            max_attachment_size: config.max_attachment_size
        };

        debugLog('[系统配置] 获取公开配置成功');

        return c.json<ApiResponse>({
            success: true,
            data: { config: publicConfig }
        });
    } catch (error) {
        errorLog('[系统配置] 获取失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: '获取系统配置失败'
        }, 500);
    }
});

/**
 * 健康检查端点
 */
system.get('/health', async (c) => {
    try {
        // 简单的数据库连接检查
        await c.env.DB.prepare('SELECT 1').first();

        return c.json<ApiResponse>({
            success: true,
            data: {
                status: 'healthy',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        errorLog('[健康检查] 失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: '系统不健康'
        }, 500);
    }
});

export { system };
