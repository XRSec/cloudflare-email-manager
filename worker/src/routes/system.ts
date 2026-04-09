/**
 * 系统配置相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { debugLog, errorLog } from '../utils/debug';
import { getSystemConfig, updateSystemConfig } from '../services/settings';
import { jwtAuthMiddleware } from '../middleware/auth';
import { bumpChangeSignals, getChangeSignals } from '../services/changeSignals';
import type { Env, ApiResponse, SystemConfig } from '../types';

const systemRoutes = new Hono<{ Bindings: Env }>();

/**
 * 发送健康检查webhook通知
 */
async function sendHealthWebhook(env: Env, status: 'healthy' | 'unhealthy', details: any) {
    try {
        // 检查上次通知状态，避免频繁发送
        const lastStatusKey = 'health:last_status';
        const lastStatus = await env.KV?.get(lastStatusKey);

        if (lastStatus === status) {
            // 状态未变化，不发送通知
            return;
        }

        // 更新状态缓存（5分钟过期）
        await env.KV?.put(lastStatusKey, status, { expirationTtl: 300 });

        const channel = await env.DB.prepare(`
            SELECT channel_url, channel_secret
            FROM routing_rules
            WHERE category = 'channel'
              AND enabled = 1
              AND channel_url != ''
            ORDER BY id ASC
            LIMIT 1
        `).first();

        const url = (channel?.channel_url as string | undefined)?.trim();
        if (!url) return; // 没有配置 webhook，直接返回

        const webhookData = {
            status,
            timestamp: new Date().toISOString(),
            service: 'cloudflare-email-manager',
            details
        };

        // 发送到系统 webhook
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Webhook-Secret': (channel?.channel_secret as string) || '',
                    'User-Agent': 'CEM-HealthCheck/1.0'
                },
                body: JSON.stringify(webhookData)
            });

            if (!response.ok) {
                errorLog(`[Webhook] 发送失败: ${url}`, response.status);
            } else {
                debugLog(`[Webhook] 健康状态通知已发送: ${status}`);
            }
        } catch (error) {
            errorLog(`[Webhook] 发送异常: ${url}`, error);
        }
    } catch (error) {
        errorLog('[Webhook] 健康检查通知失败:', error);
    }
}

/**
 * 获取系统健康状态（无需认证）
 * GET /api/system/health
 */
systemRoutes.get('/health', async (c) => {
    const startTime = Date.now();
    const healthInfo: any = {
        status: 1,
        timestamp: new Date().toISOString(),
        services: {},
        config: {},
        version: 100,
        uptime: 0
    };

    let overallHealthy = true;

    // 1. 检查D1数据库
    try {
        const dbStart = Date.now();
        await c.env.DB.prepare('SELECT 1').first();
        const dbLatency = Date.now() - dbStart;

        healthInfo.services.d1 = {
            status: 1,
            latency_ms: dbLatency
        };
    } catch (error) {
        errorLog('[健康检查] D1数据库异常:', error);
        healthInfo.services.d1 = {
            status: 0,
            latency_ms: 0
        };
        overallHealthy = false;
    }

    // 2. 检查R2存储
    try {
        // 简单的R2连接检查
        await c.env.R2.head('health-check');
        healthInfo.services.r2 = {
            status: 1,
            provider: 1 // R2
        };
    } catch (error) {
        // R2 head可能失败，尝试list检查
        try {
            await c.env.R2.list({ limit: 1 });
            healthInfo.services.r2 = {
                status: 1,
                provider: 1
            };
        } catch (r2Error) {
            errorLog('[健康检查] R2存储异常:', r2Error);
            healthInfo.services.r2 = {
                status: 0,
                provider: 1
            };
            overallHealthy = false;
        }
    }

    // 3. 检查KV存储
    try {
        await c.env.KV.get('health-check');
        healthInfo.services.kv = {
            status: 1,
            provider: 1 // KV
        };
    } catch (error) {
        errorLog('[健康检查] KV存储异常:', error);
        healthInfo.services.kv = {
            status: 0,
            provider: 1
        };
        overallHealthy = false;
    }

    // 4. 获取系统配置（如果数据库正常）
    if (healthInfo.services.d1.status === 1) {
        try {
            const config = await getSystemConfig(c.env.DB);

            // 构建配置对象 - 只保留必要的健康检查相关配置
            const configData = {
                allow_registration: config.allow_registration,
                debug_mode: config.debug_mode
            };

            healthInfo.config = configData;

        } catch (error) {
            errorLog('[健康检查] 获取配置失败:', error);
            // 配置获取失败不影响整体健康状态
        }
    }

    // 5. 设置整体状态
    healthInfo.status = overallHealthy ? 1 : 0;
    healthInfo.total_latency_ms = Date.now() - startTime;

    // 6. 发送webhook通知（仅在状态变化时）
    // TODO: 暂时禁用webhook通知功能
    // if (!overallHealthy) {
    //     await sendHealthWebhook(c.env, 'unhealthy', {
    //         services: healthInfo.services,
    //         total_latency_ms: healthInfo.total_latency_ms
    //     });
    // }

    // 7. 返回结果
    if (overallHealthy) {
        return c.json<ApiResponse>({
            success: true,
            data: { health: healthInfo }
        });
    } else {
        return c.json<ApiResponse>({
            success: false,
            data: {
                health: {
                    status: 0,
                    timestamp: healthInfo.timestamp,
                    services: healthInfo.services,
                    total_latency_ms: healthInfo.total_latency_ms,
                    error: '系统服务异常'
                }
            }
        }, 500);
    }
});

/**
 * 获取系统变更信号（需要认证）
 * GET /api/system/changes
 */
systemRoutes.get('/changes', jwtAuthMiddleware, async (c) => {
    try {
        const changes = await getChangeSignals(c.env.DB);
        const serverTime = new Date().toISOString();
        const requestId = crypto.randomUUID();

        c.header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
        c.header('Pragma', 'no-cache');
        c.header('Expires', '0');
        c.header('X-CEM-Request-Id', requestId);

        return c.json<ApiResponse>({
            success: true,
            data: {
                changes,
                server_time: serverTime,
                request_id: requestId
            }
        });
    } catch (error) {
        errorLog('[系统变更信号] 获取失败:', error);
        throw new HTTPException(500, { message: '获取系统变更信号失败' });
    }
});

/**
 * 获取系统配置（需要认证）
 * GET /api/system/config
 */
systemRoutes.get('/config', jwtAuthMiddleware, async (c) => {
    try {
        const config = await getSystemConfig(c.env.DB);
        const user = c.get('jwtPayload');

        // 返回完整配置
        return c.json<ApiResponse>({
            success: true,
            data: {
                config
            }
        });
    } catch (error) {
        errorLog('[系统配置] 获取失败:', error);
        throw new HTTPException(500, { message: '获取系统配置失败' });
    }
});

/**
 * 更新系统配置
 * PUT /api/system/config
 */
systemRoutes.put('/config', jwtAuthMiddleware, async (c) => {
    try {
        const updates = await c.req.json() as Partial<SystemConfig>;

        await updateSystemConfig(c.env.DB, updates);
        await bumpChangeSignals(c.env.DB, ['system_config']);

        return c.json<ApiResponse>({
            success: true,
            message: '系统配置更新成功'
        });
    } catch (error) {
        errorLog('[系统配置] 更新失败:', error);
        throw new HTTPException(500, { message: '更新系统配置失败' });
    }
});


export { systemRoutes };
