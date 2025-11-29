/**
 * API访问频率限制中间件
 */

import { Context, Next } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { getSystemConfig } from '../services/settings';
import { SYSTEM_DEFAULTS } from '../config/constants';
import { debugLog } from '../utils/debug';
import type { Env } from '../types';

/**
 * 获取客户端标识符（IP地址或用户ID）
 */
function getClientIdentifier(c: Context<{ Bindings: Env }>): string {
  // 优先使用用户ID（如果已认证）
  const payload = c.get('jwtPayload');
  if (payload) {
    return `user:${payload.user_id}`;
  }

  // 否则使用IP地址
  const forwardedFor = c.req.header('CF-Connecting-IP') ||
    c.req.header('X-Forwarded-For') ||
    c.req.header('X-Real-IP') ||
    'unknown';

  // 如果X-Forwarded-For包含多个IP，取第一个
  const ip = forwardedFor.split(',')[0].trim();
  return `ip:${ip}`;
}

/**
 * 频率限制时间窗口（固定为60秒，即1分钟）
 */
const RATE_LIMIT_WINDOW_SECONDS = 60;

/**
 * 获取频率限制配置
 */
async function getRateLimitConfig(db: Env['DB']): Promise<{
  enabled: boolean;
  maxRequests: number;
}> {
  try {
    const config = await getSystemConfig(db);
    return {
      enabled: config.api_rate_limit === 1,
      maxRequests: config.api_rate_limit_max_requests || SYSTEM_DEFAULTS.API_RATE_LIMIT_MAX_REQUESTS
    };
  } catch (error) {
    const { errorLog } = await import('../utils/debug');
    errorLog('频率限制', '获取配置失败，使用默认值:', error);
    return {
      enabled: Number(SYSTEM_DEFAULTS.API_RATE_LIMIT) === 1,
      maxRequests: SYSTEM_DEFAULTS.API_RATE_LIMIT_MAX_REQUESTS
    };
  }
}

/**
 * API访问频率限制中间件
 * 
 * 使用 KV 存储记录每个客户端的请求计数
 * Key格式: rate_limit:{clientIdentifier}
 * Value: JSON字符串，包含 { count: number, resetAt: number }
 */
export async function rateLimitMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  // 跳过非API路径
  if (!c.req.path.startsWith('/api/')) {
    await next();
    return;
  }

  // 跳过健康检查接口
  if (c.req.path === '/api/system/health') {
    await next();
    return;
  }

  // 获取频率限制配置
  const config = await getRateLimitConfig(c.env.DB);

  // 如果未启用频率限制，直接通过
  if (!config.enabled) {
    await next();
    return;
  }

  // 获取客户端标识符
  const clientId = getClientIdentifier(c);
  const kvKey = `rate_limit:${clientId}`;

  try {
    // 从KV获取当前计数
    const kvData = await c.env.KV.get(kvKey);
    const now = Date.now();
    const windowMs = RATE_LIMIT_WINDOW_SECONDS * 1000;

    let count = 0;
    let resetAt = now + windowMs;

    if (kvData) {
      try {
        const data = JSON.parse(kvData);
        // 如果时间窗口已过期，重置计数
        if (data.resetAt && data.resetAt > now) {
          count = data.count || 0;
          resetAt = data.resetAt;
        } else {
          // 时间窗口已过期，重置计数
          count = 0;
          resetAt = now + windowMs;
        }
      } catch (error) {
        // 解析失败，重置计数
        count = 0;
        resetAt = now + windowMs;
      }
    }

    // 检查是否超过限制
    if (count >= config.maxRequests) {
      const retryAfter = Math.ceil((resetAt - now) / 1000);
      debugLog(`[频率限制] 客户端 ${clientId} 超过限制: ${count}/${config.maxRequests}`);

      throw new HTTPException(429, {
        message: `请求过于频繁，请稍后再试。限制：${config.maxRequests} 次/分钟`,
        cause: {
          retryAfter,
          limit: config.maxRequests,
          window: RATE_LIMIT_WINDOW_SECONDS
        }
      });
    }

    // 增加计数
    count++;

    // 保存到KV（过期时间设置为时间窗口长度 + 10秒缓冲）
    const ttl = RATE_LIMIT_WINDOW_SECONDS + 10;
    await c.env.KV.put(kvKey, JSON.stringify({
      count,
      resetAt
    }), { expirationTtl: ttl });

    // 添加响应头
    c.header('X-RateLimit-Limit', String(config.maxRequests));
    c.header('X-RateLimit-Remaining', String(Math.max(0, config.maxRequests - count)));
    c.header('X-RateLimit-Reset', String(Math.ceil(resetAt / 1000)));

    debugLog(`[频率限制] 客户端 ${clientId} 请求计数: ${count}/${config.maxRequests}`);

    await next();
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    // KV操作失败，记录错误但允许请求通过（降级处理）
    const { errorLog } = await import('../utils/debug');
    errorLog('频率限制', 'KV操作失败:', error);
    await next();
  }
}

