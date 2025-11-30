/**
 * 调试模式中间件
 * 检查系统是否启用调试模式，如果未启用则返回404
 */

import { Context, Next } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { getSystemConfig } from '../services/settings';
import type { Env } from '../types';

/**
 * 调试模式检查中间件
 * 只有在调试模式启用时才允许访问
 */
export async function debugModeMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  try {
    // 获取系统配置（使用缓存）
    const config = await getSystemConfig(c.env.DB);

    if (config.debug_mode !== 1) {
      throw new HTTPException(404, { message: '接口不存在' });
    }

    // 调试模式已启用，继续处理
    await next();
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }

    // 其他错误也返回404，避免泄露系统信息
    throw new HTTPException(404, { message: '接口不存在' });
  }
}

/**
 * 调试模式检查辅助函数
 * 返回调试模式状态，不抛出异常
 */
export async function isDebugModeEnabled(db: any): Promise<boolean> {
  try {
    const config = await getSystemConfig(db);
    return config.debug_mode === 1;
  } catch (error) {
    const { errorLog } = await import('../utils/debug');
    errorLog('调试模式', '检查调试模式失败:', error);
    return false;
  }
}
