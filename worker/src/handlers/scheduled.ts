/**
 * 定时任务处理器
 */

import { debugLog, errorLog, infoLog } from '../utils/debug';
import { cleanupExpiredAttachments } from '../services/email';
import type { Env, ScheduledEvent } from '../types';

/**
 * 处理定时清理任务
 */
export async function handleScheduledCleanup(env: Env): Promise<void> {
    try {
        infoLog('[定时清理] 开始执行附件清理任务');

        const result = await cleanupExpiredAttachments(env);

        infoLog('[定时清理] 清理完成', {
            deletedAttachments: result.deletedAttachments,
            deletedAttachmentFiles: result.deletedAttachmentFiles
        });

    } catch (error) {
        errorLog('[定时清理] 清理任务失败:', error);
        throw error;
    }
}

/**
 * 定时任务路由处理器 - Cloudflare Workers Cron 入口点
 */
export default {
    async scheduled(event: ScheduledEvent, env: Env, ctx: any) {
        try {
            debugLog('[定时任务] 触发时间:', event.scheduledTime);

            switch (event.cron) {
                case '0 2 * * *': // 每天凌晨2点执行清理
                    await handleScheduledCleanup(env);
                    break;
                default:
                    debugLog('[定时任务] 未知的定时任务:', event.cron);
                    break;
            }

        } catch (error) {
            errorLog('[定时任务] 执行失败:', error);
            // 不抛出错误，避免影响其他定时任务
        }
    }
};
