/**
 * 仪表板和转发日志相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { debugLog, errorLog } from '../utils/debug';
import { jwtAuthMiddleware } from '../middleware/auth';
import { ensureForwardLogDeliveryColumns, sendWebhook } from '../services/webhook';
import type { Env, ApiResponse, Email } from '../types';

const dashboardRoutes = new Hono<{ Bindings: Env }>();

// 所有路由需要认证
dashboardRoutes.use('*', jwtAuthMiddleware);

/**
 * 获取仪表板统计数据
 * GET /api/dashboard/stats
 * 
 * 返回数据包括：
 * - 邮件数量（总数、今日、未读）
 * - R2 文件数量
 * - 转发日志统计（成功、失败）
 * - 系统状态
 */
dashboardRoutes.get('/stats', async (c) => {
    try {
        // 从数据库查询邮件统计
        const emailTotal = await c.env.DB.prepare('SELECT COUNT(*) as count FROM emails').first() as { count: number } | null;
        const emailToday = await c.env.DB.prepare(`
            SELECT COUNT(*) as count FROM emails 
            WHERE DATE(received_at) = DATE('now')
        `).first() as { count: number } | null;
        const emailUnread = await c.env.DB.prepare('SELECT COUNT(*) as count FROM emails WHERE is_read = 0').first() as { count: number } | null;

        // 2. 从 R2 获取文件数量(分别统计邮件和附件)
        let r2EmailCount = 0;
        let r2AttachmentCount = 0;

        try {
            // 从 R2 列出所有文件并分类统计
            let r2List = await c.env.R2.list({ limit: 1000 });

            // 统计邮件和附件
            r2List.objects.forEach((obj: any) => {
                if (obj.key.startsWith('email:') && obj.key.endsWith('.eml')) {
                    r2EmailCount++;
                } else if (obj.key.startsWith('attachments/')) {
                    r2AttachmentCount++;
                }
            });

            // 如果有更多文件，继续获取
            if (r2List.truncated) {
                let cursor = (r2List as any).cursor;

                // 最多查询 10 次（避免超时）
                for (let i = 0; i < 10 && cursor; i++) {
                    const nextList = await c.env.R2.list({ limit: 1000, cursor });

                    nextList.objects.forEach((obj: any) => {
                        if (obj.key.startsWith('email:') && obj.key.endsWith('.eml')) {
                            r2EmailCount++;
                        } else if (obj.key.startsWith('attachments/')) {
                            r2AttachmentCount++;
                        }
                    });

                    if (nextList.truncated) {
                        cursor = (nextList as any).cursor;
                    } else {
                        cursor = null;
                    }
                }
            }
        } catch (error) {
            errorLog('[仪表板] 获取 R2 文件数量失败:', error);
            r2EmailCount = 0;
            r2AttachmentCount = 0;
        }

        // 3. 查询转发日志统计
        const forwardSuccess = await c.env.DB.prepare('SELECT COUNT(*) as count FROM forward_logs WHERE status = 0').first() as { count: number } | null;
        const forwardFailed = await c.env.DB.prepare('SELECT COUNT(*) as count FROM forward_logs WHERE status = 1').first() as { count: number } | null;
        const forwardTotal = await c.env.DB.prepare('SELECT COUNT(*) as count FROM forward_logs').first() as { count: number } | null;

        // 4. 获取最近转发日志(最近5条)
        const recentForwardLogs = await c.env.DB.prepare(`
            SELECT 
                fl.id,
                fl.email_id,
                fl.webhook_url,
                fl.status,
                fl.response_code,
                fl.error_message,
                fl.sent_at,
                e.subject,
                e.from_address
            FROM forward_logs fl
            LEFT JOIN emails e ON fl.email_id = e.id
            ORDER BY fl.sent_at DESC
            LIMIT 5
        `).all();

        // 5. 组装统计数据
        const stats = {
            email: {
                total: emailTotal?.count || 0,
                today: emailToday?.count || 0,
                unread: emailUnread?.count || 0
            },
            r2: {
                emailCount: r2EmailCount,
                attachmentCount: r2AttachmentCount
            },
            forward: {
                total: forwardTotal?.count || 0,
                success: forwardSuccess?.count || 0,
                failed: forwardFailed?.count || 0,
                recentLogs: recentForwardLogs.results || []
            },
            timestamp: new Date().toISOString()
        };

        return c.json<ApiResponse>({
            success: true,
            data: { stats }
        });
    } catch (error) {
        errorLog('[仪表板] 获取统计数据失败:', error);
        throw new HTTPException(500, { message: '获取仪表板数据失败' });
    }
});

/**
 * 获取转发日志列表
 * GET /api/forward-logs?page=1&limit=20&status=0
 */
dashboardRoutes.get('/forward-logs', async (c) => {
    try {
        await ensureForwardLogDeliveryColumns(c.env.DB);

        const page = parseInt(c.req.query('page') || '1');
        const limit = Math.min(parseInt(c.req.query('limit') || '20'), 100);
        const status = c.req.query('status'); // 可选: 0=成功, 1=失败
        const offset = (page - 1) * limit;

        // 构建查询
        let whereClause = '';
        let countQuery = 'SELECT COUNT(*) as count FROM forward_logs';
        let dataQuery = `
            SELECT 
                fl.id,
                fl.email_id,
                fl.webhook_url,
                fl.status,
                fl.response_code,
                fl.error_message,
                fl.delivery_from_address,
                fl.delivery_to_address,
                fl.sent_at,
                fl.created_at,
                e.subject,
                e.from_address,
                e.to_address
            FROM forward_logs fl
            LEFT JOIN emails e ON fl.email_id = e.id
        `;

        const bindings: any[] = [];

        if (status !== undefined && status !== '') {
            whereClause = ' WHERE fl.status = ?';
            bindings.push(parseInt(status));
        }

        // 查询总数
        const totalResult = await c.env.DB.prepare(countQuery + whereClause)
            .bind(...bindings)
            .first() as { count: number } | null;
        const total = (totalResult?.count as number) || 0;

        // 查询数据
        const logsResult = await c.env.DB.prepare(
            dataQuery + whereClause + ' ORDER BY fl.sent_at DESC LIMIT ? OFFSET ?'
        ).bind(...bindings, limit, offset).all();

        return c.json<ApiResponse>({
            success: true,
            data: {
                items: logsResult.results || [],
                total,
                page,
                limit,
                totalPages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        errorLog('[转发日志] 获取列表失败:', error);
        throw new HTTPException(500, { message: '获取转发日志失败' });
    }
});

/**
 * 获取转发日志详情
 * GET /api/forward-logs/:id
 */
dashboardRoutes.get('/forward-logs/:id', async (c) => {
    try {
        await ensureForwardLogDeliveryColumns(c.env.DB);

        const id = parseInt(c.req.param('id'));

        const log = await c.env.DB.prepare(`
            SELECT 
                fl.*,
                e.subject,
                e.from_address,
                e.to_address,
                e.content,
                e.received_at
            FROM forward_logs fl
            LEFT JOIN emails e ON fl.email_id = e.id
            WHERE fl.id = ?
        `).bind(id).first();

        if (!log) {
            throw new HTTPException(404, { message: '转发日志不存在' });
        }

        return c.json<ApiResponse>({
            success: true,
            data: { log }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[转发日志] 获取详情失败:', error);
        throw new HTTPException(500, { message: '获取转发日志详情失败' });
    }
});

/**
 * 重发转发日志对应的 Webhook
 * POST /api/forward-logs/:id/replay
 */
dashboardRoutes.post('/forward-logs/:id/replay', async (c) => {
    try {
        await ensureForwardLogDeliveryColumns(c.env.DB);

        const id = parseInt(c.req.param('id'));
        if (!Number.isInteger(id) || id <= 0) {
            throw new HTTPException(400, { message: '转发日志 ID 无效' });
        }

        const log = await c.env.DB.prepare(`
            SELECT
                fl.*,
                e.id AS email_id,
                e.subject,
                e.from_address,
                e.to_address,
                e.content,
                e.is_read,
                e.attachment_count,
                e.message_id,
                e.headers_json,
                e.size_bytes,
                e.date,
                e.reply_to,
                e.cc,
                e.bcc,
                e.content_type,
                e.received_at,
                e.created_at,
                e.updated_at
            FROM forward_logs fl
            LEFT JOIN emails e ON fl.email_id = e.id
            WHERE fl.id = ?
        `).bind(id).first<any>();

        if (!log) {
            throw new HTTPException(404, { message: '转发日志不存在' });
        }

        const webhookUrl = typeof log.webhook_url === 'string' ? log.webhook_url.trim() : '';
        if (!webhookUrl || webhookUrl.startsWith('mailto:')) {
            throw new HTTPException(400, { message: '当前重发按钮仅支持 Webhook 日志' });
        }

        if (!log.email_id || !log.received_at) {
            throw new HTTPException(404, { message: '关联邮件不存在，无法重发' });
        }

        const channel = await c.env.DB.prepare(`
            SELECT channel_type, channel_secret
            FROM routing_rules
            WHERE category = 'channel'
              AND channel_url = ?
            LIMIT 1
        `).bind(webhookUrl).first<any>();

        const channelType = channel?.channel_type as string | undefined;
        const type = channelType === 'feishu' || channelType === 'bark'
            ? channelType
            : 'dingtalk';

        const email: Email = {
            id: log.email_id,
            subject: log.subject || null,
            from_address: log.from_address || null,
            to_address: log.to_address || null,
            content: log.content || null,
            is_read: Number(log.is_read || 0),
            attachment_count: Number(log.attachment_count || 0),
            message_id: log.message_id || null,
            headers_json: log.headers_json || null,
            size_bytes: log.size_bytes ?? null,
            date: log.date || null,
            reply_to: log.reply_to || null,
            cc: log.cc || null,
            bcc: log.bcc || null,
            content_type: log.content_type || null,
            received_at: log.received_at,
            created_at: log.created_at || undefined,
            updated_at: log.updated_at || undefined
        };

        const result = await sendWebhook(webhookUrl, email, channel?.channel_secret || undefined, type);

        if (!result.success) {
            return c.json<ApiResponse>({
                success: false,
                message: `Webhook 重发失败：${result.errorMessage || '未知错误'}`,
                data: {
                    target: webhookUrl,
                    type,
                    responseCode: result.responseCode || null,
                    errorMessage: result.errorMessage || null,
                    debug: result.debug || null
                }
            }, 502);
        }

        return c.json<ApiResponse>({
            success: true,
            message: 'Webhook 已重发',
            data: {
                target: webhookUrl,
                type,
                responseCode: result.responseCode || null,
                debug: result.debug || null
            }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[转发日志] 重发失败:', error);
        throw new HTTPException(500, { message: '重发失败' });
    }
});

/**
 * 删除转发日志
 * DELETE /api/forward-logs/:id
 */
dashboardRoutes.delete('/forward-logs/:id', async (c) => {
    try {
        const id = parseInt(c.req.param('id'));
        if (!Number.isInteger(id) || id <= 0) {
            throw new HTTPException(400, { message: '转发日志 ID 无效' });
        }

        const result = await c.env.DB.prepare('DELETE FROM forward_logs WHERE id = ?').bind(id).run();
        if (!result.meta?.changes) {
            throw new HTTPException(404, { message: '转发日志不存在' });
        }

        return c.json<ApiResponse>({
            success: true,
            message: '转发日志已删除'
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[转发日志] 删除失败:', error);
        throw new HTTPException(500, { message: '删除转发日志失败' });
    }
});

export { dashboardRoutes };
