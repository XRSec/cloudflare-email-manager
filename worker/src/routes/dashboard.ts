/**
 * 仪表板和转发日志相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { debugLog, errorLog } from '../utils/debug';
import { jwtAuthMiddleware } from '../middleware/auth';
import { KVCacheService } from '../services/kvCache';
import type { Env, ApiResponse } from '../types';

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
        const kvCache = new KVCacheService(c.env.KV);

        // 1. 尝试从 KV 缓存获取
        let stats = await kvCache.getDashboardStats();
        
        if (stats) {
            debugLog('[仪表板] 从缓存读取统计数据');
            return c.json<ApiResponse>({
                success: true,
                data: { stats, cached: true }
            });
        }

        debugLog('[仪表板] 缓存未命中，从数据库查询');

        // 2. 从数据库查询邮件统计
        const emailTotal = await c.env.DB.prepare('SELECT COUNT(*) as count FROM emails').first();
        const emailToday = await c.env.DB.prepare(`
            SELECT COUNT(*) as count FROM emails 
            WHERE DATE(received_at) = DATE('now')
        `).first();
        const emailUnread = await c.env.DB.prepare('SELECT COUNT(*) as count FROM emails WHERE is_read = 0').first();

        // 3. 从 KV 缓存或 R2 获取文件数量
        let r2FileCount = await kvCache.getR2FileCount();
        
        if (r2FileCount === null) {
            try {
                // 从 R2 列出文件并计数（限制返回1000条）
                const r2List = await c.env.R2.list({ limit: 1000 });
                r2FileCount = r2List.objects.length;
                
                // 如果有更多文件，继续获取
                if (r2List.truncated) {
                    let cursor = (r2List as any).cursor;
                    let totalCount = r2FileCount;
                    
                    // 最多查询 10 次（避免超时）
                    for (let i = 0; i < 10 && cursor; i++) {
                        const nextList = await c.env.R2.list({ limit: 1000, cursor });
                        totalCount += nextList.objects.length;
                        if (nextList.truncated) {
                            cursor = (nextList as any).cursor;
                        } else {
                            cursor = null;
                        }
                    }
                    r2FileCount = totalCount;
                }

                // 写入缓存
                await kvCache.setR2FileCount(r2FileCount);
            } catch (error) {
                errorLog('[仪表板] 获取 R2 文件数量失败:', error);
                r2FileCount = 0;
            }
        }

        // 4. 查询转发日志统计
        const forwardSuccess = await c.env.DB.prepare('SELECT COUNT(*) as count FROM forward_logs WHERE status = 0').first();
        const forwardFailed = await c.env.DB.prepare('SELECT COUNT(*) as count FROM forward_logs WHERE status = 1').first();
        const forwardTotal = await c.env.DB.prepare('SELECT COUNT(*) as count FROM forward_logs').first();

        // 5. 获取最近转发日志（最近5条）
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

        // 6. 组装统计数据
        stats = {
            email: {
                total: emailTotal?.count || 0,
                today: emailToday?.count || 0,
                unread: emailUnread?.count || 0
            },
            r2: {
                fileCount: r2FileCount
            },
            forward: {
                total: forwardTotal?.count || 0,
                success: forwardSuccess?.count || 0,
                failed: forwardFailed?.count || 0,
                recentLogs: recentForwardLogs.results || []
            },
            timestamp: new Date().toISOString()
        };

        // 7. 写入缓存（5分钟过期）
        await kvCache.setDashboardStats(stats);

        return c.json<ApiResponse>({
            success: true,
            data: { stats, cached: false }
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
            .first();
        const total = totalResult?.count || 0;

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
 * 清理仪表板缓存
 * DELETE /api/dashboard/cache
 */
dashboardRoutes.delete('/cache', async (c) => {
    try {
        const kvCache = new KVCacheService(c.env.KV);
        await kvCache.clearDashboardCache();

        return c.json<ApiResponse>({
            success: true,
            message: '仪表板缓存已清理'
        });
    } catch (error) {
        errorLog('[仪表板] 清理缓存失败:', error);
        throw new HTTPException(500, { message: '清理缓存失败' });
    }
});

export { dashboardRoutes };
