/**
 * 邮箱相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware, adminAuthMiddleware } from '../middleware/auth';
import { getPaginationParams } from '../config/constants';
import { debugLog, errorLog } from '../utils/debug';
import {
    getAllMailboxes,
    getMailboxById,
    createMailbox,
    createMailboxApplication,
    deleteMailbox,
    getMailboxApplications,
    processMailboxApplication,
    toggleMailboxStatus
} from '../services/mailbox';
import type { Env, ApiResponse, MailboxApplication } from '../types';

const mailboxRoutes = new Hono<{ Bindings: Env }>();

// 应用JWT认证中间件
mailboxRoutes.use('*', jwtAuthMiddleware);

/**
 * 获取邮箱列表
 * GET /api/mailboxes
 */
mailboxRoutes.get('/', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const queryParams = getPaginationParams(c.req.query());
        const scope = c.req.query('scope');

        let userId: number | undefined;

        // 根据 scope 参数决定显示范围
        if (scope === 'all') {
            // 显示所有邮箱，只有管理员可以访问
            if (payload.user_type !== 1) {
                throw new HTTPException(403, { message: '权限不足，只有管理员可以查看所有邮箱' });
            }
            userId = undefined;
        } else {
            // 默认行为：始终返回当前用户的邮箱（不管是否是管理员）
            // 其他任何值都当作不存在处理
            userId = payload.user_id;
        }

        const result = await getAllMailboxes(c.env.DB, queryParams.page, queryParams.limit, userId);

        // 获取系统配置中的可用域名
        const { getSystemConfig } = await import('../services/settings');
        const systemConfig = await getSystemConfig(c.env.DB);
        const availableDomains = systemConfig.supported_domains || [];

        // 获取额外的统计信息
        const [userMailboxesCount, totalMailboxesCount] = await Promise.all([
            // 当前用户的邮箱数量
            c.env.DB.prepare(`
                SELECT COUNT(*) as count FROM mailboxes 
                WHERE owner_id = ? AND status = 1
            `).bind(payload.user_id).first(),

            // 全部邮箱数量（只有管理员能看到）
            payload.user_type === 1 ?
                c.env.DB.prepare(`SELECT COUNT(*) as count FROM mailboxes WHERE status = 1`).first() :
                Promise.resolve({ count: 0 })
        ]);

        return c.json<ApiResponse>({
            success: true,
            data: {
                total: result.total,
                items: result.mailboxes,
                available_domains: availableDomains,
                stats: {
                    user_mailboxes: (userMailboxesCount as any)?.count || 0,
                    total_mailboxes: (totalMailboxesCount as any)?.count || 0,
                    is_admin: payload.user_type === 1
                }
            }
        });
    } catch (error) {
        errorLog('[邮箱列表] 获取失败:', error);
        throw new HTTPException(500, { message: '获取邮箱列表失败' });
    }
});

/**
 * 创建邮箱
 * POST /api/mailboxes
 */
mailboxRoutes.post('/', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const { address, owner_id, reason } = await c.req.json();

        // 普通用户提交申请，管理员直接创建
        if (payload.user_type === 1) {
            if (!address || !owner_id) {
                throw new HTTPException(400, { message: '邮箱地址和所有者ID不能为空' });
            }

            const mailbox = await createMailbox(c.env.DB, parseInt(owner_id), address);

            return c.json<ApiResponse>({
                success: true,
                message: '邮箱创建成功',
                data: { mailbox }
            });
        } else {
            // 普通用户申请邮箱
            if (!address || !reason) {
                throw new HTTPException(400, { message: '邮箱地址和申请理由不能为空' });
            }

            const application = await createMailboxApplication(c.env.DB, payload.user_id, address, reason);

            return c.json<ApiResponse>({
                success: true,
                message: '邮箱申请提交成功',
                data: {
                    application_id: application.id,
                    status: application.status
                }
            });
        }
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[创建邮箱] 失败:', error);
        throw new HTTPException(500, { message: '创建邮箱失败' });
    }
});

/**
 * 获取邮箱申请列表
 * GET /api/mailboxes/applications
 */
mailboxRoutes.get('/applications', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const queryParams = getPaginationParams(c.req.query());

        // 普通用户只能看到自己的申请，管理员可以看到所有申请
        const userId = payload.user_type === 1 ? undefined : payload.user_id;
        const applications = await getMailboxApplications(c.env.DB, userId, queryParams);

        return c.json<ApiResponse>({
            success: true,
            data: {
                total: applications.length,
                items: applications
            }
        });
    } catch (error) {
        errorLog('[邮箱申请列表] 获取失败:', error);
        throw new HTTPException(500, { message: '获取邮箱申请列表失败' });
    }
});

/**
 * 获取邮箱详情
 * GET /api/mailboxes/{id}
 */
mailboxRoutes.get('/:id', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const mailboxId = parseInt(c.req.param('id'));

        if (isNaN(mailboxId)) {
            throw new HTTPException(400, { message: '无效的邮箱ID' });
        }

        const mailbox = await getMailboxById(c.env.DB, mailboxId);
        if (!mailbox) {
            throw new HTTPException(404, { message: '邮箱不存在' });
        }

        // 普通用户只能查看自己的邮箱
        if (payload.user_type !== 1 && mailbox.user_id !== payload.user_id) {
            throw new HTTPException(403, { message: '无权访问此邮箱' });
        }

        return c.json<ApiResponse>({
            success: true,
            data: { mailbox }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[邮箱详情] 获取失败:', error);
        throw new HTTPException(500, { message: '获取邮箱详情失败' });
    }
});

/**
 * 删除邮箱
 * DELETE /api/mailboxes/{id}
 */
mailboxRoutes.delete('/:id', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const mailboxId = parseInt(c.req.param('id'));

        if (isNaN(mailboxId)) {
            throw new HTTPException(400, { message: '无效的邮箱ID' });
        }

        const mailbox = await getMailboxById(c.env.DB, mailboxId);
        if (!mailbox) {
            throw new HTTPException(404, { message: '邮箱不存在' });
        }

        // 普通用户只能删除自己的邮箱，且不能删除默认邮箱
        if (payload.user_type !== 1) {
            if (mailbox.user_id !== payload.user_id) {
                throw new HTTPException(403, { message: '无权删除此邮箱' });
            }
            if (mailbox.is_default) {
                throw new HTTPException(400, { message: '不能删除默认邮箱' });
            }
        }

        // 获取请求信息
        const requestInfo = {
            ip: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
            userAgent: c.req.header('User-Agent') || 'unknown'
        };

        await deleteMailbox(c.env.DB, mailboxId, payload.user_id, payload.user_type, requestInfo);

        return c.json<ApiResponse>({
            success: true,
            message: '邮箱删除成功'
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[删除邮箱] 失败:', error);
        throw new HTTPException(500, { message: '删除邮箱失败' });
    }
});

/**
 * 处理邮箱申请（仅管理员）
 * POST /api/mailboxes/applications/{id}/process
 */
mailboxRoutes.post('/applications/:id/process', adminAuthMiddleware, async (c) => {
    try {
        const applicationId = parseInt(c.req.param('id'));
        const { action } = await c.req.json();

        if (isNaN(applicationId)) {
            throw new HTTPException(400, { message: '无效的申请ID' });
        }

        if (typeof action !== 'number' || ![1, 2].includes(action)) {
            throw new HTTPException(400, { message: '无效的处理动作，必须是1(批准)或2(拒绝)' });
        }

        const payload = c.get('jwtPayload');
        await processMailboxApplication(c.env.DB, applicationId, payload.user_id, action as 1 | 2);

        return c.json<ApiResponse>({
            success: true,
            message: `邮箱申请${action === 1 ? '批准' : '拒绝'}成功`
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[处理邮箱申请] 失败:', error);
        throw new HTTPException(500, { message: '处理邮箱申请失败' });
    }
});

/**
 * 切换邮箱状态（仅管理员）
 * PUT /api/mailboxes/{id}/status
 */
mailboxRoutes.put('/:id/status', adminAuthMiddleware, async (c) => {
    try {
        const mailboxId = parseInt(c.req.param('id'));
        const { status } = await c.req.json();

        if (isNaN(mailboxId)) {
            throw new HTTPException(400, { message: '无效的邮箱ID' });
        }

        if (![1, 2].includes(status)) {
            throw new HTTPException(400, { message: '无效的状态值，必须是1(启用)或2(停用)' });
        }

        const mailbox = await getMailboxById(c.env.DB, mailboxId);
        if (!mailbox) {
            throw new HTTPException(404, { message: '邮箱不存在' });
        }

        const payload = c.get('jwtPayload');
        await toggleMailboxStatus(c.env.DB, mailboxId, status, payload.user_id);

        return c.json<ApiResponse>({
            success: true,
            message: `邮箱已${status === 1 ? '启用' : '停用'}`
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[切换邮箱状态] 失败:', error);
        throw new HTTPException(500, { message: '切换邮箱状态失败' });
    }
});

export { mailboxRoutes };