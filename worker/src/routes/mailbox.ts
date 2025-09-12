/**
 * 邮箱管理路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { jwtAuthMiddleware, adminAuthMiddleware } from '../middleware/auth';
import { debugLog, errorLog } from '../utils/debug';
import { 
    findMailboxesByUserId,
    createMailboxApplication,
    getUserMailboxApplications,
    getAllMailboxApplications,
    processMailboxApplication,
    createMailbox,
    deleteMailbox,
    getAllMailboxes,
    isReservedMailbox,
    checkUserMailboxLimit,
    findMailboxByEmail
} from '../services/mailbox';
import { getSystemSetting, matchDomainForEmail, getSystemConfig } from '../services/settings';
import type { Env, ApiResponse } from '../types';

const mailbox = new Hono<{ Bindings: Env }>();

// ===================
// 用户邮箱管理
// ===================

/**
 * 获取当前用户的邮箱列表
 */
mailbox.get('/user/mailboxes', jwtAuthMiddleware, async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const mailboxes = await findMailboxesByUserId(c.env.DB, payload.user_id);

        return c.json<ApiResponse>({
            success: true,
            data: { mailboxes }
        });
    } catch (error) {
        errorLog('[邮箱API] 获取用户邮箱失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '获取邮箱列表失败'
        }, 500);
    }
});

/**
 * 检查邮箱是否可用
 */
mailbox.get('/check-availability', requireAuth, async (c) => {
    try {
        const email_address = c.req.query('email');
        
        if (!email_address) {
            return c.json<ApiResponse>({
                success: false,
                error: '邮箱地址不能为空'
            }, 400);
        }

        // 验证邮箱格式
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email_address)) {
            return c.json<ApiResponse>({
                success: false,
                error: '邮箱格式不正确'
            }, 400);
        }

        // 验证域名是否在支持的域名列表中
        const matchedDomain = await matchDomainForEmail(c.env.DB, email_address);
        if (!matchedDomain) {
            return c.json<ApiResponse>({
                success: false,
                error: '该域名不在系统支持的域名列表中'
            }, 400);
        }

        // 检查是否为保留邮箱
        if (await isReservedMailbox(c.env.DB, email_address)) {
            return c.json<ApiResponse>({
                success: false,
                error: '该邮箱地址为系统保留，不可申请'
            }, 400);
        }

        // 检查邮箱是否已存在
        const existingMailbox = await findMailboxByEmail(c.env.DB, email_address);
        if (existingMailbox) {
            return c.json<ApiResponse>({
                success: false,
                error: '邮箱地址已被使用'
            }, 400);
        }

        return c.json<ApiResponse>({
            success: true,
            message: '邮箱地址可用'
        });
    } catch (error) {
        errorLog('[邮箱API] 检查邮箱可用性失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '检查失败'
        }, 500);
    }
});

/**
 * 申请新邮箱
 */
mailbox.post('/user/applications', jwtAuthMiddleware, async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const { email_address, reason } = await c.req.json();

        if (!email_address) {
            return c.json<ApiResponse>({
                success: false,
                error: '邮箱地址不能为空'
            }, 400);
        }

        // 验证邮箱格式
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email_address)) {
            return c.json<ApiResponse>({
                success: false,
                error: '邮箱格式不正确'
            }, 400);
        }

        // 验证域名是否在支持的域名列表中
        const matchedDomain = await matchDomainForEmail(c.env.DB, email_address);
        if (!matchedDomain) {
            return c.json<ApiResponse>({
                success: false,
                error: '该域名不在系统支持的域名列表中'
            }, 400);
        }

        // 检查是否为保留邮箱
        if (await isReservedMailbox(c.env.DB, email_address)) {
            return c.json<ApiResponse>({
                success: false,
                error: '该邮箱地址为系统保留，不可申请'
            }, 400);
        }

        // 检查用户邮箱数量限制
        if (!(await checkUserMailboxLimit(c.env.DB, payload.user_id))) {
            return c.json<ApiResponse>({
                success: false,
                error: '已达到邮箱数量上限'
            }, 400);
        }

        // 检查邮箱是否已存在
        const existingMailbox = await findMailboxByEmail(c.env.DB, email_address);
        if (existingMailbox) {
            return c.json<ApiResponse>({
                success: false,
                error: '邮箱地址已被使用'
            }, 400);
        }

        // 检查是否自动批准
        const systemConfig = await getSystemConfig(c.env.DB);
        const autoApprove = systemConfig.auto_approve_mailbox;
        
        if (autoApprove) {
            // 自动批准，直接创建邮箱
            const mailbox = await createMailbox(c.env.DB, payload.user_id, email_address);
            
            return c.json<ApiResponse>({
                success: true,
                message: '邮箱创建成功',
                data: { mailbox }
            });
        } else {
            // 创建申请
            const application = await createMailboxApplication(c.env.DB, payload.user_id, email_address, reason);
            
            return c.json<ApiResponse>({
                success: true,
                message: '申请已提交，等待管理员审核',
                data: { application }
            });
        }
    } catch (error) {
        errorLog('[邮箱API] 申请邮箱失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '申请提交失败'
        }, 500);
    }
});

/**
 * 获取当前用户的申请列表
 */
mailbox.get('/user/applications', jwtAuthMiddleware, async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const applications = await getUserMailboxApplications(c.env.DB, payload.user_id);

        return c.json<ApiResponse>({
            success: true,
            data: { applications }
        });
    } catch (error) {
        errorLog('[邮箱API] 获取用户申请失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '获取申请列表失败'
        }, 500);
    }
});

/**
 * 删除用户邮箱
 */
mailbox.delete('/user/mailboxes/:id', jwtAuthMiddleware, async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const mailboxId = parseInt(c.req.param('id'));

        if (isNaN(mailboxId)) {
            return c.json<ApiResponse>({
                success: false,
                error: '无效的邮箱ID'
            }, 400);
        }

        // 验证邮箱是否属于当前用户
        const userMailboxes = await findMailboxesByUserId(c.env.DB, payload.user_id);
        const mailbox = userMailboxes.find(m => m.id === mailboxId);
        
        if (!mailbox) {
            return c.json<ApiResponse>({
                success: false,
                error: '邮箱不存在或无权限删除'
            }, 403);
        }

        // 检查是否为默认邮箱
        if (mailbox.is_default === 1) {
            return c.json<ApiResponse>({
                success: false,
                error: '不能删除默认邮箱'
            }, 400);
        }

        await deleteMailbox(c.env.DB, mailboxId);

        return c.json<ApiResponse>({
            success: true,
            message: '邮箱删除成功'
        });
    } catch (error) {
        errorLog('[邮箱API] 删除邮箱失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '删除邮箱失败'
        }, 500);
    }
});

// ===================
// 管理员邮箱管理
// ===================

/**
 * 获取所有邮箱（管理员）
 */
mailbox.get('/admin/mailboxes', jwtAuthMiddleware, adminAuthMiddleware, async (c) => {
    try {
        const page = parseInt(c.req.query('page') || '1');
        const pageSize = parseInt(c.req.query('page_size') || '20');

        const result = await getAllMailboxes(c.env.DB, page, pageSize);

        return c.json<ApiResponse>({
            success: true,
            data: result
        });
    } catch (error) {
        errorLog('[邮箱API] 获取所有邮箱失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '获取邮箱列表失败'
        }, 500);
    }
});

/**
 * 管理员创建邮箱
 */
mailbox.post('/admin/mailboxes', jwtAuthMiddleware, adminAuthMiddleware, async (c) => {
    try {
        const { user_id, email_address } = await c.req.json();

        if (!user_id || !email_address) {
            return c.json<ApiResponse>({
                success: false,
                error: '用户ID和邮箱地址不能为空'
            }, 400);
        }

        const mailbox = await createMailbox(c.env.DB, user_id, email_address);

        return c.json<ApiResponse>({
            success: true,
            message: '邮箱创建成功',
            data: { mailbox }
        });
    } catch (error) {
        errorLog('[邮箱API] 管理员创建邮箱失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '创建邮箱失败'
        }, 500);
    }
});


/**
 * 管理员删除邮箱
 */
mailbox.delete('/admin/mailboxes/:id', jwtAuthMiddleware, adminAuthMiddleware, async (c) => {
    try {
        const mailboxId = parseInt(c.req.param('id'));

        if (isNaN(mailboxId)) {
            return c.json<ApiResponse>({
                success: false,
                error: '无效的邮箱ID'
            }, 400);
        }

        await deleteMailbox(c.env.DB, mailboxId);

        return c.json<ApiResponse>({
            success: true,
            message: '邮箱删除成功'
        });
    } catch (error) {
        errorLog('[邮箱API] 管理员删除邮箱失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '删除邮箱失败'
        }, 500);
    }
});

// ===================
// 邮箱申请管理
// ===================

/**
 * 获取所有申请（管理员）
 */
mailbox.get('/admin/applications', jwtAuthMiddleware, adminAuthMiddleware, async (c) => {
    try {
        const page = parseInt(c.req.query('page') || '1');
        const pageSize = parseInt(c.req.query('page_size') || '20');

        const result = await getAllMailboxApplications(c.env.DB, page, pageSize);

        return c.json<ApiResponse>({
            success: true,
            data: result
        });
    } catch (error) {
        errorLog('[邮箱API] 获取申请列表失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '获取申请列表失败'
        }, 500);
    }
});

/**
 * 处理申请（批准/拒绝）
 */
mailbox.post('/admin/applications/:id/process', jwtAuthMiddleware, adminAuthMiddleware, async (c) => {
    try {
        const admin = c.get('jwtPayload');
        const applicationId = parseInt(c.req.param('id'));
        const { action, admin_comment } = await c.req.json();

        if (isNaN(applicationId)) {
            return c.json<ApiResponse>({
                success: false,
                error: '无效的申请ID'
            }, 400);
        }

        if (!['approve', 'reject'].includes(action)) {
            return c.json<ApiResponse>({
                success: false,
                error: '无效的操作类型'
            }, 400);
        }

        await processMailboxApplication(c.env.DB, applicationId, admin.user_id, action, admin_comment);

        return c.json<ApiResponse>({
            success: true,
            message: action === 'approve' ? '申请已批准' : '申请已拒绝'
        });
    } catch (error) {
        errorLog('[邮箱API] 处理申请失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '处理申请失败'
        }, 500);
    }
});

export { mailbox };
