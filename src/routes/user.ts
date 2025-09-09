/**
 * 用户相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { hashPassword } from '../utils/crypto';
import { debugLog, errorLog } from '../utils/debug';
import { getPaginationParams } from '../config/constants';
import { findUserById, updateUserSettings } from '../services/user';
import { getUserEmails, getEmailById, deleteEmail, getEmailAttachments, getAttachmentById } from '../services/email';
import { jwtAuthMiddleware } from '../middleware/auth';
import type { Env, ApiResponse, EmailQueryParams, UserSettingsUpdate } from '../types';

const user = new Hono<{ Bindings: Env }>();

// 应用JWT认证中间件到所有用户路由
user.use('*', jwtAuthMiddleware);

/**
 * 获取当前用户信息
 */
user.get('/me', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const userData = await findUserById(c.env.DB, payload.user_id);

        if (!userData) {
            throw new HTTPException(404, { message: '用户不存在' });
        }

        return c.json<ApiResponse>({
            success: true,
            data: {
                id: userData.id,
                email_prefix: userData.email_prefix,
                user_type: userData.user_type,
                webhook_url: userData.webhook_url,
                created_at: userData.created_at,
                updated_at: userData.updated_at
            }
        });
    } catch (error) {
        errorLog('[用户信息] 获取失败:', error);
        throw new HTTPException(500, { message: '获取用户信息失败' });
    }
});

/**
 * 获取用户设置
 */
user.get('/settings', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const userData = await findUserById(c.env.DB, payload.user_id);

        if (!userData) {
            throw new HTTPException(404, { message: '用户不存在' });
        }

        return c.json<ApiResponse>({
            success: true,
            data: {
                email_prefix: userData.email_prefix,
                webhook_url: userData.webhook_url,
                webhook_secret: userData.webhook_secret ? '***已设置***' : '', // 不返回实际密钥
                user_type: userData.user_type
            }
        });
    } catch (error) {
        errorLog('[用户设置] 获取失败:', error);
        throw new HTTPException(500, { message: '获取用户设置失败' });
    }
});

/**
 * 更新用户设置
 */
user.put('/settings', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const updates = await c.req.json() as UserSettingsUpdate;

        debugLog('[用户设置] 更新请求:', JSON.stringify(updates, null, 2));

        // 验证输入
        const validatedUpdates: UserSettingsUpdate = {};

        // 处理密码更新
        if (updates.email_password && updates.email_password.trim()) {
            if (updates.email_password.length < 6) {
                return c.json<ApiResponse>({
                    success: false,
                    error: '密码长度至少为6位'
                }, 400);
            }
            validatedUpdates.email_password = await hashPassword(updates.email_password);
        }

        // 处理webhook URL更新
        if (updates.webhook_url !== undefined) {
            const webhookUrl = updates.webhook_url.trim();
            if (webhookUrl && !webhookUrl.startsWith('http')) {
                return c.json<ApiResponse>({
                    success: false,
                    error: 'Webhook URL必须以http或https开头'
                }, 400);
            }
            validatedUpdates.webhook_url = webhookUrl || undefined;
        }

        // 处理webhook secret更新
        if (updates.webhook_secret !== undefined) {
            const webhookSecret = updates.webhook_secret.trim();
            validatedUpdates.webhook_secret = webhookSecret || undefined;
        }

        // 检查是否有需要更新的内容
        if (Object.keys(validatedUpdates).length === 0) {
            return c.json<ApiResponse>({
                success: false,
                error: '没有需要更新的内容'
            }, 400);
        }

        // 执行更新
        await updateUserSettings(c.env.DB, payload.user_id, validatedUpdates);

        debugLog('[用户设置] 更新成功，用户ID:', payload.user_id);

        return c.json<ApiResponse>({
            success: true,
            message: '设置更新成功'
        });

    } catch (error) {
        errorLog('[用户设置] 更新失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '更新设置失败'
        }, 500);
    }
});

/**
 * 获取用户邮件列表
 */
user.get('/emails', async (c) => {
    try {
        const payload = c.get('jwtPayload');

        // 解析查询参数
        const queryParams: EmailQueryParams = {
            ...getPaginationParams(c.req.query()),
            search: c.req.query('search'),
            sender: c.req.query('sender'),
            subject: c.req.query('subject'),
            start_date: c.req.query('start_date'),
            end_date: c.req.query('end_date'),
            has_attachments: c.req.query('has_attachments') === 'true' ? true :
                           c.req.query('has_attachments') === 'false' ? false : undefined,
            sort: c.req.query('sort') || 'received_at',
            order: (c.req.query('order') as 'asc' | 'desc') || 'desc'
        };

        const result = await getUserEmails(c.env.DB, payload.user_id, queryParams);

        return c.json<ApiResponse>({
            success: true,
            data: {
                emails: result.emails,
                total: result.total,
                page: queryParams.page,
                limit: queryParams.limit,
                total_pages: Math.ceil(result.total / queryParams.limit!)
            }
        });
    } catch (error) {
        errorLog('[用户邮件] 获取失败:', error);
        throw new HTTPException(500, { message: '获取邮件列表失败' });
    }
});

/**
 * 获取邮件详情
 */
user.get('/emails/:id', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const emailId = parseInt(c.req.param('id'));

        if (isNaN(emailId)) {
            throw new HTTPException(400, { message: '无效的邮件ID' });
        }

        const email = await getEmailById(c.env.DB, emailId);
        if (!email) {
            throw new HTTPException(404, { message: '邮件不存在' });
        }

        // 检查权限：普通用户只能查看自己的邮件
        if (payload.user_type !== 'admin' && email.user_id !== payload.user_id) {
            throw new HTTPException(403, { message: '无权访问此邮件' });
        }

        // 获取附件列表
        const attachments = await getEmailAttachments(c.env.DB, emailId);

        return c.json<ApiResponse>({
            success: true,
            data: {
                ...email,
                attachments
            }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[邮件详情] 获取失败:', error);
        throw new HTTPException(500, { message: '获取邮件详情失败' });
    }
});

/**
 * 删除邮件
 */
user.delete('/emails/:id', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const emailId = parseInt(c.req.param('id'));

        if (isNaN(emailId)) {
            throw new HTTPException(400, { message: '无效的邮件ID' });
        }

        const email = await getEmailById(c.env.DB, emailId);
        if (!email) {
            throw new HTTPException(404, { message: '邮件不存在' });
        }

        // 检查权限：普通用户只能删除自己的邮件
        if (payload.user_type !== 'admin' && email.user_id !== payload.user_id) {
            throw new HTTPException(403, { message: '无权删除此邮件' });
        }

        await deleteEmail(c.env.DB, c.env.R2, emailId);

        debugLog('[删除邮件] 成功，邮件ID:', emailId);

        return c.json<ApiResponse>({
            success: true,
            message: '邮件删除成功'
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[删除邮件] 失败:', error);
        throw new HTTPException(500, { message: '删除邮件失败' });
    }
});

/**
 * 下载附件
 */
user.get('/attachments/:id/download', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const attachmentId = parseInt(c.req.param('id'));

        if (isNaN(attachmentId)) {
            throw new HTTPException(400, { message: '无效的附件ID' });
        }

        const attachment = await getAttachmentById(c.env.DB, attachmentId);
        if (!attachment) {
            throw new HTTPException(404, { message: '附件不存在' });
        }

        // 获取邮件信息以检查权限
        const email = await getEmailById(c.env.DB, attachment.email_id);
        if (!email) {
            throw new HTTPException(404, { message: '关联邮件不存在' });
        }

        // 检查权限：普通用户只能下载自己邮件的附件
        if (payload.user_type !== 'admin' && email.user_id !== payload.user_id) {
            throw new HTTPException(403, { message: '无权下载此附件' });
        }

        // 从R2获取文件
        const object = await c.env.R2.get(attachment.r2_key);
        if (!object) {
            throw new HTTPException(404, { message: '附件文件不存在' });
        }

        debugLog('[下载附件] 成功，文件名:', attachment.filename);

        return new Response(object.body as any, {
            headers: {
                'Content-Type': attachment.content_type,
                'Content-Disposition': `attachment; filename="${encodeURIComponent(attachment.filename)}"`,
                'Content-Length': attachment.size_bytes.toString(),
            }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[下载附件] 失败:', error);
        throw new HTTPException(500, { message: '下载附件失败' });
    }
});

export { user };
