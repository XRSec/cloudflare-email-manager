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
import { 
    getUserWebhooks, 
    createUserWebhook, 
    updateUserWebhook, 
    deleteUserWebhook,
    getUserWebhookById 
} from '../services/user-webhook';
import { 
    getForwardRules, 
    createForwardRule, 
    updateForwardRule, 
    deleteForwardRule,
    getForwardRuleById 
} from '../services/webhook';
import { findMailboxesByUserId } from '../services/mailbox';
import { jwtAuthMiddleware } from '../middleware/auth';
import type { Env, ApiResponse, EmailQueryParams, UserSettingsUpdate, ForwardRule } from '../types';

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
                username: userData.username,
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
                username: userData.username,
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
        if (updates.password && updates.password.trim()) {
            if (updates.password.length < 6) {
                return c.json<ApiResponse>({
                    success: false,
                    error: '密码长度至少为6位'
                }, 400);
            }
            validatedUpdates.password = await hashPassword(updates.password);
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

// ===================
// 用户Webhook管理
// ===================

/**
 * 获取用户的所有webhook配置
 */
user.get('/webhooks', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const webhooks = await getUserWebhooks(c.env.DB, payload.user_id);

        return c.json<ApiResponse>({
            success: true,
            data: { webhooks }
        });
    } catch (error) {
        errorLog('[用户Webhook] 获取失败:', error);
        throw new HTTPException(500, { message: '获取webhook配置失败' });
    }
});

/**
 * 创建用户webhook配置
 */
user.post('/webhooks', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const { webhook_name, webhook_url, webhook_secret, webhook_type = 'custom' } = await c.req.json();

        if (!webhook_name || !webhook_url) {
            return c.json<ApiResponse>({
                success: false,
                error: 'webhook名称和URL不能为空'
            }, 400);
        }

        if (!webhook_url.startsWith('http')) {
            return c.json<ApiResponse>({
                success: false,
                error: 'Webhook URL必须以http或https开头'
            }, 400);
        }

        const webhook = await createUserWebhook(c.env.DB, payload.user_id, {
            webhook_name,
            webhook_url,
            webhook_secret,
            webhook_type
        });

        return c.json<ApiResponse>({
            success: true,
            message: 'Webhook配置创建成功',
            data: { webhook }
        });
    } catch (error) {
        errorLog('[用户Webhook] 创建失败:', error);
        throw new HTTPException(500, { message: '创建webhook配置失败' });
    }
});

/**
 * 更新用户webhook配置
 */
user.put('/webhooks/:id', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const webhookId = parseInt(c.req.param('id'));
        const updates = await c.req.json();

        if (isNaN(webhookId)) {
            return c.json<ApiResponse>({
                success: false,
                error: '无效的webhook ID'
            }, 400);
        }

        if (updates.webhook_url && !updates.webhook_url.startsWith('http')) {
            return c.json<ApiResponse>({
                success: false,
                error: 'Webhook URL必须以http或https开头'
            }, 400);
        }

        await updateUserWebhook(c.env.DB, webhookId, payload.user_id, updates);

        return c.json<ApiResponse>({
            success: true,
            message: 'Webhook配置更新成功'
        });
    } catch (error) {
        errorLog('[用户Webhook] 更新失败:', error);
        throw new HTTPException(500, { message: '更新webhook配置失败' });
    }
});

/**
 * 删除用户webhook配置
 */
user.delete('/webhooks/:id', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const webhookId = parseInt(c.req.param('id'));

        if (isNaN(webhookId)) {
            return c.json<ApiResponse>({
                success: false,
                error: '无效的webhook ID'
            }, 400);
        }

        await deleteUserWebhook(c.env.DB, webhookId, payload.user_id);

        return c.json<ApiResponse>({
            success: true,
            message: 'Webhook配置删除成功'
        });
    } catch (error) {
        errorLog('[用户Webhook] 删除失败:', error);
        throw new HTTPException(500, { message: '删除webhook配置失败' });
    }
});

// ===================
// 用户转发规则管理
// ===================

/**
 * 获取用户的转发规则列表
 */
user.get('/forward-rules', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const rules = await getForwardRules(c.env.DB);

        // 过滤出只包含用户自己邮箱的规则
        const userMailboxes = await c.env.DB.prepare(`
            SELECT email_address FROM mailboxes WHERE user_id = ?
        `).bind(payload.user_id).all();

        const userEmails = userMailboxes.results.map(row => row.email_address as string);
        
        const userRules = rules.filter(rule => {
            // 如果规则有收件人过滤，检查是否包含用户的邮箱
            if (rule.recipient_filter) {
                return userEmails.some(email => email.includes(rule.recipient_filter!));
            }
            return true; // 没有收件人过滤的规则，用户可以看到
        });

        return c.json<ApiResponse>({
            success: true,
            data: { rules: userRules }
        });
    } catch (error) {
        errorLog('[用户转发规则] 获取失败:', error);
        throw new HTTPException(500, { message: '获取转发规则失败' });
    }
});

/**
 * 创建用户转发规则
 */
user.post('/forward-rules', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const ruleData = await c.req.json() as Omit<ForwardRule, 'id' | 'created_at' | 'updated_at'>;

        // 验证必填字段
        if (!ruleData.rule_name || !ruleData.webhook_url) {
            throw new HTTPException(400, { message: '规则名称和Webhook URL不能为空' });
        }

        // 验证收件人过滤是否包含用户的邮箱
        if (ruleData.recipient_filter) {
            const userMailboxes = await c.env.DB.prepare(`
                SELECT email_address FROM mailboxes WHERE user_id = ?
            `).bind(payload.user_id).all();

            const userEmails = userMailboxes.results.map(row => row.email_address as string);
            const hasUserEmail = userEmails.some(email => email.includes(ruleData.recipient_filter!));

            if (!hasUserEmail) {
                throw new HTTPException(400, { message: '收件人过滤必须包含您的邮箱地址' });
            }
        }

        const rule = await createForwardRule(c.env.DB, ruleData);

        return c.json<ApiResponse>({
            success: true,
            message: '转发规则创建成功',
            data: { rule }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[用户转发规则] 创建失败:', error);
        throw new HTTPException(500, { message: '创建转发规则失败' });
    }
});

/**
 * 获取单个用户转发规则
 */
user.get('/forward-rules/:id', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const ruleId = parseInt(c.req.param('id'));

        if (isNaN(ruleId)) {
            throw new HTTPException(400, { message: '无效的规则ID' });
        }

        const rule = await getForwardRuleById(c.env.DB, ruleId);
        if (!rule) {
            throw new HTTPException(404, { message: '转发规则不存在' });
        }

        // 验证用户是否有权限访问此规则
        if (rule.recipient_filter) {
            const userMailboxes = await c.env.DB.prepare(`
                SELECT email_address FROM mailboxes WHERE user_id = ?
            `).bind(payload.user_id).all();

            const userEmails = userMailboxes.results.map(row => row.email_address as string);
            const hasUserEmail = userEmails.some(email => email.includes(rule.recipient_filter!));

            if (!hasUserEmail) {
                throw new HTTPException(403, { message: '您没有权限访问此转发规则' });
            }
        }

        return c.json<ApiResponse>({
            success: true,
            data: { rule }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[用户转发规则] 获取失败:', error);
        throw new HTTPException(500, { message: '获取转发规则失败' });
    }
});

/**
 * 更新用户转发规则
 */
user.put('/forward-rules/:id', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const ruleId = parseInt(c.req.param('id'));

        if (isNaN(ruleId)) {
            throw new HTTPException(400, { message: '无效的规则ID' });
        }

        const rule = await getForwardRuleById(c.env.DB, ruleId);
        if (!rule) {
            throw new HTTPException(404, { message: '转发规则不存在' });
        }

        // 验证用户是否有权限修改此规则
        if (rule.recipient_filter) {
            const userMailboxes = await c.env.DB.prepare(`
                SELECT email_address FROM mailboxes WHERE user_id = ?
            `).bind(payload.user_id).all();

            const userEmails = userMailboxes.results.map(row => row.email_address as string);
            const hasUserEmail = userEmails.some(email => email.includes(rule.recipient_filter!));

            if (!hasUserEmail) {
                throw new HTTPException(403, { message: '您没有权限修改此转发规则' });
            }
        }

        const updates = await c.req.json() as Partial<ForwardRule>;

        // 验证更新后的收件人过滤是否包含用户的邮箱
        if (updates.recipient_filter) {
            const userMailboxes = await c.env.DB.prepare(`
                SELECT email_address FROM mailboxes WHERE user_id = ?
            `).bind(payload.user_id).all();

            const userEmails = userMailboxes.results.map(row => row.email_address as string);
            const hasUserEmail = userEmails.some(email => email.includes(updates.recipient_filter!));

            if (!hasUserEmail) {
                throw new HTTPException(400, { message: '收件人过滤必须包含您的邮箱地址' });
            }
        }

        await updateForwardRule(c.env.DB, ruleId, updates);

        return c.json<ApiResponse>({
            success: true,
            message: '转发规则更新成功'
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[用户转发规则] 更新失败:', error);
        throw new HTTPException(500, { message: '更新转发规则失败' });
    }
});

/**
 * 删除用户转发规则
 */
user.delete('/forward-rules/:id', async (c) => {
    try {
        const payload = c.get('jwtPayload');
        const ruleId = parseInt(c.req.param('id'));

        if (isNaN(ruleId)) {
            throw new HTTPException(400, { message: '无效的规则ID' });
        }

        const rule = await getForwardRuleById(c.env.DB, ruleId);
        if (!rule) {
            throw new HTTPException(404, { message: '转发规则不存在' });
        }

        // 验证用户是否有权限删除此规则
        if (rule.recipient_filter) {
            const userMailboxes = await c.env.DB.prepare(`
                SELECT email_address FROM mailboxes WHERE user_id = ?
            `).bind(payload.user_id).all();

            const userEmails = userMailboxes.results.map(row => row.email_address as string);
            const hasUserEmail = userEmails.some(email => email.includes(rule.recipient_filter!));

            if (!hasUserEmail) {
                throw new HTTPException(403, { message: '您没有权限删除此转发规则' });
            }
        }

        await deleteForwardRule(c.env.DB, ruleId);

        return c.json<ApiResponse>({
            success: true,
            message: '转发规则删除成功'
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[用户转发规则] 删除失败:', error);
        throw new HTTPException(500, { message: '删除转发规则失败' });
    }
});

// 用户邮箱管理
user.get('/mailboxes', jwtAuthMiddleware, async (c) => {
    try {
        const jwtPayload = c.get('jwtPayload');
        const mailboxes = await findMailboxesByUserId(c.env.DB, jwtPayload.user_id);
        
        return c.json({
            success: true,
            data: mailboxes
        });
    } catch (error) {
        errorLog('[用户邮箱] 获取失败:', error);
        throw new HTTPException(500, { message: '获取邮箱列表失败' });
    }
});

export { user };
