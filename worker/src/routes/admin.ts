/**
 * 管理员相关路由
 */

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { generateRandomString, hashPassword } from '../utils/crypto';
import { debugLog, errorLog } from '../utils/debug';
import { getPaginationParams, validatePassword } from '../config/constants';
import {
    getAllUsers,
    createUser,
    deleteUser,
    findUserById,
    findUserByUsername,
    updateUserSettings
} from '../services/user';
import {
    getAllEmails,
    getEmailById,
    deleteEmail
} from '../services/email';
import {
    getForwardRules,
    getForwardRuleById,
    createForwardRule,
    updateForwardRule,
    deleteForwardRule
} from '../services/webhook';
import {
    getAllSystemSettings,
    updateSystemConfig,
    getSystemConfig,
    refreshSystemSettings
} from '../services/settings';
import { jwtAuthMiddleware, adminAuthMiddleware } from '../middleware/auth';
import type {
    Env,
    ApiResponse,
    EmailQueryParams,
    ForwardRule,
    SystemConfig
} from '../types';

const admin = new Hono<{ Bindings: Env }>();

// 应用认证中间件
admin.use('*', jwtAuthMiddleware);
admin.use('*', adminAuthMiddleware);

/**
 * 获取所有用户
 */
admin.get('/users', async (c) => {
    try {
        const { page, limit } = getPaginationParams(c.req.query());
        const { search, user_type, created_after, created_before } = c.req.query();

        const searchParams = {
            search,
            user_type,
            created_after,
            created_before
        };

        const result = await getAllUsers(c.env.DB, page, limit, searchParams);

        return c.json<ApiResponse>({
            success: true,
            data: {
                users: result.users,
                total: result.total,
                page,
                limit,
                total_pages: Math.ceil(result.total / limit)
            }
        });
    } catch (error) {
        errorLog('[管理员-用户列表] 获取失败:', error);
        throw new HTTPException(500, { message: '获取用户列表失败' });
    }
});

/**
 * 创建用户
 */
admin.post('/users', async (c) => {
    try {
        const { password, user_type = 'user', username } = await c.req.json();

        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
            return c.json<ApiResponse>({
                success: false,
                error: passwordValidation.error!
            }, 400);
        }

        if (!['admin', 'user'].includes(user_type)) {
            return c.json<ApiResponse>({
                success: false,
                error: '用户类型必须为admin或user'
            }, 400);
        }

        if (!username) {
            return c.json<ApiResponse>({
                success: false,
                error: '用户名不能为空'
            }, 400);
        }

        // 验证用户名格式（只允许英文、数字、下划线、连字符）
        const usernameRegex = /^[a-zA-Z0-9_-]+$/;
        if (!usernameRegex.test(username)) {
            return c.json<ApiResponse>({
                success: false,
                error: '用户名只能包含英文字母、数字、下划线和连字符'
            }, 400);
        }

        // 检查用户名是否已存在
        const existingUser = await findUserByUsername(c.env.DB, username);
        if (existingUser) {
            return c.json<ApiResponse>({
                success: false,
                error: '用户名已存在'
            }, 400);
        }

        // 哈希密码
        const hashedPassword = await hashPassword(password);

        // 创建用户
        const user = await createUser(c.env.DB, username, hashedPassword, user_type);

        debugLog('[管理员-创建用户] 成功:', username, '类型:', user_type);

        return c.json<ApiResponse>({
            success: true,
            message: '用户创建成功',
            data: {
                id: user.id,
                username: user.username,
                user_type: user.user_type,
                created_at: user.created_at
            }
        });

    } catch (error) {
        errorLog('[管理员-创建用户] 失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '创建用户失败'
        }, 500);
    }
});

/**
 * 删除用户
 */
admin.delete('/users/:id', async (c) => {
    try {
        const userId = parseInt(c.req.param('id'));

        if (isNaN(userId)) {
            throw new HTTPException(400, { message: '无效的用户ID' });
        }

        // 检查用户是否存在
        const user = await findUserById(c.env.DB, userId);
        if (!user) {
            throw new HTTPException(404, { message: '用户不存在' });
        }

        // 防止删除管理员账户
        if (user.user_type === 'admin') {
            return c.json<ApiResponse>({
                success: false,
                error: '不能删除管理员账户'
            }, 403);
        }

        await deleteUser(c.env.DB, userId);

        debugLog('[管理员-删除用户] 成功，用户ID:', userId);

        return c.json<ApiResponse>({
            success: true,
            message: '用户删除成功'
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[管理员-删除用户] 失败:', error);
        throw new HTTPException(500, { message: '删除用户失败' });
    }
});

/**
 * 向用户发送账户信息
 */
admin.post('/users/:id/send-info', async (c) => {
    try {
        const userId = parseInt(c.req.param('id'));

        if (isNaN(userId)) {
            throw new HTTPException(400, { message: '无效的用户ID' });
        }

        const user = await findUserById(c.env.DB, userId);
        if (!user) {
            throw new HTTPException(404, { message: '用户不存在' });
        }

        // 获取请求数据
        const requestData = await c.req.json();
        const { to_email, from_email, subject, content, content_type = 'markdown' } = requestData;

        if (!to_email || !from_email || !subject || !content) {
            throw new HTTPException(400, { message: '缺少必要的邮件参数' });
        }

        // 创建模拟邮件数据
        let processedContent = content;
        let finalContentType = content_type;
        
        if (content_type === 'markdown') {
            // 对于Markdown内容，保持原样，让前端渲染
            processedContent = content;
            finalContentType = 'markdown';
        } else {
            // 对于其他类型，包装成HTML
            processedContent = `<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <h2>临时邮箱系统通知</h2>
                <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 10px 0;">
                    ${content.replace(/\n/g, '<br>')}
                </div>
                <p style="font-size: 12px; color: #666; margin-top: 20px;">
                    此邮件由临时邮箱系统自动发送
                </p>
            </div>`;
            finalContentType = 'html';
        }
        
        const emailData = {
            message_id: `admin-${Date.now()}@system`,
            sender_email: from_email,
            recipient_email: to_email,
            subject: subject,
            content: processedContent,
            content_type: finalContentType,
            has_attachments: false,
            received_at: new Date().toISOString()
        };

        // 将邮件保存到数据库
        const emailId = await c.env.DB.prepare(`
            INSERT INTO emails (message_id, user_id, sender_email, recipient_email, subject, content, content_type, has_attachments, received_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `).bind(
            emailData.message_id,
            userId,
            emailData.sender_email,
            emailData.recipient_email,
            emailData.subject,
            emailData.content,
            emailData.content_type,
            emailData.has_attachments ? 1 : 0,
            emailData.received_at
        ).run();

        debugLog('[管理员-发送用户信息] 邮件已发送到用户邮箱:', to_email, '邮件ID:', emailId.meta.last_row_id);

        return c.json<ApiResponse>({
            success: true,
            message: '用户信息邮件发送成功',
            data: {
                email_id: emailId.meta.last_row_id,
                to_email: to_email,
                from_email: from_email,
                subject: subject
            }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[管理员-发送用户信息] 失败:', error);
        throw new HTTPException(500, { message: '发送用户信息失败' });
    }
});

/**
 * 获取所有邮件（管理员视图）
 */
admin.get('/emails', async (c) => {
    try {
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

        const result = await getAllEmails(c.env.DB, queryParams);

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
        errorLog('[管理员-邮件列表] 获取失败:', error);
        throw new HTTPException(500, { message: '获取邮件列表失败' });
    }
});

/**
 * 获取转发规则列表
 */
admin.get('/forward-rules', async (c) => {
    try {
        const rules = await getForwardRules(c.env.DB);

        return c.json<ApiResponse>({
            success: true,
            data: { rules }
        });
    } catch (error) {
        errorLog('[管理员-转发规则] 获取失败:', error);
        throw new HTTPException(500, { message: '获取转发规则失败' });
    }
});

/**
 * 创建转发规则
 */
admin.post('/forward-rules', async (c) => {
    try {
        const ruleData = await c.req.json() as Omit<ForwardRule, 'id' | 'created_at' | 'updated_at'>;

        // 验证必填字段
        if (!ruleData.rule_name || !ruleData.webhook_url) {
            return c.json<ApiResponse>({
                success: false,
                error: '规则名称和Webhook URL不能为空'
            }, 400);
        }

        // 验证webhook URL格式
        if (!ruleData.webhook_url.startsWith('http')) {
            return c.json<ApiResponse>({
                success: false,
                error: 'Webhook URL必须以http或https开头'
            }, 400);
        }

        // 验证webhook类型
        if (!['dingtalk', 'feishu', 'custom'].includes(ruleData.webhook_type)) {
            return c.json<ApiResponse>({
                success: false,
                error: 'Webhook类型必须为dingtalk、feishu或custom'
            }, 400);
        }

        const rule = await createForwardRule(c.env.DB, ruleData);

        debugLog('[管理员-创建转发规则] 成功:', rule.rule_name);

        return c.json<ApiResponse>({
            success: true,
            message: '转发规则创建成功',
            data: { rule }
        });
    } catch (error) {
        errorLog('[管理员-创建转发规则] 失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '创建转发规则失败'
        }, 500);
    }
});

/**
 * 获取单个转发规则
 */
admin.get('/forward-rules/:id', async (c) => {
    try {
        const ruleId = parseInt(c.req.param('id'));

        if (isNaN(ruleId)) {
            throw new HTTPException(400, { message: '无效的规则ID' });
        }

        const rule = await getForwardRuleById(c.env.DB, ruleId);
        if (!rule) {
            throw new HTTPException(404, { message: '转发规则不存在' });
        }

        return c.json<ApiResponse>({
            success: true,
            data: { rule }
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[管理员-获取转发规则] 失败:', error);
        throw new HTTPException(500, { message: '获取转发规则失败' });
    }
});

/**
 * 更新转发规则
 */
admin.put('/forward-rules/:id', async (c) => {
    try {
        const ruleId = parseInt(c.req.param('id'));

        if (isNaN(ruleId)) {
            throw new HTTPException(400, { message: '无效的规则ID' });
        }

        const updates = await c.req.json();

        // 验证webhook URL格式（如果提供）
        if (updates.webhook_url && !updates.webhook_url.startsWith('http')) {
            return c.json<ApiResponse>({
                success: false,
                error: 'Webhook URL必须以http或https开头'
            }, 400);
        }

        // 验证webhook类型（如果提供）
        if (updates.webhook_type && !['dingtalk', 'feishu', 'custom'].includes(updates.webhook_type)) {
            return c.json<ApiResponse>({
                success: false,
                error: 'Webhook类型必须为dingtalk、feishu或custom'
            }, 400);
        }

        await updateForwardRule(c.env.DB, ruleId, updates);

        debugLog('[管理员-更新转发规则] 成功，规则ID:', ruleId);

        return c.json<ApiResponse>({
            success: true,
            message: '转发规则更新成功'
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[管理员-更新转发规则] 失败:', error);
        throw new HTTPException(500, { message: '更新转发规则失败' });
    }
});

/**
 * 删除转发规则
 */
admin.delete('/forward-rules/:id', async (c) => {
    try {
        const ruleId = parseInt(c.req.param('id'));

        if (isNaN(ruleId)) {
            throw new HTTPException(400, { message: '无效的规则ID' });
        }

        await deleteForwardRule(c.env.DB, ruleId);

        debugLog('[管理员-删除转发规则] 成功，规则ID:', ruleId);

        return c.json<ApiResponse>({
            success: true,
            message: '转发规则删除成功'
        });
    } catch (error) {
        if (error instanceof HTTPException) {
            throw error;
        }
        errorLog('[管理员-删除转发规则] 失败:', error);
        throw new HTTPException(500, { message: '删除转发规则失败' });
    }
});

/**
 * 获取系统设置
 */
admin.get('/settings', async (c) => {
    try {
        debugLog('[管理员-系统设置] 开始获取系统配置');
        const config = await getSystemConfig(c.env.DB);
        debugLog('[管理员-系统设置] 配置获取成功:', config);

        return c.json<ApiResponse>({
            success: true,
            data: { config }
        });
    } catch (error) {
        errorLog('[管理员-系统设置] 获取失败:', error);
        // 返回更详细的错误信息
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '获取系统设置失败'
        }, 500);
    }
});

/**
 * 更新系统设置
 */
admin.put('/settings', async (c) => {
    try {
        const updates = await c.req.json() as Partial<SystemConfig>;

        // 验证域名数组格式
        if (updates.domains && !Array.isArray(updates.domains)) {
            return c.json<ApiResponse>({
                success: false,
                error: '域名配置必须为数组格式'
            }, 400);
        }

        // 验证数值字段
        if (updates.cleanup_days !== undefined && (updates.cleanup_days < 1 || updates.cleanup_days > 365)) {
            return c.json<ApiResponse>({
                success: false,
                error: '清理天数必须在1-365之间'
            }, 400);
        }

        if (updates.max_attachment_size !== undefined && updates.max_attachment_size < 1024) {
            return c.json<ApiResponse>({
                success: false,
                error: '最大附件大小不能小于1KB'
            }, 400);
        }

        await updateSystemConfig(c.env.DB, updates);

        debugLog('[管理员-更新系统设置] 成功');

        return c.json<ApiResponse>({
            success: true,
            message: '系统设置更新成功'
        });
    } catch (error) {
        errorLog('[管理员-更新系统设置] 失败:', error);
        return c.json<ApiResponse>({
            success: false,
            error: error instanceof Error ? error.message : '更新系统设置失败'
        }, 500);
    }
});

/**
 * 刷新系统设置缓存
 */
admin.post('/settings/refresh', async (c) => {
    try {
        await refreshSystemSettings(c.env.DB);

        debugLog('[管理员-刷新设置缓存] 成功');

        return c.json<ApiResponse>({
            success: true,
            message: '系统设置缓存已刷新'
        });
    } catch (error) {
        errorLog('[管理员-刷新设置缓存] 失败:', error);
        throw new HTTPException(500, { message: '刷新系统设置缓存失败' });
    }
});

export { admin };
