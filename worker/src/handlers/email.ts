/**
 * 邮件处理器 - 处理接收到的邮件
 */

import { debugLog, errorLog, infoLog } from '../utils/debug';
import { createEmail, createAttachment, parseEmailAttachments } from '../services/email';
import { handleEmailForwarding } from '../services/webhook';
import { matchDomainForEmail } from '../services/settings';
import { getUserIdByEmail } from '../services/mailbox';
import type { Env, Email } from '../types';

/**
 * 处理接收到的邮件
 */
export async function handleIncomingEmail(message: any, env: Env): Promise<void> {
    try {
        infoLog('[邮件处理] ========== 开始处理新邮件 ==========');
        infoLog('[邮件处理] 时间戳:', new Date().toISOString());

        // 详细记录消息对象
        infoLog('[邮件处理] 消息对象检查:');
        infoLog('[邮件处理] - message 存在:', !!message);
        infoLog('[邮件处理] - message.from:', message?.from);
        infoLog('[邮件处理] - message.to:', message?.to);
        infoLog('[邮件处理] - message.headers 存在:', !!message?.headers);

        // 提取邮件基本信息
        let messageId: string;
        let senderEmail: string;
        let recipientEmail: string;
        let subject: string = '';

        try {
            // 尝试多种方式获取 Message-ID
            if (message.headers) {
                if (typeof message.headers.get === 'function') {
                    messageId = message.headers.get('Message-ID') || '';
                    subject = message.headers.get('Subject') || '';
                } else if (message.headers instanceof Map) {
                    messageId = message.headers.get('Message-ID') || '';
                    subject = message.headers.get('Subject') || '';
                } else {
                    messageId = message.headers['Message-ID'] || message.headers['message-id'] || '';
                    subject = message.headers['Subject'] || message.headers['subject'] || '';
                }
            } else {
                messageId = '';
            }

            if (!messageId) {
                messageId = `generated-${Date.now()}-${Math.random()}`;
                infoLog('[邮件处理] 未找到 Message-ID，生成新的:', messageId);
            }

            senderEmail = message.from || '';
            recipientEmail = message.to || '';

            infoLog('[邮件处理] 提取的邮件信息:');
            infoLog('[邮件处理] - Message-ID:', messageId);
            infoLog('[邮件处理] - 发件人:', senderEmail);
            infoLog('[邮件处理] - 收件人:', recipientEmail);
            infoLog('[邮件处理] - 主题:', subject);
        } catch (extractError) {
            errorLog('[邮件处理] 提取邮件基本信息失败:', extractError);
            throw new Error('无法提取邮件基本信息: ' + (extractError instanceof Error ? extractError.message : String(extractError)));
        }

        // 验证收件人邮箱格式
        if (!recipientEmail || !recipientEmail.includes('@')) {
            errorLog('[邮件处理] 无效的收件人邮箱格式:', recipientEmail);
            return;
        }

        // 提取邮件前缀（用户名部分）
        const [emailPrefix, domain] = recipientEmail.split('@');
        if (!emailPrefix || !domain) {
            errorLog('[邮件处理] 无法解析邮件地址:', recipientEmail);
            return;
        }

        // 验证域名是否在配置的域名列表中
        const matchedDomain = await matchDomainForEmail(env.DB, recipientEmail);
        if (!matchedDomain) {
            debugLog('[邮件处理] 域名不在配置列表中，跳过处理:', domain);
            return;
        }

        infoLog('[邮件处理] 域名匹配成功:', matchedDomain);

        // 根据邮箱地址获取用户ID
        const userId = await getUserIdByEmail(env.DB, recipientEmail);
        if (!userId) {
            // 未找到用户，但域名匹配成功（属于安全邮箱），保存邮件但 user_id 设为 null
            // 这样管理员可以查看这些邮件
            infoLog('[邮件处理] 未找到邮箱对应的用户，但域名匹配成功，保存邮件（user_id 为 null）:', recipientEmail);
        } else {
            infoLog('[邮件处理] 找到用户ID:', userId);
        }

        // 获取原始邮件内容
        const rawEmail = await message.raw();

        // 简单提取邮件内容
        let content = '';
        let contentType = 'text';

        try {
            // 优先获取HTML内容
            if (message.html) {
                const htmlContent = await message.html();
                if (htmlContent && htmlContent.trim()) {
                    content = htmlContent;
                    contentType = 'html';
                }
            }

            // 如果没有HTML内容，尝试获取纯文本内容
            if (!content && message.text) {
                const textContent = await message.text();
                if (textContent && textContent.trim()) {
                    content = textContent;
                    contentType = 'text';
                }
            }
        } catch (contentError) {
            debugLog('[邮件处理] 提取邮件内容时出错:', contentError);
        }

        // 解析附件
        const attachmentData = await parseEmailAttachments(rawEmail, env);
        const hasAttachments = attachmentData.length > 0;

        debugLog('[邮件处理] 解析到附件数量:', attachmentData.length);

        // 创建邮件记录
        const emailRecord: Omit<Email, 'id' | 'created_at' | 'updated_at'> = {
            message_id: messageId,
            user_id: userId,
            sender_email: senderEmail,
            recipient_email: recipientEmail,
            subject: subject || undefined,
            content: content || undefined,
            content_type: contentType as 'text' | 'html',
            raw_content: rawEmail, // 修复字段名，与数据库一致
            is_read: 0, // 新邮件默认为未读
            has_attachments: hasAttachments ? 1 : 0,
            received_at: new Date().toISOString()
        };

        infoLog('[邮件处理] 准备创建邮件记录:', emailRecord);
        const savedEmail = await createEmail(env.DB, emailRecord);
        infoLog('[邮件处理] 邮件保存成功，ID:', savedEmail.id);

        // 保存附件记录
        for (const attachment of attachmentData) {
            try {
                await createAttachment(env.DB, {
                    ...attachment,
                    email_id: savedEmail.id
                });
                debugLog('[邮件处理] 附件保存成功:', attachment.filename);
            } catch (attachmentError) {
                errorLog('[邮件处理] 附件保存失败: ' + attachment.filename, attachmentError);
            }
        }

        // 处理邮件转发（只有找到用户时才处理个人 webhook，全局转发规则始终处理）
        try {
            await handleEmailForwarding(savedEmail, userId, env.DB);
            debugLog('[邮件处理] 邮件转发处理完成');
        } catch (forwardError) {
            errorLog('[邮件处理] 邮件转发失败:', forwardError);
        }

        infoLog('[邮件处理] 邮件处理完成:', messageId);

    } catch (error) {
        errorLog('[邮件处理] 处理邮件时发生错误:', error);
        throw error;
    }
}


/**
 * 邮件路由处理器 - Cloudflare Email Routing 入口点
 */
export default {
    async email(message: any, env: Env, ctx: any) {
        try {
            // 详细记录邮件消息对象结构
            infoLog('[邮件路由] ========== 收到新邮件 ==========');
            infoLog('[邮件路由] 消息对象类型:', typeof message);
            infoLog('[邮件路由] 消息对象键:', Object.keys(message || {}));

            // 记录基本属性
            if (message) {
                infoLog('[邮件路由] message.from:', message.from);
                infoLog('[邮件路由] message.to:', message.to);
                infoLog('[邮件路由] message.headers 类型:', typeof message.headers);

                // 尝试获取 headers
                if (message.headers) {
                    if (typeof message.headers.get === 'function') {
                        infoLog('[邮件路由] Message-ID:', message.headers.get('Message-ID'));
                        infoLog('[邮件路由] Subject:', message.headers.get('Subject'));
                        infoLog('[邮件路由] From:', message.headers.get('From'));
                        infoLog('[邮件路由] To:', message.headers.get('To'));
                    } else if (message.headers instanceof Map) {
                        infoLog('[邮件路由] Headers Map 内容:', Array.from(message.headers.entries()));
                    } else {
                        infoLog('[邮件路由] Headers 对象:', message.headers);
                    }
                }

                // 检查可用的方法
                const availableMethods = [];
                if (typeof message.raw === 'function') availableMethods.push('raw');
                if (typeof message.text === 'function') availableMethods.push('text');
                if (typeof message.html === 'function') availableMethods.push('html');
                infoLog('[邮件路由] 可用方法:', availableMethods);
            }

            infoLog('[邮件路由] 环境变量检查:');
            infoLog('[邮件路由] - DB 存在:', !!env.DB);
            infoLog('[邮件路由] - R2 存在:', !!env.R2);

            await handleIncomingEmail(message, env);

            infoLog('[邮件路由] ========== 邮件处理完成 ==========');
        } catch (error) {
            errorLog('[邮件路由] ========== 处理失败 ==========');
            errorLog('[邮件路由] 错误类型:', error instanceof Error ? error.constructor.name : typeof error);
            errorLog('[邮件路由] 错误消息:', error instanceof Error ? error.message : String(error));
            errorLog('[邮件路由] 错误堆栈:', error instanceof Error ? error.stack : '无堆栈信息');
            errorLog('[邮件路由] 完整错误对象:', JSON.stringify(error, Object.getOwnPropertyNames(error), 2));
            // 不抛出错误，避免影响邮件路由
        }
    }
};
