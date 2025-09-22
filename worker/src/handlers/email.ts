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
        infoLog('[邮件处理] 开始处理新邮件');

        // 提取邮件基本信息
        const messageId = message.headers.get('Message-ID') || `generated-${Date.now()}-${Math.random()}`;
        const senderEmail = message.from;
        const recipientEmail = message.to;
        const subject = message.headers.get('Subject') || '';

        infoLog('[邮件处理] 邮件信息:', {
            messageId,
            senderEmail,
            recipientEmail,
            subject
        });

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
            debugLog('[邮件处理] 未找到邮箱对应的用户:', recipientEmail);
            return;
        }

        infoLog('[邮件处理] 找到用户ID:', userId);

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

        // 处理邮件转发
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
            await handleIncomingEmail(message, env);
        } catch (error) {
            errorLog('[邮件路由] 处理失败:', error);
            // 不抛出错误，避免影响邮件路由
        }
    }
};
