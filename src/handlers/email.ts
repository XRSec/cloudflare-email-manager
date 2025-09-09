/**
 * 邮件处理器 - 处理接收到的邮件
 */

import { debugLog, errorLog, infoLog } from '../utils/debug';
import { findUserByPrefix } from '../services/user';
import { createEmail, createAttachment, parseEmailAttachments } from '../services/email';
import { handleEmailForwarding } from '../services/webhook';
import { matchDomainForEmail } from '../services/settings';
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

        debugLog('[邮件处理] 邮件信息:', {
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

        debugLog('[邮件处理] 域名匹配成功:', matchedDomain);

        // 查找对应的用户
        const user = await findUserByPrefix(env.DB, emailPrefix);
        if (!user) {
            debugLog('[邮件处理] 未找到对应用户:', emailPrefix);
            return;
        }

        debugLog('[邮件处理] 找到用户:', user.email_prefix, '类型:', user.user_type);

        // 获取原始邮件内容
        const rawEmail = await message.raw();

        // 提取邮件内容
        let textContent = '';
        let htmlContent = '';

        try {
            // 尝试获取纯文本内容
            if (message.text) {
                textContent = await message.text();
            }

            // 尝试获取HTML内容
            if (message.html) {
                htmlContent = await message.html();
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
            user_id: user.id,
            sender_email: senderEmail,
            recipient_email: recipientEmail,
            subject: subject || undefined,
            text_content: textContent || undefined,
            html_content: htmlContent || undefined,
            raw_email: rawEmail,
            has_attachments: hasAttachments ? 1 : 0,
            received_at: new Date().toISOString()
        };

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
            await handleEmailForwarding(savedEmail, user, env.DB);
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
