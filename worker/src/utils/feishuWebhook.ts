import type { Email } from '../types/index.ts';

function truncateText(value: string | null | undefined, maxLength = 800): string {
    const text = (value || '').trim();
    return text.length <= maxLength ? text : `${text.slice(0, maxLength)}...`;
}

function isVerificationCodeContent(content: string | null | undefined): boolean {
    return /^Your Verification Code: [A-Za-z0-9]{4,10}$/.test((content || '').trim());
}

export function buildFeishuWebhookPayload(email: Email) {
    const subject = email.subject || '(无主题)';
    const fromAddress = email.from_address || '未知发件人';
    const toAddress = email.to_address || '未知收件人';
    const receivedAt = email.received_at || '-';
    const attachmentCount = email.attachment_count || 0;
    const content = truncateText(email.content || '(无内容)');
    const titleContent = isVerificationCodeContent(email.content)
        ? email.content!.trim()
        : subject;
    const title = `新邮件通知：${titleContent}`;

    return {
        msg_type: 'interactive',
        card: {
            header: {
                template: 'blue',
                title: {
                    content: title,
                    tag: 'plain_text'
                }
            },
            elements: [
                {
                    tag: 'div',
                    fields: [
                        {
                            is_short: true,
                            text: { tag: 'lark_md', content: `**发件人：** ${fromAddress}` }
                        },
                        {
                            is_short: true,
                            text: { tag: 'lark_md', content: `**收件人：** ${toAddress}` }
                        }
                    ]
                },
                {
                    tag: 'div',
                    fields: [
                        {
                            is_short: true,
                            text: { tag: 'lark_md', content: `**接收时间：** ${receivedAt}` }
                        },
                        {
                            is_short: true,
                            text: { tag: 'lark_md', content: `**附件数：** ${attachmentCount}` }
                        }
                    ]
                },
                {
                    tag: 'div',
                    text: {
                        tag: 'lark_md',
                        content: `**主题：** ${subject}`
                    }
                },
                {
                    tag: 'div',
                    text: {
                        tag: 'lark_md',
                        content: `**内容摘要：**\n${content}`
                    }
                }
            ]
        }
    };
}
