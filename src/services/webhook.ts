/**
 * Webhook 服务
 */

import { signJWT } from '../utils/crypto';
import type { Email, User, ForwardRule, ForwardLog } from '../types';
import type { D1Database } from '@cloudflare/workers-types';

/**
 * 发送 Webhook
 */
export async function sendWebhook(
    url: string,
    data: any,
    secret?: string,
    type: string = 'custom'
): Promise<{ success: boolean; responseCode?: number; errorMessage?: string }> {
    try {
        let payload: any;
        let headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'User-Agent': 'CloudflareTempEmail/1.0'
        };

        // 根据webhook类型构造不同的消息格式
        switch (type) {
            case 'dingtalk':
                payload = {
                    msgtype: 'text',
                    text: {
                        content: `新邮件通知\n发件人: ${data.sender_email}\n主题: ${data.subject || '(无主题)'}\n内容: ${data.text_content?.substring(0, 200) || '(无内容)'}...`
                    }
                };
                break;
            case 'feishu':
                payload = {
                    msg_type: 'text',
                    content: {
                        text: `新邮件通知\n发件人: ${data.sender_email}\n主题: ${data.subject || '(无主题)'}\n内容: ${data.text_content?.substring(0, 200) || '(无内容)'}...`
                    }
                };
                break;
            default:
                payload = data;
                break;
        }

        // 添加签名验证
        if (secret) {
            const timestamp = Math.floor(Date.now() / 1000).toString();
            const signString = timestamp + JSON.stringify(payload);
            const signature = await signJWT(signString, secret);
            headers['X-Timestamp'] = timestamp;
            headers['X-Signature'] = signature;
        }

        const response = await fetch(url, {
            method: 'POST',
            headers,
            body: JSON.stringify(payload)
        });

        return {
            success: response.ok,
            responseCode: response.status,
            errorMessage: response.ok ? undefined : `HTTP ${response.status}: ${response.statusText}`
        };
    } catch (error) {
        console.error('Webhook发送失败:', error);
        return {
            success: false,
            errorMessage: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}

/**
 * 邮件过滤函数 - 检查邮件是否匹配转发规则
 */
export function matchForwardRule(email: Email, rule: ForwardRule): boolean {
    // 检查发件人过滤器
    if (rule.sender_filter) {
        const senderPattern = rule.sender_filter.toLowerCase();
        if (!email.sender_email.toLowerCase().includes(senderPattern)) {
            return false;
        }
    }

    // 检查收件人过滤器
    if (rule.recipient_filter) {
        const recipientPattern = rule.recipient_filter.toLowerCase();
        if (!email.recipient_email.toLowerCase().includes(recipientPattern)) {
            return false;
        }
    }

    // 检查关键字过滤器
    if (rule.keyword_filter) {
        const keyword = rule.keyword_filter.toLowerCase();
        const subject = (email.subject || '').toLowerCase();
        const content = (email.text_content || '').toLowerCase();
        if (!subject.includes(keyword) && !content.includes(keyword)) {
            return false;
        }
    }

    return true;
}

/**
 * 处理邮件转发
 */
export async function handleEmailForwarding(email: Email, user: User, db: D1Database): Promise<void> {
    try {
        // 获取启用的转发规则
        const rulesResult = await db.prepare(`
            SELECT id, rule_name, sender_filter, keyword_filter, recipient_filter,
                   webhook_url, webhook_secret, webhook_type, enabled
            FROM forward_rules
            WHERE enabled = 1
        `).all();

        const rules = rulesResult.results as unknown as ForwardRule[];

        // 检查用户个人 webhook
        if (user.webhook_url) {
            console.log(`发送用户个人webhook: ${user.webhook_url}`);
            const result = await sendWebhook(
                user.webhook_url,
                email,
                user.webhook_secret,
                'custom'
            );

            // 记录转发日志
            await logForwardResult(db, email.id, null, user.webhook_url, result);
        }

        // 检查全局转发规则
        for (const rule of rules) {
            if (matchForwardRule(email, rule)) {
                console.log(`邮件匹配转发规则: ${rule.rule_name}`);
                const result = await sendWebhook(
                    rule.webhook_url,
                    email,
                    rule.webhook_secret,
                    rule.webhook_type
                );

                // 记录转发日志
                await logForwardResult(db, email.id, rule.id, rule.webhook_url, result);
            }
        }
    } catch (error) {
        console.error('处理邮件转发失败:', error);
    }
}

/**
 * 记录转发日志
 */
async function logForwardResult(
    db: D1Database,
    emailId: number,
    ruleId: number | null,
    webhookUrl: string,
    result: { success: boolean; responseCode?: number; errorMessage?: string }
): Promise<void> {
    try {
        await db.prepare(`
            INSERT INTO forward_logs (
                email_id, rule_id, webhook_url, status, response_code, error_message,
                sent_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        `).bind(
            emailId,
            ruleId,
            webhookUrl,
            result.success ? 'success' : 'failed',
            result.responseCode || null,
            result.errorMessage || null
        ).run();
    } catch (error) {
        console.error('记录转发日志失败:', error);
    }
}

/**
 * 获取转发规则列表
 */
export async function getForwardRules(db: D1Database): Promise<ForwardRule[]> {
    const result = await db.prepare(`
        SELECT id, rule_name, sender_filter, keyword_filter, recipient_filter,
               webhook_url, webhook_secret, webhook_type, enabled,
               created_at, updated_at
        FROM forward_rules
        ORDER BY created_at DESC
    `).all();

    return result.results.map(row => ({
        id: row.id as number,
        rule_name: row.rule_name as string,
        sender_filter: row.sender_filter as string | undefined,
        keyword_filter: row.keyword_filter as string | undefined,
        recipient_filter: row.recipient_filter as string | undefined,
        webhook_url: row.webhook_url as string,
        webhook_secret: row.webhook_secret as string | undefined,
        webhook_type: row.webhook_type as 'dingtalk' | 'feishu' | 'custom',
        enabled: row.enabled as number,
        created_at: row.created_at as string | undefined,
        updated_at: row.updated_at as string | undefined,
    }));
}

/**
 * 创建转发规则
 */
export async function createForwardRule(
    db: D1Database,
    rule: Omit<ForwardRule, 'id' | 'created_at' | 'updated_at'>
): Promise<ForwardRule> {
    const result = await db.prepare(`
        INSERT INTO forward_rules (
            rule_name, sender_filter, keyword_filter, recipient_filter,
            webhook_url, webhook_secret, webhook_type, enabled,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).bind(
        rule.rule_name,
        rule.sender_filter || null,
        rule.keyword_filter || null,
        rule.recipient_filter || null,
        rule.webhook_url,
        rule.webhook_secret || null,
        rule.webhook_type,
        rule.enabled
    ).run();

    if (!result.success) {
        throw new Error('Failed to create forward rule');
    }

    const createdRule = await db.prepare(`
        SELECT id, rule_name, sender_filter, keyword_filter, recipient_filter,
               webhook_url, webhook_secret, webhook_type, enabled,
               created_at, updated_at
        FROM forward_rules
        WHERE id = ?
    `).bind(result.meta.last_row_id).first();

    if (!createdRule) {
        throw new Error('Failed to retrieve created rule');
    }

    return {
        id: createdRule.id as number,
        rule_name: createdRule.rule_name as string,
        sender_filter: createdRule.sender_filter as string | undefined,
        keyword_filter: createdRule.keyword_filter as string | undefined,
        recipient_filter: createdRule.recipient_filter as string | undefined,
        webhook_url: createdRule.webhook_url as string,
        webhook_secret: createdRule.webhook_secret as string | undefined,
        webhook_type: createdRule.webhook_type as 'dingtalk' | 'feishu' | 'custom',
        enabled: createdRule.enabled as number,
        created_at: createdRule.created_at as string | undefined,
        updated_at: createdRule.updated_at as string | undefined,
    };
}

/**
 * 更新转发规则
 */
export async function updateForwardRule(
    db: D1Database,
    id: number,
    updates: Partial<Omit<ForwardRule, 'id' | 'created_at' | 'updated_at'>>
): Promise<void> {
    const setParts: string[] = [];
    const values: any[] = [];

    if (updates.rule_name !== undefined) {
        setParts.push('rule_name = ?');
        values.push(updates.rule_name);
    }

    if (updates.sender_filter !== undefined) {
        setParts.push('sender_filter = ?');
        values.push(updates.sender_filter || null);
    }

    if (updates.keyword_filter !== undefined) {
        setParts.push('keyword_filter = ?');
        values.push(updates.keyword_filter || null);
    }

    if (updates.recipient_filter !== undefined) {
        setParts.push('recipient_filter = ?');
        values.push(updates.recipient_filter || null);
    }

    if (updates.webhook_url !== undefined) {
        setParts.push('webhook_url = ?');
        values.push(updates.webhook_url);
    }

    if (updates.webhook_secret !== undefined) {
        setParts.push('webhook_secret = ?');
        values.push(updates.webhook_secret || null);
    }

    if (updates.webhook_type !== undefined) {
        setParts.push('webhook_type = ?');
        values.push(updates.webhook_type);
    }

    if (updates.enabled !== undefined) {
        setParts.push('enabled = ?');
        values.push(updates.enabled);
    }

    if (setParts.length === 0) {
        return; // 没有需要更新的字段
    }

    setParts.push('updated_at = CURRENT_TIMESTAMP');
    values.push(id);

    const sql = `UPDATE forward_rules SET ${setParts.join(', ')} WHERE id = ?`;
    const result = await db.prepare(sql).bind(...values).run();

    if (!result.success) {
        throw new Error('Failed to update forward rule');
    }
}

/**
 * 删除转发规则
 */
export async function deleteForwardRule(db: D1Database, id: number): Promise<void> {
    const result = await db.prepare(`
        DELETE FROM forward_rules WHERE id = ?
    `).bind(id).run();

    if (!result.success) {
        throw new Error('Failed to delete forward rule');
    }
}
