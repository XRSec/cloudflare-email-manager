/**
 * 用户Webhook配置服务
 */

import type { D1Database } from '@cloudflare/workers-types';
import type { UserWebhook } from '../types';

/**
 * 获取用户的所有webhook配置
 */
export async function getUserWebhooks(
    db: D1Database,
    userId: number
): Promise<UserWebhook[]> {
    const result = await db.prepare(`
        SELECT id, user_id, webhook_name, webhook_url, webhook_secret, 
               webhook_type, enabled, created_at, updated_at
        FROM user_webhooks
        WHERE user_id = ?
        ORDER BY created_at DESC
    `).bind(userId).all();

    return result.results.map(row => ({
        id: row.id as number,
        user_id: row.user_id as number,
        webhook_name: row.webhook_name as string,
        webhook_url: row.webhook_url as string,
        webhook_secret: row.webhook_secret as string | undefined,
        webhook_type: row.webhook_type as 'dingtalk' | 'feishu' | 'custom',
        enabled: row.enabled as number,
        created_at: row.created_at as string | undefined,
        updated_at: row.updated_at as string | undefined,
    }));
}

/**
 * 创建用户webhook配置
 */
export async function createUserWebhook(
    db: D1Database,
    userId: number,
    webhookData: {
        webhook_name: string;
        webhook_url: string;
        webhook_secret?: string;
        webhook_type: 'dingtalk' | 'feishu' | 'custom';
    }
): Promise<UserWebhook> {
    const result = await db.prepare(`
        INSERT INTO user_webhooks (user_id, webhook_name, webhook_url, webhook_secret, webhook_type)
        VALUES (?, ?, ?, ?, ?)
    `).bind(
        userId,
        webhookData.webhook_name,
        webhookData.webhook_url,
        webhookData.webhook_secret || null,
        webhookData.webhook_type
    ).run();

    if (!result.success) {
        throw new Error('Failed to create user webhook');
    }

    const webhook = await db.prepare(`
        SELECT id, user_id, webhook_name, webhook_url, webhook_secret, 
               webhook_type, enabled, created_at, updated_at
        FROM user_webhooks
        WHERE id = ?
    `).bind(result.meta.last_row_id).first();

    return {
        id: webhook.id as number,
        user_id: webhook.user_id as number,
        webhook_name: webhook.webhook_name as string,
        webhook_url: webhook.webhook_url as string,
        webhook_secret: webhook.webhook_secret as string | undefined,
        webhook_type: webhook.webhook_type as 'dingtalk' | 'feishu' | 'custom',
        enabled: webhook.enabled as number,
        created_at: webhook.created_at as string | undefined,
        updated_at: webhook.updated_at as string | undefined,
    };
}

/**
 * 更新用户webhook配置
 */
export async function updateUserWebhook(
    db: D1Database,
    webhookId: number,
    userId: number,
    updates: {
        webhook_name?: string;
        webhook_url?: string;
        webhook_secret?: string;
        webhook_type?: 'dingtalk' | 'feishu' | 'custom';
        enabled?: boolean;
    }
): Promise<void> {
    const setParts: string[] = [];
    const values: any[] = [];

    if (updates.webhook_name !== undefined) {
        setParts.push('webhook_name = ?');
        values.push(updates.webhook_name);
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
        values.push(updates.enabled ? 1 : 0);
    }

    if (setParts.length === 0) {
        return; // 没有需要更新的字段
    }

    setParts.push('updated_at = CURRENT_TIMESTAMP');
    values.push(webhookId, userId);

    const sql = `UPDATE user_webhooks SET ${setParts.join(', ')} WHERE id = ? AND user_id = ?`;
    const result = await db.prepare(sql).bind(...values).run();

    if (!result.success) {
        throw new Error('Failed to update user webhook');
    }
}

/**
 * 删除用户webhook配置
 */
export async function deleteUserWebhook(
    db: D1Database,
    webhookId: number,
    userId: number
): Promise<void> {
    const result = await db.prepare(`
        DELETE FROM user_webhooks
        WHERE id = ? AND user_id = ?
    `).bind(webhookId, userId).run();

    if (!result.success) {
        throw new Error('Failed to delete user webhook');
    }
}

/**
 * 获取用户webhook配置详情
 */
export async function getUserWebhookById(
    db: D1Database,
    webhookId: number,
    userId: number
): Promise<UserWebhook | null> {
    const result = await db.prepare(`
        SELECT id, user_id, webhook_name, webhook_url, webhook_secret, 
               webhook_type, enabled, created_at, updated_at
        FROM user_webhooks
        WHERE id = ? AND user_id = ?
    `).bind(webhookId, userId).first();

    if (!result) {
        return null;
    }

    return {
        id: result.id as number,
        user_id: result.user_id as number,
        webhook_name: result.webhook_name as string,
        webhook_url: result.webhook_url as string,
        webhook_secret: result.webhook_secret as string | undefined,
        webhook_type: result.webhook_type as 'dingtalk' | 'feishu' | 'custom',
        enabled: result.enabled as number,
        created_at: result.created_at as string | undefined,
        updated_at: result.updated_at as string | undefined,
    };
}
