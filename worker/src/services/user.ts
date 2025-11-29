/**
 * 用户服务（单管理员模式：只保留修改用户名和密码功能）
 */

import type { D1Database } from '@cloudflare/workers-types';

/**
 * 更新用户设置（只支持改名和改密码）
 */
export async function updateUserSettings(
    db: D1Database,
    userId: number,
    updates: {
        username?: string;
        password?: string;
    }
): Promise<void> {
    const setParts: string[] = [];
    const values: any[] = [];

    if (updates.username !== undefined) {
        // 验证用户名格式
        if (updates.username.length < 3 || updates.username.length > 50) {
            throw new Error('用户名长度必须在3-50个字符之间');
        }
        // 检查用户名是否已被其他用户使用
        const existingUser = await db.prepare(`
            SELECT id FROM users WHERE username = ? AND id != ?
        `).bind(updates.username, userId).first();
        if (existingUser) {
            throw new Error('用户名已被使用');
        }
        setParts.push('username = ?');
        values.push(updates.username);
    }

    if (updates.password !== undefined) {
        // 密码应该已经是哈希后的值
        setParts.push('password = ?');
        values.push(updates.password);
    }

    if (setParts.length === 0) {
        return; // 没有需要更新的字段
    }

    setParts.push('updated_at = CURRENT_TIMESTAMP');
    values.push(userId);

    const sql = `UPDATE users SET ${setParts.join(', ')} WHERE id = ?`;
    const result = await db.prepare(sql).bind(...values).run();

    if (!result.success) {
        throw new Error('Failed to update user settings');
    }
}
