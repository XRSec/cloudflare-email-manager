/**
 * 用户服务
 */

import type { D1Database } from '@cloudflare/workers-types';
import type { User } from '../types';

/**
 * 根据邮件前缀查找用户
 */
export async function findUserByPrefix(db: D1Database, prefix: string): Promise<User | null> {
    const result = await db.prepare(`
        SELECT id,
               email_prefix,
               email_password,
               user_type,
               webhook_url,
               webhook_secret,
               created_at,
               updated_at
        FROM users
        WHERE email_prefix = ?
    `).bind(prefix).first();

    if (!result) {
        return null;
    }

    // 安全地转换数据库结果为 User 类型
    return {
        id: result.id as number,
        email_prefix: result.email_prefix as string,
        email_password: result.email_password as string,
        user_type: result.user_type as 'admin' | 'user',
        webhook_url: result.webhook_url as string | undefined,
        webhook_secret: result.webhook_secret as string | undefined,
        created_at: result.created_at as string | undefined,
        updated_at: result.updated_at as string | undefined,
    };
}

/**
 * 根据用户ID查找用户
 */
export async function findUserById(db: D1Database, id: number): Promise<User | null> {
    const result = await db.prepare(`
        SELECT id,
               email_prefix,
               email_password,
               user_type,
               webhook_url,
               webhook_secret,
               created_at,
               updated_at
        FROM users
        WHERE id = ?
    `).bind(id).first();

    if (!result) {
        return null;
    }

    return {
        id: result.id as number,
        email_prefix: result.email_prefix as string,
        email_password: result.email_password as string,
        user_type: result.user_type as 'admin' | 'user',
        webhook_url: result.webhook_url as string | undefined,
        webhook_secret: result.webhook_secret as string | undefined,
        created_at: result.created_at as string | undefined,
        updated_at: result.updated_at as string | undefined,
    };
}

/**
 * 创建新用户
 */
export async function createUser(
    db: D1Database,
    emailPrefix: string,
    hashedPassword: string,
    userType: 'admin' | 'user' = 'user'
): Promise<User> {
    const result = await db.prepare(`
        INSERT INTO users (email_prefix, email_password, user_type, created_at, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).bind(emailPrefix, hashedPassword, userType).run();

    if (!result.success) {
        throw new Error('Failed to create user');
    }

    const user = await findUserById(db, result.meta.last_row_id as number);
    if (!user) {
        throw new Error('Failed to retrieve created user');
    }

    return user;
}

/**
 * 更新用户设置
 */
export async function updateUserSettings(
    db: D1Database,
    userId: number,
    updates: {
        email_password?: string;
        webhook_url?: string;
        webhook_secret?: string;
    }
): Promise<void> {
    const setParts: string[] = [];
    const values: any[] = [];

    if (updates.email_password !== undefined) {
        setParts.push('email_password = ?');
        values.push(updates.email_password);
    }

    if (updates.webhook_url !== undefined) {
        setParts.push('webhook_url = ?');
        values.push(updates.webhook_url || null);
    }

    if (updates.webhook_secret !== undefined) {
        setParts.push('webhook_secret = ?');
        values.push(updates.webhook_secret || null);
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

/**
 * 删除用户
 */
export async function deleteUser(db: D1Database, userId: number): Promise<void> {
    const result = await db.prepare(`
        DELETE FROM users WHERE id = ?
    `).bind(userId).run();

    if (!result.success) {
        throw new Error('Failed to delete user');
    }
}

/**
 * 获取所有用户（管理员功能）
 */
export async function getAllUsers(
    db: D1Database,
    page: number = 1,
    limit: number = 20
): Promise<{ users: Omit<User, 'email_password'>[]; total: number }> {
    const offset = (page - 1) * limit;

    // 获取用户列表（不包含密码）
    const usersResult = await db.prepare(`
        SELECT id,
               email_prefix,
               user_type,
               webhook_url,
               webhook_secret,
               created_at,
               updated_at
        FROM users
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    `).bind(limit, offset).all();

    // 获取总数
    const countResult = await db.prepare(`
        SELECT COUNT(*) as total FROM users
    `).first();

    const users = usersResult.results.map(result => ({
        id: result.id as number,
        email_prefix: result.email_prefix as string,
        user_type: result.user_type as 'admin' | 'user',
        webhook_url: result.webhook_url as string | undefined,
        webhook_secret: result.webhook_secret as string | undefined,
        created_at: result.created_at as string | undefined,
        updated_at: result.updated_at as string | undefined,
    }));

    return {
        users,
        total: countResult?.total as number || 0
    };
}
