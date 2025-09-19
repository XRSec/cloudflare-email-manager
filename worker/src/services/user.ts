/**
 * 用户服务
 */

import type { D1Database } from '@cloudflare/workers-types';
import type { User } from '../types';

/**
 * 根据用户名查找用户
 */
export async function findUserByUsername(db: D1Database, username: string): Promise<User | null> {
    const result = await db.prepare(`
        SELECT id,
               username,
               password,
               user_type,
               status,
               webhook_url,
               webhook_secret,
               created_at,
               updated_at
        FROM users
        WHERE username = ?
    `).bind(username).first();

    if (!result) {
        return null;
    }

    // 安全地转换数据库结果为 User 类型
    return {
        id: result.id as number,
        username: result.username as string,
        password: result.password as string,
        user_type: result.user_type as 'admin' | 'user',
        status: result.status as 'active' | 'disabled',
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
               username,
               password,
               user_type,
               status,
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
        username: result.username as string,
        password: result.password as string,
        user_type: result.user_type as 'admin' | 'user',
        status: result.status as 'active' | 'disabled',
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
    username: string,
    hashedPassword: string,
    userType: 'admin' | 'user' = 'user'
): Promise<User> {
    const result = await db.prepare(`
        INSERT INTO users (username, password, user_type, status, created_at, updated_at)
        VALUES (?, ?, ?, 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).bind(username, hashedPassword, userType).run();

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
        password?: string;
        webhook_url?: string;
        webhook_secret?: string;
    }
): Promise<void> {
    const setParts: string[] = [];
    const values: any[] = [];

    if (updates.password !== undefined) {
        setParts.push('password = ?');
        values.push(updates.password);
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
    limit: number = 20,
    searchParams: {
        search?: string;
        user_type?: string;
        created_after?: string;
        created_before?: string;
    } = {}
): Promise<{ users: Omit<User, 'password'>[]; total: number }> {
    const offset = (page - 1) * limit;
    const { search, user_type, created_after, created_before } = searchParams;

    // 构建查询条件
    const whereConditions: string[] = [];
    const bindValues: any[] = [];

    if (search) {
        whereConditions.push('username LIKE ?');
        bindValues.push(`%${search}%`);
    }

    if (user_type) {
        whereConditions.push('user_type = ?');
        bindValues.push(user_type);
    }

    if (created_after) {
        whereConditions.push('created_at >= ?');
        bindValues.push(created_after);
    }

    if (created_before) {
        whereConditions.push('created_at <= ?');
        bindValues.push(created_before);
    }

    const whereClause = whereConditions.length > 0 ? 'WHERE ' + whereConditions.join(' AND ') : '';

    // 获取用户列表（不包含密码）
    const allBindValues = [...bindValues, limit, offset];
    const usersResult = await db.prepare(`
        SELECT id,
               username,
               user_type,
               status,
               webhook_url,
               webhook_secret,
               created_at,
               updated_at
        FROM users
        ${whereClause}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    `).bind(...allBindValues).all();

    // 获取总数
    const countResult = await db.prepare(`
        SELECT COUNT(*) as total FROM users
        ${whereClause}
    `).bind(...bindValues).first();

    const users = usersResult.results.map(result => ({
        id: result.id as number,
        username: result.username as string,
        user_type: result.user_type as 'admin' | 'user',
        status: result.status as number,
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

/**
 * 切换用户状态
 */
export async function toggleUserStatus(
    db: D1Database,
    userId: number,
    status: 'active' | 'disabled'
): Promise<void> {
    const result = await db.prepare(`
        UPDATE users 
        SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `).bind(status, userId).run();

    if (!result.success) {
        throw new Error('Failed to update user status');
    }
}
