/**
 * 邮箱管理服务
 */

import { debugLog, errorLog } from '../utils/debug';
import type { Mailbox, MailboxApplication, User } from '../types';

/**
 * 根据邮箱地址查找邮箱记录
 */
export async function findMailboxByEmail(db: D1Database, email: string): Promise<Mailbox | null> {
    const result = await db.prepare(`
        SELECT id, user_id, email_address, is_active, created_at, updated_at
        FROM mailboxes
        WHERE email_address = ? AND is_active = 1
    `).bind(email).first();

    return result as Mailbox | null;
}

/**
 * 根据用户ID查找所有邮箱
 */
export async function findMailboxesByUserId(db: D1Database, userId: number): Promise<Mailbox[]> {
    const result = await db.prepare(`
        SELECT id, user_id, email_address, is_active, created_at, updated_at
        FROM mailboxes
        WHERE user_id = ? AND is_active = 1
        ORDER BY created_at ASC
    `).bind(userId).all();

    return result.results as unknown as Mailbox[];
}

/**
 * 创建新邮箱
 */
export async function createMailbox(
    db: D1Database,
    userId: number,
    emailAddress: string
): Promise<Mailbox> {
    // 检查邮箱是否已存在
    const existing = await findMailboxByEmail(db, emailAddress);
    if (existing) {
        throw new Error('邮箱地址已存在');
    }

    const result = await db.prepare(`
        INSERT INTO mailboxes (user_id, email_address, is_default, is_active, created_at, updated_at)
        VALUES (?, ?, 0, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).bind(userId, emailAddress).run();

    if (!result.success) {
        throw new Error('创建邮箱失败');
    }

    const mailbox = await db.prepare(`
        SELECT id, user_id, email_address, is_default, is_active, created_at, updated_at
        FROM mailboxes
        WHERE id = ?
    `).bind(result.meta.last_row_id).first();

    if (!mailbox) {
        throw new Error('获取创建的邮箱失败');
    }

    debugLog('[邮箱服务] 邮箱创建成功:', emailAddress, '用户ID:', userId);
    return mailbox as unknown as Mailbox;
}

/**
 * 删除邮箱（软删除）
 */
export async function deleteMailbox(db: D1Database, mailboxId: number): Promise<void> {
    const result = await db.prepare(`
        UPDATE mailboxes 
        SET is_active = 0, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `).bind(mailboxId).run();

    if (!result.success) {
        throw new Error('删除邮箱失败');
    }

    debugLog('[邮箱服务] 邮箱已删除:', mailboxId);
}

/**
 * 获取所有邮箱（管理员用）
 */
export async function getAllMailboxes(
    db: D1Database, 
    page: number = 1, 
    pageSize: number = 20
): Promise<{ mailboxes: (Mailbox & { user_username: string; user_type: string })[], total: number }> {
    const offset = (page - 1) * pageSize;

    // 获取总数
    const countResult = await db.prepare(`
        SELECT COUNT(*) as total 
        FROM mailboxes m
        JOIN users u ON m.user_id = u.id
        WHERE m.is_active = 1
    `).first();

    const total = (countResult as any)?.total || 0;

    // 获取邮箱列表
    const result = await db.prepare(`
        SELECT 
            m.id,
            m.user_id,
            m.email_address,
            m.is_active,
            m.created_at,
            m.updated_at,
            u.username as user_username,
            u.user_type
        FROM mailboxes m
        JOIN users u ON m.user_id = u.id
        WHERE m.is_active = 1
        ORDER BY m.created_at DESC
        LIMIT ? OFFSET ?
    `).bind(pageSize, offset).all();

    return {
        mailboxes: result.results as unknown as (Mailbox & { user_username: string; user_type: string })[],
        total
    };
}

/**
 * 根据完整邮箱地址查找用户
 */
export async function findUserByEmail(db: D1Database, email: string): Promise<User | null> {
    const result = await db.prepare(`
        SELECT 
            u.id,
            u.username,
            u.password,
            u.user_type,
            u.webhook_url,
            u.webhook_secret,
            u.created_at,
            u.updated_at
        FROM users u
        JOIN mailboxes m ON u.id = m.user_id
        WHERE m.email_address = ? AND m.is_active = 1
    `).bind(email).first();

    return result as User | null;
}

/**
 * 创建邮箱申请
 */
export async function createMailboxApplication(
    db: D1Database,
    userId: number,
    emailAddress: string,
    reason?: string
): Promise<MailboxApplication> {
    // 检查邮箱是否已存在
    const existing = await findMailboxByEmail(db, emailAddress);
    if (existing) {
        throw new Error('邮箱地址已被使用');
    }

    // 检查是否已有待处理的申请
    const existingApp = await db.prepare(`
        SELECT id FROM mailbox_applications 
        WHERE user_id = ? AND email_address = ? AND status = 'pending'
    `).bind(userId, emailAddress).first();

    if (existingApp) {
        throw new Error('已有待处理的申请');
    }

    const result = await db.prepare(`
        INSERT INTO mailbox_applications (user_id, email_address, reason, applied_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    `).bind(userId, emailAddress, reason || '').run();

    if (!result.success) {
        throw new Error('创建申请失败');
    }

    const application = await db.prepare(`
        SELECT id, user_id, email_address, status, reason, admin_comment,
               applied_at, processed_at, processed_by, created_at, updated_at
        FROM mailbox_applications
        WHERE id = ?
    `).bind(result.meta.last_row_id).first();

    if (!application) {
        throw new Error('获取创建的申请失败');
    }

    debugLog('[邮箱服务] 邮箱申请创建成功:', emailAddress, '用户ID:', userId);
    return application as unknown as MailboxApplication;
}

/**
 * 获取用户的邮箱申请列表
 */
export async function getUserMailboxApplications(db: D1Database, userId: number): Promise<MailboxApplication[]> {
    const result = await db.prepare(`
        SELECT id, user_id, email_address, status, reason, admin_comment,
               applied_at, processed_at, processed_by, created_at, updated_at
        FROM mailbox_applications
        WHERE user_id = ?
        ORDER BY applied_at DESC
    `).bind(userId).all();

    return result.results as unknown as MailboxApplication[];
}

/**
 * 获取所有邮箱申请（管理员用）
 */
export async function getAllMailboxApplications(
    db: D1Database,
    page: number = 1,
    pageSize: number = 20
): Promise<{ applications: (MailboxApplication & { user_username: string })[], total: number }> {
    const offset = (page - 1) * pageSize;

    // 获取总数
    const countResult = await db.prepare(`
        SELECT COUNT(*) as total 
        FROM mailbox_applications ma
        JOIN users u ON ma.user_id = u.id
    `).first();

    const total = (countResult as any)?.total || 0;

    // 获取申请列表
    const result = await db.prepare(`
        SELECT 
            ma.id,
            ma.user_id,
            ma.email_address,
            ma.status,
            ma.reason,
            ma.admin_comment,
            ma.applied_at,
            ma.processed_at,
            ma.processed_by,
            ma.created_at,
            ma.updated_at,
            u.username as user_username
        FROM mailbox_applications ma
        JOIN users u ON ma.user_id = u.id
        ORDER BY ma.applied_at DESC
        LIMIT ? OFFSET ?
    `).bind(pageSize, offset).all();

    return {
        applications: result.results as unknown as (MailboxApplication & { user_username: string })[],
        total
    };
}

/**
 * 处理邮箱申请
 */
export async function processMailboxApplication(
    db: D1Database,
    applicationId: number,
    adminId: number,
    action: 'approve' | 'reject',
    adminComment?: string
): Promise<void> {
    // 获取申请信息
    const application = await db.prepare(`
        SELECT id, user_id, email_address, status
        FROM mailbox_applications
        WHERE id = ?
    `).bind(applicationId).first();

    if (!application) {
        throw new Error('申请不存在');
    }

    if ((application as any).status !== 'pending') {
        throw new Error('申请已被处理');
    }

    const newStatus = action === 'approve' ? 'approved' : 'rejected';

    // 更新申请状态
    const updateResult = await db.prepare(`
        UPDATE mailbox_applications 
        SET status = ?, processed_at = CURRENT_TIMESTAMP, processed_by = ?, admin_comment = ?
        WHERE id = ?
    `).bind(newStatus, adminId, adminComment || '', applicationId).run();

    if (!updateResult.success) {
        throw new Error('更新申请状态失败');
    }

    // 如果批准，创建邮箱
    if (action === 'approve') {
        await createMailbox(db, (application as any).user_id, (application as any).email_address);
    }

    debugLog('[邮箱服务] 申请已处理:', applicationId, '状态:', newStatus);
}

/**
 * 检查邮箱地址是否被保留
 */
export async function isReservedMailbox(db: D1Database, emailAddress: string): Promise<boolean> {
    const setting = await db.prepare(`
        SELECT value FROM system_settings WHERE key = 'reserved_mailboxes'
    `).first();

    if (!setting) {
        return false;
    }

    try {
        const reservedList = JSON.parse((setting as any).value);
        const localPart = emailAddress.split('@')[0].toLowerCase();
        return reservedList.includes(localPart);
    } catch (error) {
        errorLog('[邮箱服务] 解析保留邮箱列表失败:', error);
        return false;
    }
}

/**
 * 检查用户邮箱数量限制
 */
export async function checkUserMailboxLimit(db: D1Database, userId: number): Promise<boolean> {
    const setting = await db.prepare(`
        SELECT value FROM system_settings WHERE key = 'max_mailboxes_per_user'
    `).first();

    const maxMailboxes = setting ? parseInt((setting as any).value) : 5;

    const countResult = await db.prepare(`
        SELECT COUNT(*) as count FROM mailboxes WHERE user_id = ? AND is_active = 1
    `).bind(userId).first();

    const currentCount = (countResult as any)?.count || 0;
    return currentCount < maxMailboxes;
}
