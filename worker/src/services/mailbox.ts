/**
 * 邮箱管理服务
 */

import { debugLog, errorLog } from '../utils/debug';
import type { Mailbox, MailboxApplication, User } from '../types';
import { recordMailboxAction } from './mailbox-history';
import { validateMailboxOperationPermission, validateUserExists } from './permission';

/**
 * 根据邮箱地址查找邮箱记录
 */
export async function findMailboxByEmail(db: D1Database, email: string): Promise<Mailbox | null> {
    const result = await db.prepare(`
        SELECT id, owner_id, address, status, created_at, updated_at
        FROM mailboxes
        WHERE address = ? AND status = 1
    `).bind(email).first();

    return result as Mailbox | null;
}

/**
 * 根据用户ID查找所有邮箱
 */
export async function findMailboxesByUserId(db: D1Database, userId: number): Promise<Mailbox[]> {
    const result = await db.prepare(`
        SELECT id, owner_id, address, status, created_at, updated_at
        FROM mailboxes
        WHERE owner_id = ? AND status = 1
        ORDER BY created_at ASC
    `).bind(userId).all();

    return result.results as unknown as Mailbox[];
}

/**
 * 根据ID获取邮箱
 */
export async function getMailboxById(db: D1Database, mailboxId: number): Promise<Mailbox | null> {
    const result = await db.prepare(`
        SELECT id, owner_id, address, status, created_at, updated_at
        FROM mailboxes
        WHERE id = ?
    `).bind(mailboxId).first();

    return result as Mailbox | null;
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
    const existing = await db.prepare(`
        SELECT id, status FROM mailboxes WHERE address = ?
    `).bind(emailAddress).first();

    if (existing) {
        const existingStatus = (existing as any).status;
        if (existingStatus === 1 || existingStatus === 2) {
            throw new Error('邮箱地址已被使用');
        } else if (existingStatus === 3) {
            // 如果邮箱被删除，重新激活
            const result = await db.prepare(`
                UPDATE mailboxes 
                SET owner_id = ?, status = 1, updated_at = CURRENT_TIMESTAMP
                WHERE address = ?
            `).bind(userId, emailAddress).run();

            if (!result.success) {
                throw new Error('重新激活邮箱失败');
            }

            const mailbox = await db.prepare(`
                SELECT id, owner_id, address, status, created_at, updated_at
                FROM mailboxes
                WHERE address = ?
            `).bind(emailAddress).first();

            debugLog('[邮箱服务] 邮箱重新激活成功:', emailAddress, '用户ID:', userId);

            // 记录重新分配历史
            await recordMailboxAction(
                db,
                (mailbox as any).id,
                userId,
                userId,
                'created'
            );

            return mailbox as unknown as Mailbox;
        } else {
            // 未知状态，抛出错误
            throw new Error('邮箱状态异常，无法处理');
        }
    } else {
        // 创建新邮箱
        const result = await db.prepare(`
            INSERT INTO mailboxes (owner_id, address, status, created_at, updated_at)
            VALUES (?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        `).bind(userId, emailAddress).run();

        if (!result.success) {
            throw new Error('创建邮箱失败');
        }

        const mailbox = await db.prepare(`
            SELECT id, owner_id, address, status, created_at, updated_at
            FROM mailboxes
            WHERE id = ?
        `).bind(result.meta.last_row_id).first();

        if (!mailbox) {
            throw new Error('获取创建的邮箱失败');
        }

        debugLog('[邮箱服务] 邮箱创建成功:', emailAddress, '用户ID:', userId);

        // 记录创建历史
        await recordMailboxAction(
            db,
            (mailbox as any).id,
            userId,
            userId,
            'created'
        );

        return mailbox as unknown as Mailbox;
    }
}

/**
 * 删除邮箱（软删除）
 */
export async function deleteMailbox(
    db: D1Database,
    mailboxId: number,
    userId: number,
    userType: number,
    requestInfo?: { ip?: string; userAgent?: string }
): Promise<void> {
    // 验证权限
    const permissionCheck = await validateMailboxOperationPermission(db, mailboxId, userId, userType, requestInfo);
    if (!permissionCheck.hasPermission) {
        throw new Error(permissionCheck.reason || '权限验证失败');
    }

    // 验证用户存在
    const userValidation = await validateUserExists(db, userId);
    if (!userValidation.exists) {
        throw new Error('用户不存在');
    }

    const result = await db.prepare(`
        UPDATE mailboxes 
        SET status = 3, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `).bind(mailboxId).run();

    if (!result.success) {
        throw new Error('删除邮箱失败');
    }

    debugLog('[邮箱服务] 邮箱已删除:', mailboxId, '操作人:', userId);

    // 记录删除历史
    await recordMailboxAction(
        db,
        mailboxId,
        userId,
        permissionCheck.mailbox!.owner_id,
        'deleted'
    );
}

/**
 * 获取邮箱列表
 * @param db 数据库实例
 * @param page 页码
 * @param pageSize 每页数量
 * @param userId 用户ID，如果提供则只返回该用户的邮箱，否则返回所有邮箱
 */
export async function getAllMailboxes(
    db: D1Database,
    page: number = 1,
    pageSize: number = 20,
    userId?: number
): Promise<{ mailboxes: (Mailbox & { owner_username: string })[], total: number }> {
    const offset = (page - 1) * pageSize;

    // 构建查询条件 - 只显示 active 状态的邮箱 (status = 1)
    const whereClause = userId ? 'WHERE m.status = 1 AND m.owner_id = ?' : 'WHERE m.status = 1';
    const bindValues = userId ? [userId] : [];

    // 获取总数
    const countResult = await db.prepare(`
        SELECT COUNT(*) as total 
        FROM mailboxes m
        JOIN users u ON m.owner_id = u.id
        ${whereClause}
    `).bind(...bindValues).first();

    const total = (countResult as any)?.total || 0;

    // 获取邮箱列表
    const result = await db.prepare(`
        SELECT 
            m.id,
            m.owner_id,
            m.address,
            m.status,
            m.created_at,
            m.updated_at,
            u.username as owner_username,
            u.user_type as owner_usertype
        FROM mailboxes m
        JOIN users u ON m.owner_id = u.id
        ${whereClause}
        ORDER BY m.created_at DESC
        LIMIT ? OFFSET ?
    `).bind(...bindValues, pageSize, offset).all();

    return {
        mailboxes: result.results as unknown as (Mailbox & { owner_username: string; owner_usertype: number })[],
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
    // 检查邮箱是否已被使用（排除 deleted 状态）
    const existing = await db.prepare(`
        SELECT id FROM mailboxes 
        WHERE address = ? AND status IN (1, 2)
    `).bind(emailAddress).first();

    if (existing) {
        throw new Error('邮箱地址已被使用');
    }

    // 检查是否已有待处理的申请
    const existingApp = await db.prepare(`
        SELECT id FROM mailbox_applications 
        WHERE user_id = ? AND requested_address = ? AND status = 0
    `).bind(userId, emailAddress).first();

    if (existingApp) {
        throw new Error('已有待处理的申请');
    }

    const result = await db.prepare(`
        INSERT INTO mailbox_applications (user_id, requested_address, reason, applied_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    `).bind(userId, emailAddress, reason || '').run();

    if (!result.success) {
        throw new Error('创建申请失败');
    }

    const application = await db.prepare(`
        SELECT id, user_id, requested_address, requested_address as email_address, status, reason, admin_comment,
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
        SELECT id, user_id, requested_address, requested_address as email_address, status, reason, admin_comment,
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
            ma.requested_address,
            ma.requested_address as email_address,
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
    action: 1 | 2, // 1=批准, 2=拒绝
    adminComment?: string
): Promise<void> {
    // 获取申请信息
    const application = await db.prepare(`
        SELECT id, user_id, requested_address, requested_address as email_address, status
        FROM mailbox_applications
        WHERE id = ?
    `).bind(applicationId).first();

    if (!application) {
        throw new Error('申请不存在');
    }

    if ((application as any).status !== 0) {
        throw new Error('申请已被处理');
    }

    const newStatus = action; // action直接就是状态值

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
    if (action === 1) {
        await createMailbox(db, (application as any).user_id, (application as any).requested_address);
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
        SELECT COUNT(*) as count FROM mailboxes WHERE owner_id = ? AND status = 1
    `).bind(userId).first();

    const currentCount = (countResult as any)?.count || 0;
    return currentCount < maxMailboxes;
}

/**
 * 获取邮箱申请列表（支持用户过滤）
 */
export async function getMailboxApplications(
    db: D1Database,
    userId?: number,
    paginationParams: { page: number; limit: number } = { page: 1, limit: 20 }
): Promise<MailboxApplication[]> {
    const { page, limit } = paginationParams;
    const offset = (page - 1) * limit;

    let whereClause = '';
    let bindValues: any[] = [];

    if (userId !== undefined) {
        whereClause = 'WHERE user_id = ?';
        bindValues = [userId];
    }

    const result = await db.prepare(`
        SELECT id, user_id, requested_address, requested_address as email_address, status, reason, admin_comment,
               applied_at, processed_at, processed_by, created_at, updated_at
        FROM mailbox_applications
        ${whereClause}
        ORDER BY applied_at DESC
        LIMIT ? OFFSET ?
    `).bind(...bindValues, limit, offset).all();

    return result.results as unknown as MailboxApplication[];
}

/**
 * 根据邮箱地址获取用户ID
 */
export async function getUserIdByEmail(db: D1Database, email: string): Promise<number | null> {
    const result = await db.prepare(`
        SELECT u.id
        FROM users u
        JOIN mailboxes m ON u.id = m.owner_id
        WHERE m.address = ? AND m.status = 1
    `).bind(email).first();

    return (result as any)?.id || null;
}

/**
 * 根据邮箱地址获取邮箱ID和用户ID
 */
export async function getMailboxInfoByEmail(db: D1Database, email: string): Promise<{ mailboxId: number; userId: number } | null> {
    const result = await db.prepare(`
        SELECT m.id as mailbox_id, u.id as user_id
        FROM users u
        JOIN mailboxes m ON u.id = m.owner_id
        WHERE m.address = ? AND m.status = 1
    `).bind(email).first();

    if (!result) return null;

    return {
        mailboxId: (result as any).mailbox_id,
        userId: (result as any).user_id
    };
}

/**
 * 切换邮箱状态
 */
export async function toggleMailboxStatus(
    db: D1Database,
    mailboxId: number,
    status: 1 | 2,
    adminId: number
): Promise<void> {
    // 验证管理员权限
    const userValidation = await validateUserExists(db, adminId);
    if (!userValidation.exists) {
        throw new Error('用户不存在');
    }

    if (userValidation.user!.user_type !== 1) {
        throw new Error('需要管理员权限');
    }

    // 获取邮箱信息
    const mailbox = await db.prepare(`
        SELECT id, owner_id, address, status FROM mailboxes WHERE id = ?
    `).bind(mailboxId).first();

    if (!mailbox) {
        throw new Error('邮箱不存在');
    }

    const result = await db.prepare(`
        UPDATE mailboxes 
        SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `).bind(status, mailboxId).run();

    if (!result.success) {
        throw new Error('Failed to update mailbox status');
    }

    // 记录状态变更历史
    const actionType = status === 1 ? 'created' : 'disabled';

    await recordMailboxAction(
        db,
        mailboxId,
        adminId,
        (mailbox as any).owner_id,
        actionType
    );
}
