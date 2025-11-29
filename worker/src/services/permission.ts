/**
 * 权限验证服务
 */

import { debugLog, errorLog } from '../utils/debug';
import { recordPermissionDenied } from './security-audit';

/**
 * 验证用户是否存在
 */
export async function validateUserExists(
  db: D1Database,
  userId: number
): Promise<{ exists: boolean; user?: any }> {
  try {
    const result = await db.prepare(`
            SELECT id, username, user_type, created_at
            FROM users 
            WHERE id = ? AND status = 1
        `).bind(userId).first();

    if (result) {
      debugLog('[权限验证] 用户存在:', userId, '用户名:', (result as any).username);
      return { exists: true, user: result };
    } else {
      debugLog('[权限验证] 用户不存在:', userId);
      return { exists: false };
    }
  } catch (error) {
    errorLog('[权限验证] 验证用户存在失败:', error);
    return { exists: false };
  }
}

/**
 * 验证邮箱所有者权限
 */
export async function validateMailboxOwner(
  db: D1Database,
  mailboxId: number,
  userId: number
): Promise<{ isOwner: boolean; mailbox?: any }> {
  try {
    const result = await db.prepare(`
            SELECT id, owner_id, address, status
            FROM mailboxes 
            WHERE id = ? AND owner_id = ?
        `).bind(mailboxId, userId).first();

    if (result) {
      debugLog('[权限验证] 邮箱所有者验证通过:', mailboxId, '用户ID:', userId);
      return { isOwner: true, mailbox: result };
    } else {
      debugLog('[权限验证] 邮箱所有者验证失败:', mailboxId, '用户ID:', userId);
      return { isOwner: false };
    }
  } catch (error) {
    errorLog('[权限验证] 验证邮箱所有者失败:', error);
    return { isOwner: false };
  }
}

/**
 * 验证管理员权限
 */
export async function validateAdminPermission(
  db: D1Database,
  userId: number
): Promise<{ isAdmin: boolean; user?: any }> {
  try {
    const result = await db.prepare(`
            SELECT id, username, user_type
            FROM users 
            WHERE id = ? AND user_type = 1 AND status = 1
        `).bind(userId).first();

    if (result) {
      debugLog('[权限验证] 管理员权限验证通过:', userId);
      return { isAdmin: true, user: result };
    } else {
      debugLog('[权限验证] 管理员权限验证失败:', userId);
      return { isAdmin: false };
    }
  } catch (error) {
    errorLog('[权限验证] 验证管理员权限失败:', error);
    return { isAdmin: false };
  }
}

/**
 * 验证邮箱操作权限
 * 普通用户只能操作自己的邮箱，管理员可以操作所有邮箱
 */
export async function validateMailboxOperationPermission(
  db: D1Database,
  mailboxId: number,
  userId: number,
  userType: number,
  requestInfo?: { ip?: string; userAgent?: string }
): Promise<{ hasPermission: boolean; mailbox?: any; reason?: string }> {
  try {
    // 首先验证用户是否存在
    const userValidation = await validateUserExists(db, userId);
    if (!userValidation.exists) {
      return { hasPermission: false, reason: '用户不存在' };
    }

    // 获取邮箱信息
    const mailboxResult = await db.prepare(`
            SELECT id, owner_id, address, status
            FROM mailboxes 
            WHERE id = ?
        `).bind(mailboxId).first();

    if (!mailboxResult) {
      return { hasPermission: false, reason: '邮箱不存在' };
    }

    const mailbox = mailboxResult as any;

    // 管理员可以操作所有邮箱
    if (userType === 1) {
      debugLog('[权限验证] 管理员权限验证通过:', userId, '邮箱ID:', mailboxId);
      return { hasPermission: true, mailbox };
    }

    // 普通用户只能操作自己的邮箱
    if (mailbox.owner_id === userId) {
      debugLog('[权限验证] 邮箱所有者权限验证通过:', userId, '邮箱ID:', mailboxId);
      return { hasPermission: true, mailbox };
    }

    debugLog('[权限验证] 权限验证失败:', userId, '邮箱ID:', mailboxId, '邮箱所有者:', mailbox.owner_id);

    // 记录权限拒绝事件
    if (requestInfo) {
      await recordPermissionDenied(db, {
        user_id: userId,
        resource_type: 0, // mailbox
        resource_id: mailboxId,
        request_ip: requestInfo.ip,
        user_agent: requestInfo.userAgent,
        description: `用户 ${userId} 尝试操作不属于自己的邮箱 ${mailboxId}`
      });
    }

    return { hasPermission: false, reason: '无权操作此邮箱' };

  } catch (error) {
    errorLog('[权限验证] 验证邮箱操作权限失败:', error);
    return { hasPermission: false, reason: '权限验证失败' };
  }
}

/**
 * 验证邮箱申请操作权限
 * 普通用户只能操作自己的申请，管理员可以操作所有申请
 */
export async function validateMailboxApplicationPermission(
  db: D1Database,
  applicationId: number,
  userId: number,
  userType: string
): Promise<{ hasPermission: boolean; application?: any; reason?: string }> {
  try {
    // 首先验证用户是否存在
    const userValidation = await validateUserExists(db, userId);
    if (!userValidation.exists) {
      return { hasPermission: false, reason: '用户不存在' };
    }

    // 获取申请信息
    const applicationResult = await db.prepare(`
            SELECT id, user_id, requested_address, requested_address as email_address, status
            FROM mailbox_applications 
            WHERE id = ?
        `).bind(applicationId).first();

    if (!applicationResult) {
      return { hasPermission: false, reason: '申请不存在' };
    }

    const application = applicationResult as any;

    // 管理员可以操作所有申请
    if (userType === 'admin') {
      debugLog('[权限验证] 管理员申请权限验证通过:', userId, '申请ID:', applicationId);
      return { hasPermission: true, application };
    }

    // 普通用户只能操作自己的申请
    if (application.user_id === userId) {
      debugLog('[权限验证] 申请所有者权限验证通过:', userId, '申请ID:', applicationId);
      return { hasPermission: true, application };
    }

    debugLog('[权限验证] 申请权限验证失败:', userId, '申请ID:', applicationId, '申请者:', application.user_id);
    return { hasPermission: false, reason: '无权操作此申请' };

  } catch (error) {
    errorLog('[权限验证] 验证申请操作权限失败:', error);
    return { hasPermission: false, reason: '权限验证失败' };
  }
}
