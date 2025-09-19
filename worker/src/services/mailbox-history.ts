/**
 * 邮箱历史记录服务
 */

import { debugLog } from '../utils/debug';
import type { MailboxHistory } from '../types';

/**
 * 记录邮箱操作历史
 */
export async function recordMailboxAction(
  db: D1Database,
  mailboxId: number,
  userId: number,
  ownerId: number,
  actionType: 'created' | 'deleted' | 'disabled'
): Promise<void> {
  const result = await db.prepare(`
        INSERT INTO mailbox_history (
            mailbox_id, user_id, owner_id, action_type, created_at
        )
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).bind(
    mailboxId,
    userId,
    ownerId,
    actionType
  ).run();

  if (!result.success) {
    debugLog('[邮箱历史] 记录操作失败:', actionType, '邮箱ID:', mailboxId);
  } else {
    debugLog('[邮箱历史] 记录操作成功:', actionType, '邮箱ID:', mailboxId, '操作人:', userId, '所有者:', ownerId);
  }
}

/**
 * 获取邮箱历史记录
 */
export async function getMailboxHistory(
  db: D1Database,
  mailboxId: number,
  page: number = 1,
  limit: number = 20
): Promise<{ history: (MailboxHistory & { user_username: string; owner_username: string })[], total: number }> {
  const offset = (page - 1) * limit;

  // 获取总数
  const countResult = await db.prepare(`
        SELECT COUNT(*) as total 
        FROM mailbox_history mh
        JOIN users u ON mh.user_id = u.id
        WHERE mh.mailbox_id = ?
    `).bind(mailboxId).first();

  const total = (countResult as any)?.total || 0;

  // 获取历史记录
  const result = await db.prepare(`
        SELECT 
            mh.id,
            mh.mailbox_id,
            mh.user_id,
            mh.owner_id,
            mh.action_type,
            mh.created_at
        FROM mailbox_history mh
        WHERE mh.mailbox_id = ?
        ORDER BY mh.created_at DESC
        LIMIT ? OFFSET ?
    `).bind(mailboxId, limit, offset).all();

  const history = result.results as unknown as MailboxHistory[];

  // 获取所有涉及的用户ID并去重（优化内存使用）
  const userIds = new Set<number>();
  for (const record of history) {
    userIds.add(record.user_id);
    userIds.add(record.owner_id);
  }

  // 批量查询用户名（去重后查询，增加错误处理）
  const userMap = new Map<number, string>();
  if (userIds.size > 0) {
    try {
      const uniqueUserIds = Array.from(userIds);
      // 限制查询数量，避免SQL参数过多
      const maxUsers = 100;
      if (uniqueUserIds.length > maxUsers) {
        debugLog('[邮箱历史] 用户ID数量过多，截取前', maxUsers, '个');
        uniqueUserIds.splice(maxUsers);
      }

      const placeholders = uniqueUserIds.map(() => '?').join(',');
      const userResult = await db.prepare(`
                SELECT id, username
                FROM users 
                WHERE id IN (${placeholders})
            `).bind(...uniqueUserIds).all();

      userResult.results.forEach((user: any) => {
        userMap.set(user.id, user.username);
      });
    } catch (error) {
      debugLog('[邮箱历史] 批量查询用户名失败:', error);
      // 查询失败时，所有用户名都设为"未知用户"
    }
  }

  // 添加用户名到历史记录
  const historyWithUsernames = history.map(record => ({
    ...record,
    user_username: userMap.get(record.user_id) || '未知用户',
    owner_username: userMap.get(record.owner_id) || '未知用户'
  }));

  return {
    history: historyWithUsernames,
    total
  };
}

/**
 * 获取用户的所有邮箱历史记录
 */
export async function getUserMailboxHistory(
  db: D1Database,
  userId: number,
  page: number = 1,
  limit: number = 20
): Promise<{ history: (MailboxHistory & { mailbox_address: string; user_username: string; owner_username: string })[], total: number }> {
  const offset = (page - 1) * limit;

  // 获取总数
  const countResult = await db.prepare(`
        SELECT COUNT(*) as total 
        FROM mailbox_history mh
        JOIN users u ON mh.user_id = u.id
        JOIN mailboxes m ON mh.mailbox_id = m.id
        WHERE mh.user_id = ?
    `).bind(userId).first();

  const total = (countResult as any)?.total || 0;

  // 获取历史记录
  const result = await db.prepare(`
        SELECT 
            mh.id,
            mh.mailbox_id,
            mh.user_id,
            mh.owner_id,
            mh.action_type,
            mh.created_at,
            m.address as mailbox_address
        FROM mailbox_history mh
        JOIN mailboxes m ON mh.mailbox_id = m.id
        WHERE mh.user_id = ?
        ORDER BY mh.created_at DESC
        LIMIT ? OFFSET ?
    `).bind(userId, limit, offset).all();

  const history = result.results as unknown as (MailboxHistory & { mailbox_address: string })[];

  // 获取所有涉及的用户ID并去重（优化内存使用）
  const userIds = new Set<number>();
  for (const record of history) {
    userIds.add(record.user_id);
    userIds.add(record.owner_id);
  }

  // 批量查询用户名（去重后查询，增加错误处理）
  const userMap = new Map<number, string>();
  if (userIds.size > 0) {
    try {
      const uniqueUserIds = Array.from(userIds);
      // 限制查询数量，避免SQL参数过多
      const maxUsers = 100;
      if (uniqueUserIds.length > maxUsers) {
        debugLog('[邮箱历史] 用户ID数量过多，截取前', maxUsers, '个');
        uniqueUserIds.splice(maxUsers);
      }

      const placeholders = uniqueUserIds.map(() => '?').join(',');
      const userResult = await db.prepare(`
                SELECT id, username
                FROM users 
                WHERE id IN (${placeholders})
            `).bind(...uniqueUserIds).all();

      userResult.results.forEach((user: any) => {
        userMap.set(user.id, user.username);
      });
    } catch (error) {
      debugLog('[邮箱历史] 批量查询用户名失败:', error);
      // 查询失败时，所有用户名都设为"未知用户"
    }
  }

  // 添加用户名到历史记录
  const historyWithUsernames = history.map(record => ({
    ...record,
    user_username: userMap.get(record.user_id) || '未知用户',
    owner_username: userMap.get(record.owner_id) || '未知用户'
  }));

  return {
    history: historyWithUsernames,
    total
  };
}

/**
 * 获取所有邮箱历史记录（管理员用）
 */
export async function getAllMailboxHistory(
  db: D1Database,
  page: number = 1,
  limit: number = 20
): Promise<{ history: (MailboxHistory & { mailbox_address: string; user_username: string; owner_username: string })[], total: number }> {
  const offset = (page - 1) * limit;

  // 获取总数
  const countResult = await db.prepare(`
        SELECT COUNT(*) as total 
        FROM mailbox_history mh
        JOIN users u ON mh.user_id = u.id
        JOIN mailboxes m ON mh.mailbox_id = m.id
    `).first();

  const total = (countResult as any)?.total || 0;

  // 获取历史记录
  const result = await db.prepare(`
        SELECT 
            mh.id,
            mh.mailbox_id,
            mh.user_id,
            mh.owner_id,
            mh.action_type,
            mh.created_at,
            m.address as mailbox_address
        FROM mailbox_history mh
        JOIN mailboxes m ON mh.mailbox_id = m.id
        ORDER BY mh.created_at DESC
        LIMIT ? OFFSET ?
    `).bind(limit, offset).all();

  const history = result.results as unknown as (MailboxHistory & { mailbox_address: string })[];

  // 获取所有涉及的用户ID并去重（优化内存使用）
  const userIds = new Set<number>();
  for (const record of history) {
    userIds.add(record.user_id);
    userIds.add(record.owner_id);
  }

  // 批量查询用户名（去重后查询，增加错误处理）
  const userMap = new Map<number, string>();
  if (userIds.size > 0) {
    try {
      const uniqueUserIds = Array.from(userIds);
      // 限制查询数量，避免SQL参数过多
      const maxUsers = 100;
      if (uniqueUserIds.length > maxUsers) {
        debugLog('[邮箱历史] 用户ID数量过多，截取前', maxUsers, '个');
        uniqueUserIds.splice(maxUsers);
      }

      const placeholders = uniqueUserIds.map(() => '?').join(',');
      const userResult = await db.prepare(`
                SELECT id, username
                FROM users 
                WHERE id IN (${placeholders})
            `).bind(...uniqueUserIds).all();

      userResult.results.forEach((user: any) => {
        userMap.set(user.id, user.username);
      });
    } catch (error) {
      debugLog('[邮箱历史] 批量查询用户名失败:', error);
      // 查询失败时，所有用户名都设为"未知用户"
    }
  }

  // 添加用户名到历史记录
  const historyWithUsernames = history.map(record => ({
    ...record,
    user_username: userMap.get(record.user_id) || '未知用户',
    owner_username: userMap.get(record.owner_id) || '未知用户'
  }));

  return {
    history: historyWithUsernames,
    total
  };
}
