/**
 * 安全审计服务
 */

import { D1Database } from '@cloudflare/workers-types';
import { debugLog } from '../utils/debug';

// 安全审计记录接口
export interface SecurityAuditRecord {
  id: number;
  user_id: number;
  action_type: 1 | 2; // 1=权限拒绝, 2=可疑操作
  resource_type?: 'mailbox' | 'email' | 'user' | 'system';
  resource_id?: number;
  request_ip?: string;
  user_agent?: string;
  attack_type: 1 | 2 | 3; // 1=权限拒绝, 2=可疑活动, 3=频率限制
  description?: string;
  created_at: string;
}

/**
 * 记录安全审计事件
 */
export async function recordSecurityEvent(
  db: D1Database,
  params: {
    user_id: number;
    action_type: 1 | 2; // 1=权限拒绝, 2=可疑操作
    resource_type?: 'mailbox' | 'email' | 'user' | 'system';
    resource_id?: number;
    request_ip?: string;
    user_agent?: string;
    attack_type: 1 | 2 | 3; // 1=权限拒绝, 2=可疑活动, 3=频率限制
    description?: string;
  }
): Promise<void> {
  try {
    const result = await db.prepare(`
            INSERT INTO security_audit (
                user_id, action_type, resource_type, resource_id, 
                request_ip, user_agent, attack_type, description, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `).bind(
      params.user_id,
      params.action_type,
      params.resource_type || null,
      params.resource_id || null,
      params.request_ip || null,
      params.user_agent || null,
      params.attack_type,
      params.description || null
    ).run();

    if (!result.success) {
      debugLog('[安全审计] 记录失败:', params);
    } else {
      debugLog('[安全审计] 记录成功:', params);
    }
  } catch (error) {
    debugLog('[安全审计] 记录异常:', error, params);
  }
}

/**
 * 记录权限拒绝事件
 */
export async function recordPermissionDenied(
  db: D1Database,
  params: {
    user_id: number;
    resource_type?: 'mailbox' | 'email' | 'user' | 'system';
    resource_id?: number;
    request_ip?: string;
    user_agent?: string;
    description?: string;
  }
): Promise<void> {
  await recordSecurityEvent(db, {
    ...params,
    action_type: 1, // 权限拒绝
    attack_type: 1  // 权限拒绝
  });
}

/**
 * 记录可疑操作事件
 */
export async function recordSuspiciousOperation(
  db: D1Database,
  params: {
    user_id: number;
    resource_type?: 'mailbox' | 'email' | 'user' | 'system';
    resource_id?: number;
    request_ip?: string;
    user_agent?: string;
    description?: string;
  }
): Promise<void> {
  await recordSecurityEvent(db, {
    ...params,
    action_type: 2, // 可疑操作
    attack_type: 2  // 可疑活动
  });
}

/**
 * 获取安全审计记录
 */
export async function getSecurityAuditRecords(
  db: D1Database,
  params: {
    user_id?: number;
    action_type?: string;
    attack_type?: string;
    start_date?: string;
    end_date?: string;
    page?: number;
    limit?: number;
  } = {}
): Promise<{ records: SecurityAuditRecord[], total: number }> {
  const {
    user_id,
    action_type,
    attack_type,
    start_date,
    end_date,
    page = 1,
    limit = 20
  } = params;

  const offset = (page - 1) * limit;
  const conditions: string[] = [];
  const bindings: any[] = [];

  if (user_id !== undefined) {
    conditions.push('user_id = ?');
    bindings.push(user_id);
  }

  if (action_type) {
    conditions.push('action_type = ?');
    bindings.push(action_type);
  }

  if (attack_type) {
    conditions.push('attack_type = ?');
    bindings.push(attack_type);
  }

  if (start_date) {
    conditions.push('created_at >= ?');
    bindings.push(start_date);
  }

  if (end_date) {
    conditions.push('created_at <= ?');
    bindings.push(end_date);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  // 获取总数
  const countResult = await db.prepare(`
        SELECT COUNT(*) as total 
        FROM security_audit 
        ${whereClause}
    `).bind(...bindings).first();

  const total = (countResult as any)?.total || 0;

  // 获取记录
  const result = await db.prepare(`
        SELECT 
            id, user_id, action_type, resource_type, resource_id,
            request_ip, user_agent, attack_type, description, created_at
        FROM security_audit 
        ${whereClause}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    `).bind(...bindings, limit, offset).all();

  return {
    records: result.results as unknown as SecurityAuditRecord[],
    total
  };
}

/**
 * 获取攻击统计
 */
export async function getAttackStats(
  db: D1Database,
  days: number = 7
): Promise<{
  total_attacks: number;
  attacks_by_type: Record<string, number>;
  attacks_by_ip: Record<string, number>;
  recent_attacks: SecurityAuditRecord[];
}> {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  const startDateStr = startDate.toISOString();

  // 总攻击数
  const totalResult = await db.prepare(`
        SELECT COUNT(*) as total 
        FROM security_audit 
        WHERE created_at >= ?
    `).bind(startDateStr).first();

  // 按类型统计
  const typeResult = await db.prepare(`
        SELECT attack_type, COUNT(*) as count 
        FROM security_audit 
        WHERE created_at >= ? AND attack_type IS NOT NULL
        GROUP BY attack_type
    `).bind(startDateStr).all();

  // 按IP统计
  const ipResult = await db.prepare(`
        SELECT request_ip, COUNT(*) as count 
        FROM security_audit 
        WHERE created_at >= ? AND request_ip IS NOT NULL
        GROUP BY request_ip
        ORDER BY count DESC
        LIMIT 10
    `).bind(startDateStr).all();

  // 最近攻击
  const recentResult = await db.prepare(`
        SELECT 
            id, user_id, action_type, resource_type, resource_id,
            request_ip, user_agent, attack_type, description, created_at
        FROM security_audit 
        WHERE created_at >= ?
        ORDER BY created_at DESC
        LIMIT 20
    `).bind(startDateStr).all();

  const attacksByType: Record<string, number> = {};
  typeResult.results.forEach((row: any) => {
    attacksByType[row.attack_type] = row.count;
  });

  const attacksByIp: Record<string, number> = {};
  ipResult.results.forEach((row: any) => {
    attacksByIp[row.request_ip] = row.count;
  });

  return {
    total_attacks: (totalResult as any)?.total || 0,
    attacks_by_type: attacksByType,
    attacks_by_ip: attacksByIp,
    recent_attacks: recentResult.results as unknown as SecurityAuditRecord[]
  };
}
