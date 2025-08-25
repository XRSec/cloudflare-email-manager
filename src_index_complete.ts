/**
 * 完整的临时邮箱系统 - 单文件版本
 * 所有功能都整合在这个文件中，便于部署
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { HTTPException } from 'hono/http-exception';

// ============= 类型定义 =============

interface Env {
  DB: D1Database;
  R2: R2Bucket;
  KV: KVNamespace;
  DOMAIN: string;
  JWT_SECRET: string;
  ALLOW_REGISTRATION: string;
  CLEANUP_DAYS: string;
  MAX_ATTACHMENT_SIZE: string;
}

interface EmailData {
  id?: number;
  messageId: string;
  from: string;
  to: string;
  subject?: string;
  text?: string;
  html?: string;
  receivedAt: string;
  hasAttachments: boolean;
  attachmentCount?: number;
}

interface User {
  id: number;
  email_prefix: string;
  email_password: string;
  user_type: 'admin' | 'user';
  webhook_url?: string;
  webhook_secret?: string;
}

// ============= 工具函数 =============

/**
 * 生成随机字符串
 */
function generateRandomString(length: number = 8): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * 密码哈希
 */
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * 验证密码
 */
async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
  const hash = await hashPassword(password);
  return hash === hashedPassword;
}

/**
 * 生成JWT token
 */
async function generateJWT(payload: any, secret: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (24 * 60 * 60); // 24小时过期
  
  const jwtPayload = {
    ...payload,
    iat: now,
    exp: exp
  };
  
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadStr = btoa(JSON.stringify(jwtPayload));
  const signature = await signJWT(`${header}.${payloadStr}`, secret);
  return `${header}.${payloadStr}.${signature}`;
}

/**
 * JWT签名
 */
async function signJWT(data: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const dataToSign = encoder.encode(data);
  
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, dataToSign);
  return btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * 验证JWT token
 */
async function verifyJWT(token: string, secret: string): Promise<any> {
  try {
    const [header, payload, signature] = token.split('.');
    const expectedSignature = await signJWT(`${header}.${payload}`, secret);
    
    if (signature !== expectedSignature) {
      throw new Error('Invalid signature');
    }
    
    const decodedPayload = JSON.parse(atob(payload));
    
    if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired');
    }
    
    return decodedPayload;
  } catch (error) {
    throw new Error('Invalid token');
  }
}

/**
 * 根据邮件前缀查找用户
 */
async function findUserByPrefix(db: D1Database, prefix: string): Promise<User | null> {
  const result = await db.prepare(`
    SELECT id, email_prefix, email_password, user_type, webhook_url, webhook_secret 
    FROM users 
    WHERE email_prefix = ?
  `).bind(prefix).first();
  
  return result as User | null;
}

/**
 * 输入验证
 */
function validateInput(input: string, type: 'email_prefix' | 'password' | 'url'): { valid: boolean; message?: string } {
  if (!input || typeof input !== 'string') {
    return { valid: false, message: '输入不能为空' };
  }
  
  switch (type) {
    case 'email_prefix':
      if (input.length < 3 || input.length > 30) {
        return { valid: false, message: '邮箱前缀长度必须在3-30个字符之间' };
      }
      if (!/^[a-zA-Z0-9._-]+$/.test(input)) {
        return { valid: false, message: '邮箱前缀只能包含字母、数字、点号、下划线和连字符' };
      }
      break;
      
    case 'password':
      if (input.length < 6) {
        return { valid: false, message: '密码长度至少6位' };
      }
      if (input.length > 128) {
        return { valid: false, message: '密码长度不能超过128位' };
      }
      break;
      
    case 'url':
      try {
        new URL(input);
      } catch {
        return { valid: false, message: 'URL格式无效' };
      }
      break;
  }
  
  return { valid: true };
}

/**
 * 限流检查
 */
async function checkRateLimit(kv: KVNamespace, clientIP: string): Promise<boolean> {
  try {
    const key = `rate_limit:${clientIP}`;
    const record = await kv.get(key, 'json') as any;
    
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    if (!record || record.lastRequest < oneMinuteAgo) {
      await kv.put(key, JSON.stringify({
        requests: 1,
        lastRequest: now
      }), { expirationTtl: 3600 });
      return true;
    }
    
    if (record.requests >= 60) { // 每分钟最多60次请求
      return false;
    }
    
    record.requests++;
    record.lastRequest = now;
    await kv.put(key, JSON.stringify(record), { expirationTtl: 3600 });
    return true;
    
  } catch (error) {
    console.error('限流检查失败:', error);
    return true; // 检查失败时允许请求
  }
}

/**
 * 获取客户端IP
 */
function getClientIP(c: any): string {
  return c.req.header('CF-Connecting-IP') || 
         c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() || 
         'unknown';
}

// ============= Hono 应用初始化 =============

const app = new Hono<{ Bindings: Env }>();

// CORS配置
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

// 简单的限流中间件
app.use('/api/*', async (c, next) => {
  const clientIP = getClientIP(c);
  const isAllowed = await checkRateLimit(c.env.KV, clientIP);
  
  if (!isAllowed) {
    throw new HTTPException(429, { message: '请求过于频繁，请稍后再试' });
  }
  
  await next();
});

// JWT认证中间件
app.use('/api/protected/*', async (c, next) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new HTTPException(401, { message: '缺少认证令牌' });
  }
  
  const token = authHeader.substring(7);
  try {
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    c.set('jwtPayload', payload);
    await next();
  } catch (error) {
    throw new HTTPException(401, { message: '无效的认证令牌' });
  }
});

// 管理员权限中间件
app.use('/api/admin/*', async (c, next) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new HTTPException(401, { message: '缺少认证令牌' });
  }
  
  const token = authHeader.substring(7);
  try {
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    if (payload.user_type !== 'admin') {
      throw new HTTPException(403, { message: '需要管理员权限' });
    }
    c.set('jwtPayload', payload);
    await next();
  } catch (error) {
    throw new HTTPException(401, { message: '无效的认证令牌' });
  }
});

// ============= API 路由 =============

/**
 * 用户注册
 */
app.post('/api/register', async (c) => {
  try {
    const { email_password } = await c.req.json();
    
    const passwordValidation = validateInput(email_password, 'password');
    if (!passwordValidation.valid) {
      throw new HTTPException(400, { message: passwordValidation.message });
    }
    
    // 检查是否允许注册
    const allowRegistration = c.env.ALLOW_REGISTRATION !== 'false';
    if (!allowRegistration) {
      throw new HTTPException(403, { message: '当前不允许新用户注册' });
    }
    
    // 生成随机邮件前缀
    let emailPrefix: string;
    let attempts = 0;
    do {
      emailPrefix = generateRandomString(8);
      const existingUser = await findUserByPrefix(c.env.DB, emailPrefix);
      if (!existingUser) break;
      attempts++;
    } while (attempts < 10);
    
    if (attempts >= 10) {
      throw new HTTPException(500, { message: '生成邮箱前缀失败，请重试' });
    }
    
    // 创建用户
    const hashedPassword = await hashPassword(email_password);
    const result = await c.env.DB.prepare(`
      INSERT INTO users (email_prefix, email_password, user_type)
      VALUES (?, ?, 'user')
    `).bind(emailPrefix, hashedPassword).run();
    
    const userId = result.meta.last_row_id as number;
    
    return c.json({
      success: true,
      data: {
        user_id: userId,
        email_address: `${emailPrefix}@${c.env.DOMAIN}`,
        email_prefix: emailPrefix
      }
    });
    
  } catch (error) {
    console.error('用户注册失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '注册失败' });
  }
});

/**
 * 用户登录
 */
app.post('/api/login', async (c) => {
  try {
    const { email_prefix, email_password } = await c.req.json();
    
    if (!email_prefix || !email_password) {
      throw new HTTPException(400, { message: '邮件前缀和密码不能为空' });
    }
    
    // 查找用户
    const user = await findUserByPrefix(c.env.DB, email_prefix);
    if (!user) {
      throw new HTTPException(401, { message: '用户不存在' });
    }
    
    // 验证密码
    const isValidPassword = await verifyPassword(email_password, user.email_password);
    if (!isValidPassword) {
      throw new HTTPException(401, { message: '密码错误' });
    }
    
    // 生成JWT token
    const token = await generateJWT({
      user_id: user.id,
      email_prefix: user.email_prefix,
      user_type: user.user_type
    }, c.env.JWT_SECRET);
    
    return c.json({
      success: true,
      data: {
        token: token,
        user: {
          id: user.id,
          email_prefix: user.email_prefix,
          user_type: user.user_type,
          email_address: `${user.email_prefix}@${c.env.DOMAIN}`
        }
      }
    });
    
  } catch (error) {
    console.error('用户登录失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '登录失败' });
  }
});

/**
 * 获取用户信息
 */
app.get('/api/protected/user', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const userId = payload.user_id;
    
    const user = await c.env.DB.prepare(`
      SELECT id, email_prefix, user_type, webhook_url, created_at
      FROM users
      WHERE id = ?
    `).bind(userId).first();
    
    if (!user) {
      throw new HTTPException(404, { message: '用户不存在' });
    }
    
    return c.json({
      success: true,
      data: {
        user: {
          ...user,
          email_address: `${user.email_prefix}@${c.env.DOMAIN}`,
          webhook_secret: user.webhook_secret ? '******' : null
        }
      }
    });
    
  } catch (error) {
    console.error('获取用户信息失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '获取用户信息失败' });
  }
});

/**
 * 获取用户邮件列表
 */
app.get('/api/protected/emails', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const { page = 1, limit = 20, sender, keyword } = c.req.query();
    
    const userId = payload.user_id;
    const userType = payload.user_type;
    
    let whereClause = '';
    let bindings: any[] = [];
    
    // 普通用户只能查看自己的邮件，管理员可以查看所有邮件
    if (userType !== 'admin') {
      whereClause = 'WHERE e.user_id = ?';
      bindings.push(userId);
    } else {
      whereClause = 'WHERE 1=1';
    }
    
    // 添加过滤条件
    if (sender) {
      whereClause += ` AND e.sender_email LIKE ?`;
      bindings.push(`%${sender}%`);
    }
    
    if (keyword) {
      whereClause += ` AND (e.subject LIKE ? OR e.text_content LIKE ?)`;
      bindings.push(`%${keyword}%`, `%${keyword}%`);
    }
    
    const offset = (parseInt(page as string) - 1) * parseInt(limit as string);
    
    // 查询邮件列表
    const emails = await c.env.DB.prepare(`
      SELECT 
        e.id, e.message_id, e.sender_email, e.recipient_email,
        e.subject, e.text_content, e.has_attachments, e.received_at,
        u.email_prefix
      FROM emails e
      LEFT JOIN users u ON e.user_id = u.id
      ${whereClause}
      ORDER BY e.received_at DESC
      LIMIT ? OFFSET ?
    `).bind(...bindings, parseInt(limit as string), offset).all();
    
    // 查询总数
    const countQuery = `
      SELECT COUNT(*) as total
      FROM emails e
      LEFT JOIN users u ON e.user_id = u.id
      ${whereClause}
    `;
    
    const countResult = await c.env.DB.prepare(countQuery)
      .bind(...bindings.slice(0, -2))
      .first();
    
    return c.json({
      success: true,
      data: {
        emails: emails.results,
        total: countResult?.total || 0,
        page: parseInt(page as string),
        limit: parseInt(limit as string)
      }
    });
    
  } catch (error) {
    console.error('获取邮件列表失败:', error);
    throw new HTTPException(500, { message: '获取邮件列表失败' });
  }
});

/**
 * 获取邮件详情
 */
app.get('/api/protected/emails/:id', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const emailId = c.req.param('id');
    
    const userId = payload.user_id;
    const userType = payload.user_type;
    
    let whereClause = 'WHERE e.id = ?';
    let bindings = [emailId];
    
    // 普通用户只能查看自己的邮件
    if (userType !== 'admin') {
      whereClause += ' AND e.user_id = ?';
      bindings.push(userId);
    }
    
    // 查询邮件详情
    const email = await c.env.DB.prepare(`
      SELECT 
        e.*, u.email_prefix
      FROM emails e
      LEFT JOIN users u ON e.user_id = u.id
      ${whereClause}
    `).bind(...bindings).first();
    
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在或无权限访问' });
    }
    
    return c.json({
      success: true,
      data: {
        email: email,
        attachments: [] // 简化版本暂不处理附件
      }
    });
    
  } catch (error) {
    console.error('获取邮件详情失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '获取邮件详情失败' });
  }
});

/**
 * 删除邮件
 */
app.delete('/api/protected/emails/:id', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const emailId = c.req.param('id');
    
    const userId = payload.user_id;
    const userType = payload.user_type;
    
    let whereClause = 'WHERE id = ?';
    let bindings = [emailId];
    
    // 普通用户只能删除自己的邮件
    if (userType !== 'admin') {
      whereClause += ' AND user_id = ?';
      bindings.push(userId);
    }
    
    const result = await c.env.DB.prepare(`
      DELETE FROM emails ${whereClause}
    `).bind(...bindings).run();
    
    if (result.changes === 0) {
      throw new HTTPException(404, { message: '邮件不存在或无权限删除' });
    }
    
    return c.json({
      success: true,
      message: '邮件删除成功'
    });
    
  } catch (error) {
    console.error('删除邮件失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '删除邮件失败' });
  }
});

/**
 * 更新用户设置
 */
app.put('/api/protected/settings', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const { webhook_url, webhook_secret, email_password } = await c.req.json();
    
    const userId = payload.user_id;
    
    // 构建更新字段
    const updateFields: string[] = [];
    const bindings: any[] = [];
    
    if (webhook_url !== undefined) {
      if (webhook_url && !validateInput(webhook_url, 'url').valid) {
        throw new HTTPException(400, { message: 'Webhook URL格式无效' });
      }
      updateFields.push('webhook_url = ?');
      bindings.push(webhook_url || null);
    }
    
    if (webhook_secret !== undefined) {
      updateFields.push('webhook_secret = ?');
      bindings.push(webhook_secret || null);
    }
    
    if (email_password) {
      const passwordValidation = validateInput(email_password, 'password');
      if (!passwordValidation.valid) {
        throw new HTTPException(400, { message: passwordValidation.message });
      }
      const hashedPassword = await hashPassword(email_password);
      updateFields.push('email_password = ?');
      bindings.push(hashedPassword);
    }
    
    if (updateFields.length === 0) {
      throw new HTTPException(400, { message: '没有有效的更新字段' });
    }
    
    updateFields.push('updated_at = datetime(\'now\')');
    bindings.push(userId);
    
    await c.env.DB.prepare(`
      UPDATE users 
      SET ${updateFields.join(', ')}
      WHERE id = ?
    `).bind(...bindings).run();
    
    return c.json({
      success: true,
      message: '设置更新成功'
    });
    
  } catch (error) {
    console.error('更新用户设置失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '更新设置失败' });
  }
});

// ============= 管理员API =============

/**
 * 获取所有用户列表（管理员）
 */
app.get('/api/admin/users', async (c) => {
  try {
    const { page = 1, limit = 20, search } = c.req.query();
    
    let whereClause = 'WHERE 1=1';
    let bindings: any[] = [];
    
    if (search) {
      whereClause += ' AND email_prefix LIKE ?';
      bindings.push(`%${search}%`);
    }
    
    const offset = (parseInt(page as string) - 1) * parseInt(limit as string);
    
    const users = await c.env.DB.prepare(`
      SELECT 
        id, email_prefix, user_type, webhook_url, created_at,
        (SELECT COUNT(*) FROM emails WHERE user_id = users.id) as email_count
      FROM users
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).bind(...bindings, parseInt(limit as string), offset).all();
    
    const countResult = await c.env.DB.prepare(`
      SELECT COUNT(*) as total FROM users ${whereClause}
    `).bind(...bindings.slice(0, -2)).first();
    
    return c.json({
      success: true,
      data: {
        users: users.results.map((user: any) => ({
          ...user,
          email_address: `${user.email_prefix}@${c.env.DOMAIN}`,
          webhook_secret: user.webhook_secret ? '******' : null
        })),
        total: countResult?.total || 0,
        page: parseInt(page as string),
        limit: parseInt(limit as string)
      }
    });
    
  } catch (error) {
    console.error('获取用户列表失败:', error);
    throw new HTTPException(500, { message: '获取用户列表失败' });
  }
});

/**
 * 创建用户（管理员）
 */
app.post('/api/admin/users', async (c) => {
  try {
    const { email_prefix, email_password, user_type = 'user' } = await c.req.json();
    
    if (!email_prefix || !email_password) {
      throw new HTTPException(400, { message: '邮件前缀和密码不能为空' });
    }
    
    const prefixValidation = validateInput(email_prefix, 'email_prefix');
    if (!prefixValidation.valid) {
      throw new HTTPException(400, { message: prefixValidation.message });
    }
    
    const passwordValidation = validateInput(email_password, 'password');
    if (!passwordValidation.valid) {
      throw new HTTPException(400, { message: passwordValidation.message });
    }
    
    // 检查前缀是否已存在
    const existingUser = await findUserByPrefix(c.env.DB, email_prefix);
    if (existingUser) {
      throw new HTTPException(409, { message: '邮件前缀已存在' });
    }
    
    // 创建用户
    const hashedPassword = await hashPassword(email_password);
    const result = await c.env.DB.prepare(`
      INSERT INTO users (email_prefix, email_password, user_type)
      VALUES (?, ?, ?)
    `).bind(email_prefix, hashedPassword, user_type).run();
    
    return c.json({
      success: true,
      data: {
        user_id: result.meta.last_row_id,
        email_address: `${email_prefix}@${c.env.DOMAIN}`
      }
    });
    
  } catch (error) {
    console.error('创建用户失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '创建用户失败' });
  }
});

/**
 * 删除用户（管理员）
 */
app.delete('/api/admin/users/:id', async (c) => {
  try {
    const userId = c.req.param('id');
    
    const result = await c.env.DB.prepare(`
      DELETE FROM users WHERE id = ?
    `).bind(userId).run();
    
    if (result.changes === 0) {
      throw new HTTPException(404, { message: '用户不存在' });
    }
    
    return c.json({
      success: true,
      message: '用户删除成功'
    });
    
  } catch (error) {
    console.error('删除用户失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '删除用户失败' });
  }
});

/**
 * 获取统计信息（管理员）
 */
app.get('/api/admin/stats', async (c) => {
  try {
    // 用户统计
    const userStats = await c.env.DB.prepare(`
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN user_type = 'admin' THEN 1 END) as admin_users,
        COUNT(CASE WHEN user_type = 'user' THEN 1 END) as regular_users
      FROM users
    `).first();
    
    // 邮件统计
    const emailStats = await c.env.DB.prepare(`
      SELECT 
        COUNT(*) as total_emails,
        COUNT(CASE WHEN has_attachments = 1 THEN 1 END) as emails_with_attachments,
        COUNT(CASE WHEN received_at >= date('now', '-7 days') THEN 1 END) as emails_last_7_days
      FROM emails
    `).first();
    
    return c.json({
      success: true,
      data: {
        users: userStats,
        emails: emailStats,
        attachments: {
          total_attachments: 0,
          total_size_bytes: 0
        }
      }
    });
    
  } catch (error) {
    console.error('获取统计信息失败:', error);
    throw new HTTPException(500, { message: '获取统计信息失败' });
  }
});

// ============= 静态文件服务 =============

app.get('/', (c) => {
  return c.html(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>临时邮箱</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
               min-height: 100vh; color: #333; }
        .container { max-width: 900px; margin: 0 auto; padding: 20px; }
        .card { background: white; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); 
                padding: 30px; margin-bottom: 20px; }
        .header { text-align: center; color: white; margin-bottom: 40px; }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; font-weight: 300; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 500; }
        .form-control { width: 100%; padding: 12px; border: 2px solid #e9ecef; 
                        border-radius: 8px; font-size: 1rem; }
        .form-control:focus { outline: none; border-color: #667eea; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; 
               font-size: 1rem; cursor: pointer; font-weight: 500; }
        .btn-primary { background: #667eea; color: white; width: 100%; }
        .btn-primary:hover { background: #5a6fd8; }
        .btn-secondary { background: #6c757d; color: white; margin-left: 10px; }
        .btn-danger { background: #dc3545; color: white; margin-right: 10px; }
        .tabs { display: flex; margin-bottom: 20px; border-bottom: 2px solid #e9ecef; }
        .tab { padding: 12px 20px; background: none; border: none; 
               font-size: 1rem; cursor: pointer; color: #6c757d; 
               border-bottom: 2px solid transparent; }
        .tab.active { color: #667eea; border-bottom-color: #667eea; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .hidden { display: none !important; }
        .email-display { text-align: center; padding: 20px; 
                         background: #f8f9fa; border-radius: 8px; margin-bottom: 20px; }
        .email-address { font-size: 1.2rem; font-weight: 600; color: #667eea; margin-bottom: 10px; }
        .notification { position: fixed; top: 20px; right: 20px; 
                        padding: 15px 20px; border-radius: 8px; color: white; 
                        font-weight: 500; z-index: 1000; }
        .notification.success { background: #28a745; }
        .notification.error { background: #dc3545; }
        .email-item { border: 1px solid #dee2e6; border-radius: 8px; 
                      padding: 15px; margin-bottom: 10px; cursor: pointer; }
        .email-item:hover { background-color: #f8f9fa; }
        .email-sender { font-weight: 600; margin-bottom: 5px; }
        .email-subject { color: #667eea; margin-bottom: 5px; }
        .email-time { color: #6c757d; font-size: 0.9rem; }
        .filters { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .filter-input { flex: 1; min-width: 150px; }
        .admin-section { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                     gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2rem; font-weight: bold; color: #667eea; }
        .stat-label { color: #6c757d; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>临时邮箱</h1>
            <p>简洁高效的邮件服务</p>
        </div>

        <!-- 登录注册界面 -->
        <div id="loginSection" class="card">
            <div class="tabs">
                <button class="tab active" onclick="switchTab('login')">登录</button>
                <button class="tab" onclick="switchTab('register')">注册</button>
            </div>

            <div id="loginForm" class="tab-content active">
                <div class="form-group">
                    <label for="loginPrefix">邮箱前缀</label>
                    <input type="text" id="loginPrefix" class="form-control" placeholder="请输入邮箱前缀">
                </div>
                <div class="form-group">
                    <label for="loginPassword">邮箱密码</label>
                    <input type="password" id="loginPassword" class="form-control" placeholder="请输入邮箱密码">
                </div>
                <button class="btn btn-primary" onclick="login()">登录</button>
            </div>

            <div id="registerForm" class="tab-content">
                <div class="form-group">
                    <label for="registerPassword">邮箱密码</label>
                    <input type="password" id="registerPassword" class="form-control" placeholder="设置邮箱密码（至少6位）">
                </div>
                <button class="btn btn-primary" onclick="register()">注册</button>
                <p style="margin-top: 15px; color: #6c757d; font-size: 0.9rem;">
                    注册成功后将为您分配一个随机邮箱前缀
                </p>
            </div>
        </div>

        <!-- 主界面 -->
        <div id="mainSection" class="hidden">
            <div class="card">
                <div class="email-display">
                    <div class="email-address" id="userEmail"></div>
                    <button class="btn btn-secondary" onclick="logout()">退出登录</button>
                </div>
            </div>

            <div class="card">
                <div class="tabs">
                    <button class="tab active" onclick="switchMainTab('emails')">邮件列表</button>
                    <button class="tab" onclick="switchMainTab('settings')">个人设置</button>
                    <button id="adminTab" class="tab hidden" onclick="switchMainTab('admin')">管理后台</button>
                </div>

                <!-- 邮件列表 -->
                <div id="emailsTab" class="tab-content active">
                    <div class="filters">
                        <input type="text" id="senderFilter" class="form-control filter-input" placeholder="发件人过滤">
                        <input type="text" id="keywordFilter" class="form-control filter-input" placeholder="关键字过滤">
                        <button class="btn btn-primary" onclick="loadEmails()">搜索</button>
                    </div>
                    <div id="emailList">
                        <div style="text-align: center; padding: 40px; color: #6c757d;">
                            加载中...
                        </div>
                    </div>
                </div>

                <!-- 个人设置 -->
                <div id="settingsTab" class="tab-content">
                    <div class="form-group">
                        <label for="webhookUrl">Webhook地址</label>
                        <input type="url" id="webhookUrl" class="form-control" placeholder="https://example.com/webhook">
                    </div>
                    <div class="form-group">
                        <label for="webhookSecret">Webhook签名密钥</label>
                        <input type="text" id="webhookSecret" class="form-control" placeholder="用于验证webhook请求的密钥">
                    </div>
                    <div class="form-group">
                        <label for="newPassword">修改密码</label>
                        <input type="password" id="newPassword" class="form-control" placeholder="新密码（留空则不修改）">
                    </div>
                    <button class="btn btn-primary" onclick="updateSettings()">保存设置</button>
                </div>

                <!-- 管理后台 -->
                <div id="adminTab" class="tab-content">
                    <div class="admin-section">
                        <h3>系统统计</h3>
                        <div id="statsGrid" class="stat-grid">
                            <div class="stat-card">
                                <div class="stat-number" id="totalUsers">-</div>
                                <div class="stat-label">总用户数</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number" id="totalEmails">-</div>
                                <div class="stat-label">总邮件数</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number" id="emailsToday">-</div>
                                <div class="stat-label">近7天邮件</div>
                            </div>
                        </div>
                        
                        <h3>用户管理</h3>
                        <div style="margin-bottom: 20px;">
                            <button class="btn btn-primary" onclick="showCreateUserForm()">创建用户</button>
                        </div>
                        <div id="usersList">
                            <div style="text-align: center; padding: 20px; color: #6c757d;">
                                加载中...
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentUser = null;
        let currentToken = null;
        let isAdmin = false;

        // 初始化
        document.addEventListener('DOMContentLoaded', () => {
            const token = localStorage.getItem('token');
            if (token) {
                currentToken = token;
                getUserInfo();
            }
        });

        function switchTab(tab) {
            document.querySelectorAll('#loginSection .tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('#loginSection .tab-content').forEach(c => c.classList.remove('active'));
            
            document.querySelector(\`#loginSection [onclick="switchTab('\${tab}')"]\`).classList.add('active');
            document.getElementById(tab + 'Form').classList.add('active');
        }

        function switchMainTab(tab) {
            document.querySelectorAll('#mainSection .tabs .tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('#mainSection .tab-content').forEach(c => c.classList.remove('active'));
            
            document.querySelector(\`#mainSection [onclick="switchMainTab('\${tab}')"]\`).classList.add('active');
            document.getElementById(tab + 'Tab').classList.add('active');

            if (tab === 'admin' && isAdmin) {
                loadAdminData();
            } else if (tab === 'settings') {
                loadUserSettings();
            } else if (tab === 'emails') {
                loadEmails();
            }
        }

        async function register() {
            const password = document.getElementById('registerPassword').value;
            
            if (!password || password.length < 6) {
                showNotification('密码长度至少6位', 'error');
                return;
            }

            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email_password: password })
                });

                const result = await response.json();
                
                if (result.success) {
                    showNotification('注册成功！', 'success');
                    document.getElementById('loginPrefix').value = result.data.email_prefix;
                    document.getElementById('loginPassword').value = password;
                    switchTab('login');
                } else {
                    showNotification(result.message || '注册失败', 'error');
                }
            } catch (error) {
                showNotification('注册失败: ' + error.message, 'error');
            }
        }

        async function login() {
            const prefix = document.getElementById('loginPrefix').value;
            const password = document.getElementById('loginPassword').value;
            
            if (!prefix || !password) {
                showNotification('请填写邮箱前缀和密码', 'error');
                return;
            }

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email_prefix: prefix, email_password: password })
                });

                const result = await response.json();
                
                if (result.success) {
                    currentToken = result.data.token;
                    currentUser = result.data.user;
                    isAdmin = currentUser.user_type === 'admin';
                    localStorage.setItem('token', currentToken);
                    
                    showNotification('登录成功！', 'success');
                    showMainSection();
                } else {
                    showNotification(result.message || '登录失败', 'error');
                }
            } catch (error) {
                showNotification('登录失败: ' + error.message, 'error');
            }
        }

        function logout() {
            currentToken = null;
            currentUser = null;
            isAdmin = false;
            localStorage.removeItem('token');
            showLoginSection();
            showNotification('已退出登录', 'success');
        }

        function showLoginSection() {
            document.getElementById('loginSection').classList.remove('hidden');
            document.getElementById('mainSection').classList.add('hidden');
        }

        function showMainSection() {
            document.getElementById('loginSection').classList.add('hidden');
            document.getElementById('mainSection').classList.remove('hidden');
            document.getElementById('userEmail').textContent = currentUser.email_address;
            
            if (isAdmin) {
                document.getElementById('adminTab').classList.remove('hidden');
            }
            
            loadEmails();
        }

        async function getUserInfo() {
            try {
                const response = await fetch('/api/protected/user', {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });

                if (response.ok) {
                    const result = await response.json();
                    if (result.success) {
                        currentUser = result.data.user;
                        isAdmin = currentUser.user_type === 'admin';
                        showMainSection();
                    } else {
                        logout();
                    }
                } else {
                    logout();
                }
            } catch (error) {
                logout();
            }
        }

        async function loadEmails() {
            try {
                const sender = document.getElementById('senderFilter').value;
                const keyword = document.getElementById('keywordFilter').value;
                
                const params = new URLSearchParams({ page: 1, limit: 20 });
                if (sender) params.append('sender', sender);
                if (keyword) params.append('keyword', keyword);

                const response = await fetch(\`/api/protected/emails?\${params}\`, {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });

                const result = await response.json();
                
                if (result.success) {
                    const emailsHtml = result.data.emails.map(email => \`
                        <div class="email-item" onclick="showEmailDetail(\${email.id})">
                            <div class="email-sender">\${email.sender_email}</div>
                            <div class="email-subject">\${email.subject || '(无主题)'}</div>
                            <div class="email-time">\${new Date(email.received_at).toLocaleString()}</div>
                        </div>
                    \`).join('');
                    
                    document.getElementById('emailList').innerHTML = emailsHtml || 
                        '<div style="text-align: center; padding: 40px; color: #6c757d;">暂无邮件</div>';
                } else {
                    document.getElementById('emailList').innerHTML = 
                        '<div style="text-align: center; padding: 40px; color: #dc3545;">加载失败</div>';
                }
            } catch (error) {
                console.error('加载邮件失败:', error);
                document.getElementById('emailList').innerHTML = 
                    '<div style="text-align: center; padding: 40px; color: #dc3545;">加载失败</div>';
            }
        }

        async function showEmailDetail(emailId) {
            try {
                const response = await fetch(\`/api/protected/emails/\${emailId}\`, {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });

                const result = await response.json();
                
                if (result.success) {
                    const email = result.data.email;
                    alert(\`邮件详情:\\n\\n发件人: \${email.sender_email}\\n主题: \${email.subject}\\n时间: \${new Date(email.received_at).toLocaleString()}\\n\\n内容: \${email.text_content || '(无内容)'}\`);
                }
            } catch (error) {
                showNotification('获取邮件详情失败', 'error');
            }
        }

        async function loadUserSettings() {
            if (!currentUser) return;
            
            document.getElementById('webhookUrl').value = currentUser.webhook_url || '';
            document.getElementById('webhookSecret').value = '';
            document.getElementById('newPassword').value = '';
        }

        async function updateSettings() {
            const webhookUrl = document.getElementById('webhookUrl').value;
            const webhookSecret = document.getElementById('webhookSecret').value;
            const newPassword = document.getElementById('newPassword').value;

            const updateData = {};
            
            if (webhookUrl !== undefined) updateData.webhook_url = webhookUrl;
            if (webhookSecret) updateData.webhook_secret = webhookSecret;
            if (newPassword && newPassword.length >= 6) updateData.email_password = newPassword;

            try {
                const response = await fetch('/api/protected/settings', {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${currentToken}\`
                    },
                    body: JSON.stringify(updateData)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('设置更新成功', 'success');
                    document.getElementById('webhookSecret').value = '';
                    document.getElementById('newPassword').value = '';
                } else {
                    showNotification('更新失败: ' + result.message, 'error');
                }
            } catch (error) {
                showNotification('更新失败: ' + error.message, 'error');
            }
        }

        async function loadAdminData() {
            if (!isAdmin) return;
            
            try {
                // 加载统计信息
                const statsResponse = await fetch('/api/admin/stats', {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });
                
                if (statsResponse.ok) {
                    const statsResult = await statsResponse.json();
                    if (statsResult.success) {
                        const stats = statsResult.data;
                        document.getElementById('totalUsers').textContent = stats.users.total_users;
                        document.getElementById('totalEmails').textContent = stats.emails.total_emails;
                        document.getElementById('emailsToday').textContent = stats.emails.emails_last_7_days;
                    }
                }

                // 加载用户列表
                const usersResponse = await fetch('/api/admin/users', {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });
                
                if (usersResponse.ok) {
                    const usersResult = await usersResponse.json();
                    if (usersResult.success) {
                        const usersHtml = usersResult.data.users.map(user => \`
                            <div style="border: 1px solid #dee2e6; border-radius: 8px; padding: 15px; margin-bottom: 10px;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <div>
                                        <strong>\${user.email_address}</strong>
                                        <span style="background: \${user.user_type === 'admin' ? '#dc3545' : '#007bff'}; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; margin-left: 10px;">
                                            \${user.user_type === 'admin' ? '管理员' : '用户'}
                                        </span>
                                        <div style="color: #6c757d; font-size: 0.9rem; margin-top: 5px;">
                                            邮件数: \${user.email_count} | 注册时间: \${new Date(user.created_at).toLocaleDateString()}
                                        </div>
                                    </div>
                                    <div>
                                        <button class="btn btn-danger" onclick="deleteUser(\${user.id})" \${user.user_type === 'admin' ? 'disabled' : ''}>删除</button>
                                    </div>
                                </div>
                            </div>
                        \`).join('');
                        
                        document.getElementById('usersList').innerHTML = usersHtml || 
                            '<div style="text-align: center; padding: 20px; color: #6c757d;">暂无用户</div>';
                    }
                }
            } catch (error) {
                console.error('加载管理员数据失败:', error);
            }
        }

        function showCreateUserForm() {
            const prefix = prompt('请输入邮箱前缀:');
            const password = prompt('请输入密码:');
            const userType = confirm('是否创建管理员用户？') ? 'admin' : 'user';
            
            if (prefix && password) {
                createUser(prefix, password, userType);
            }
        }

        async function createUser(prefix, password, userType) {
            try {
                const response = await fetch('/api/admin/users', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${currentToken}\`
                    },
                    body: JSON.stringify({
                        email_prefix: prefix,
                        email_password: password,
                        user_type: userType
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('用户创建成功', 'success');
                    loadAdminData();
                } else {
                    showNotification('创建失败: ' + result.message, 'error');
                }
            } catch (error) {
                showNotification('创建失败: ' + error.message, 'error');
            }
        }

        async function deleteUser(userId) {
            if (!confirm('确定要删除这个用户吗？这将同时删除用户的所有邮件！')) {
                return;
            }
            
            try {
                const response = await fetch(\`/api/admin/users/\${userId}\`, {
                    method: 'DELETE',
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('用户删除成功', 'success');
                    loadAdminData();
                } else {
                    showNotification('删除失败: ' + result.message, 'error');
                }
            } catch (error) {
                showNotification('删除失败: ' + error.message, 'error');
            }
        }

        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = \`notification \${type}\`;
            notification.textContent = message;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }
    </script>
</body>
</html>
  `);
});

// ============= 邮件处理函数 =============

/**
 * 处理接收到的邮件
 */
async function handleIncomingEmail(message: any, env: Env): Promise<void> {
  try {
    console.log('收到新邮件:', message.from, '到', message.to);
    
    // 解析收件人邮箱，提取用户前缀
    const recipientEmail = message.to;
    const emailPrefix = recipientEmail.split('@')[0];
    
    if (!emailPrefix) {
      console.log('无效的邮箱地址:', recipientEmail);
      return;
    }

    // 查找用户
    const user = await findUserByPrefix(env.DB, emailPrefix);
    if (!user) {
      console.log('用户不存在:', emailPrefix);
      return;
    }

    // 读取邮件内容
    const rawEmail = await message.raw();
    const subject = message.headers.get('Subject') || '';
    const messageId = message.headers.get('Message-ID') || `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    // 简单的邮件内容提取
    let textContent = '';
    try {
      textContent = await message.text() || '';
    } catch (error) {
      console.warn('提取邮件文本内容失败:', error);
    }
    
    // 存储邮件到数据库
    await env.DB.prepare(`
      INSERT INTO emails (
        message_id, user_id, sender_email, recipient_email, 
        subject, text_content, raw_email, has_attachments
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `).bind(
      messageId,
      user.id,
      message.from,
      recipientEmail,
      subject,
      textContent,
      rawEmail
    ).run();

    console.log('邮件处理完成, ID:', messageId);
    
  } catch (error) {
    console.error('处理邮件时发生错误:', error);
  }
}

/**
 * 定时清理过期邮件
 */
async function handleScheduledCleanup(env: Env): Promise<void> {
  try {
    console.log('开始执行定时清理任务');
    
    const cleanupDays = parseInt(env.CLEANUP_DAYS || '7');
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - cleanupDays);
    
    // 删除过期邮件
    const result = await env.DB.prepare(`
      DELETE FROM emails WHERE received_at < ?
    `).bind(cutoffDate.toISOString()).run();
    
    console.log(`清理完成，删除了 ${result.changes} 封邮件`);
    
  } catch (error) {
    console.error('定时清理任务失败:', error);
  }
}

// ============= Worker 导出 =============

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return app.fetch(request, env, ctx);
  },

  async email(message: any, env: Env, ctx: ExecutionContext): Promise<void> {
    await handleIncomingEmail(message, env);
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    await handleScheduledCleanup(env);
  }
};