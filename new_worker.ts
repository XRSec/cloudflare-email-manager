/**
 * 新的Cloudflare Workers代码
 * 实现临时邮箱系统的核心功能
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { jwt, verify } from 'hono/jwt';
import { HTTPException } from 'hono/http-exception';

// 环境变量类型定义
interface Env {
  DB: D1Database;
  R2: R2Bucket;
  JWT_SECRET: string;
  DOMAIN: string;
  
  // Webhook配置
  DINGTALK_SECRET?: string;
  FEISHU_SECRET?: string;
}

// 邮件接口定义
interface EmailMessage {
  from: string;
  to: string;
  subject?: string;
  content?: string;
  html?: string;
  attachments?: Array<{
    name: string;
    type: string;
    content: ArrayBuffer;
  }>;
}

// 用户信息接口
interface User {
  id: number;
  email_prefix: string;
  email_password: string;
  user_type: 'admin' | 'user';
  webhook_url?: string;
  webhook_secret?: string;
}

const app = new Hono<{ Bindings: Env }>();

// CORS配置
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

/**
 * 邮件处理器 - Cloudflare Email Routing的入口点
 */
export default {
  async email(message: any, env: Env, ctx: ExecutionContext): Promise<void> {
    try {
      await handleIncomingEmail(message, env);
    } catch (error) {
      console.error('邮件处理失败:', error);
    }
  },

  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return app.fetch(request, env, ctx);
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    await handleScheduledCleanup(env);
  }
};

/**
 * 处理接收到的邮件
 */
async function handleIncomingEmail(message: any, env: Env): Promise<void> {
  try {
    console.log('收到新邮件:', message.from, '到', message.to);
    
    // 解析收件人邮箱，提取用户前缀
    const recipientEmail = message.to;
    const emailPrefix = extractEmailPrefix(recipientEmail, env.DOMAIN);
    
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
    const emailData = await parseEmail(message);
    
    // 处理附件
    const attachments = await processAttachments(emailData.attachments, env.R2);
    
    // 存储邮件到数据库
    const emailId = await saveEmailToDatabase(env.DB, {
      userId: user.id,
      messageId: message.headers.get('Message-ID') || generateMessageId(),
      senderEmail: message.from,
      recipientEmail: recipientEmail,
      subject: emailData.subject || '',
      textContent: emailData.text || '',
      htmlContent: emailData.html || '',
      rawEmail: rawEmail,
      hasAttachments: attachments.length > 0,
      attachments: attachments
    });

    // 检查转发规则
    await checkAndExecuteForwardRules(env, emailId, emailData, user);
    
    // 发送用户个人webhook（如果配置了）
    if (user.webhook_url) {
      await sendWebhook(user.webhook_url, emailData, user.webhook_secret, 'custom');
    }

    console.log('邮件处理完成, ID:', emailId);
    
  } catch (error) {
    console.error('处理邮件时发生错误:', error);
    throw error;
  }
}

/**
 * 从邮件地址中提取用户前缀
 */
function extractEmailPrefix(email: string, domain: string): string | null {
  const domainPattern = `@${domain}`;
  if (!email.endsWith(domainPattern)) {
    return null;
  }
  return email.replace(domainPattern, '');
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
 * 解析邮件内容
 */
async function parseEmail(message: any): Promise<{
  subject?: string;
  text?: string;
  html?: string;
  attachments?: Array<any>;
}> {
  try {
    // 获取邮件头信息
    const subject = message.headers.get('Subject') || '';
    const contentType = message.headers.get('Content-Type') || '';
    
    // 读取原始邮件内容
    const rawEmail = await message.raw();
    
    // 解析 MIME 邮件
    const parsedEmail = await parseMimeEmail(rawEmail);
    
    return {
      subject: subject,
      text: parsedEmail.text || '',
      html: parsedEmail.html || '',
      attachments: parsedEmail.attachments || []
    };
  } catch (error) {
    console.error('邮件解析失败:', error);
    // 回退到简单解析
    return {
      subject: message.headers.get('Subject') || '',
      text: await message.text() || '',
      html: '',
      attachments: []
    };
  }
}

/**
 * 解析 MIME 邮件格式
 */
async function parseMimeEmail(rawEmail: ArrayBuffer): Promise<{
  text?: string;
  html?: string;
  attachments?: Array<any>;
}> {
  const decoder = new TextDecoder();
  const emailText = decoder.decode(rawEmail);
  
  // 简单的 MIME 解析
  const parts = emailText.split('\r\n\r\n');
  const headers = parts[0];
  const body = parts.slice(1).join('\r\n\r\n');
  
  // 解析 Content-Type 头
  const contentTypeMatch = headers.match(/Content-Type:\s*([^;\r\n]+)/i);
  const boundaryMatch = headers.match(/boundary="?([^"\r\n]+)"?/i);
  
  if (contentTypeMatch && contentTypeMatch[1].toLowerCase().includes('multipart')) {
    // 多部分邮件
    return await parseMultipartEmail(body, boundaryMatch?.[1] || '');
  } else {
    // 单部分邮件
    return await parseSinglePartEmail(body, headers);
  }
}

/**
 * 解析多部分邮件
 */
async function parseMultipartEmail(body: string, boundary: string): Promise<{
  text?: string;
  html?: string;
  attachments?: Array<any>;
}> {
  const parts = body.split(`--${boundary}`);
  const result: any = { attachments: [] };
  
  for (const part of parts) {
    if (part.trim() === '' || part.trim() === '--') continue;
    
    const partHeaders = part.split('\r\n\r\n')[0];
    const partBody = part.split('\r\n\r\n').slice(1).join('\r\n\r\n');
    
    const partContentType = partHeaders.match(/Content-Type:\s*([^;\r\n]+)/i)?.[1] || '';
    const partName = partHeaders.match(/name="?([^"\r\n]+)"?/i)?.[1] || '';
    const partFilename = partHeaders.match(/filename="?([^"\r\n]+)"?/i)?.[1] || '';
    
    if (partContentType.toLowerCase().includes('text/plain')) {
      result.text = partBody.trim();
    } else if (partContentType.toLowerCase().includes('text/html')) {
      result.html = partBody.trim();
    } else if (partFilename || partName) {
      // 附件
      const attachment = {
        name: partFilename || partName,
        type: partContentType,
        content: new TextEncoder().encode(partBody.trim())
      };
      result.attachments.push(attachment);
    }
  }
  
  return result;
}

/**
 * 解析单部分邮件
 */
async function parseSinglePartEmail(body: string, headers: string): Promise<{
  text?: string;
  html?: string;
  attachments?: Array<any>;
}> {
  const contentType = headers.match(/Content-Type:\s*([^;\r\n]+)/i)?.[1] || '';
  
  if (contentType.toLowerCase().includes('text/html')) {
    return { html: body.trim() };
  } else {
    return { text: body.trim() };
  }
}

/**
 * 处理邮件附件，上传到R2
 */
async function processAttachments(attachments: any[], r2: R2Bucket): Promise<Array<{
  filename: string;
  contentType: string;
  sizeBytes: number;
  r2Key: string;
}>> {
  const processedAttachments = [];
  
  for (const attachment of attachments || []) {
    try {
      // 检查文件大小限制（50MB）
      if (attachment.content.byteLength > 52428800) {
        console.warn('附件超过大小限制:', attachment.name);
        continue;
      }
      
      // 生成R2存储key
      const r2Key = `attachments/${Date.now()}-${attachment.name}`;
      
      // 上传到R2
      await r2.put(r2Key, attachment.content, {
        httpMetadata: {
          contentType: attachment.type
        }
      });
      
      processedAttachments.push({
        filename: attachment.name,
        contentType: attachment.type,
        sizeBytes: attachment.content.byteLength,
        r2Key: r2Key
      });
      
    } catch (error) {
      console.error('处理附件失败:', attachment.name, error);
    }
  }
  
  return processedAttachments;
}

/**
 * 保存邮件到数据库
 */
async function saveEmailToDatabase(db: D1Database, emailData: {
  userId: number;
  messageId: string;
  senderEmail: string;
  recipientEmail: string;
  subject: string;
  textContent: string;
  htmlContent: string;
  rawEmail: string;
  hasAttachments: boolean;
  attachments: Array<any>;
}): Promise<number> {
  
  // 插入邮件记录
  const emailResult = await db.prepare(`
    INSERT INTO emails (
      message_id, user_id, sender_email, recipient_email, 
      subject, text_content, html_content, raw_email, has_attachments
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    emailData.messageId,
    emailData.userId,
    emailData.senderEmail,
    emailData.recipientEmail,
    emailData.subject,
    emailData.textContent,
    emailData.htmlContent,
    emailData.rawEmail,
    emailData.hasAttachments ? 1 : 0
  ).run();
  
  const emailId = emailResult.meta.last_row_id as number;
  
  // 插入附件记录
  for (const attachment of emailData.attachments) {
    await db.prepare(`
      INSERT INTO attachments (email_id, filename, content_type, size_bytes, r2_key)
      VALUES (?, ?, ?, ?, ?)
    `).bind(
      emailId,
      attachment.filename,
      attachment.contentType,
      attachment.sizeBytes,
      attachment.r2Key
    ).run();
  }
  
  return emailId;
}

/**
 * 检查并执行转发规则
 */
async function checkAndExecuteForwardRules(env: Env, emailId: number, emailData: any, user: User): Promise<void> {
  // 查询启用的转发规则
  const rules = await env.DB.prepare(`
    SELECT * FROM forward_rules WHERE enabled = 1
  `).all();
  
  for (const rule of rules.results) {
    let shouldForward = true;
    
    // 检查发件人过滤器
    if (rule.sender_filter && !emailData.from?.includes(rule.sender_filter)) {
      shouldForward = false;
    }
    
    // 检查关键字过滤器
    if (rule.keyword_filter && !emailData.subject?.includes(rule.keyword_filter) && !emailData.text?.includes(rule.keyword_filter)) {
      shouldForward = false;
    }
    
    // 检查收件人过滤器
    if (rule.recipient_filter && !user.email_prefix.includes(rule.recipient_filter)) {
      shouldForward = false;
    }
    
    if (shouldForward) {
      await sendWebhook(rule.webhook_url, emailData, rule.webhook_secret, rule.webhook_type);
      
      // 记录转发日志
      await env.DB.prepare(`
        INSERT INTO forward_logs (email_id, rule_id, webhook_url, status, sent_at)
        VALUES (?, ?, ?, 'success', datetime('now'))
      `).bind(emailId, rule.id, rule.webhook_url).run();
    }
  }
}

/**
 * 发送Webhook通知
 */
async function sendWebhook(url: string, emailData: any, secret?: string, type: string = 'custom'): Promise<void> {
  try {
    let payload: any = {
      subject: emailData.subject,
      from: emailData.from,
      content: emailData.text,
      timestamp: new Date().toISOString()
    };
    
    // 根据不同类型格式化payload
    if (type === 'dingtalk') {
      payload = formatDingTalkMessage(emailData);
    } else if (type === 'feishu') {
      payload = formatFeishuMessage(emailData);
    }
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    
    // 添加签名（如果有密钥）
    if (secret) {
      const signature = await generateWebhookSignature(payload, secret);
      headers['X-Signature'] = signature;
    }
    
    const response = await fetch(url, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
      throw new Error(`Webhook响应错误: ${response.status}`);
    }
    
    console.log('Webhook发送成功:', url);
    
  } catch (error) {
    console.error('Webhook发送失败:', url, error);
    throw error;
  }
}

/**
 * 格式化钉钉消息
 */
function formatDingTalkMessage(emailData: any): any {
  return {
    msgtype: 'markdown',
    markdown: {
      title: `新邮件: ${emailData.subject}`,
      text: `### 新邮件通知\n\n**发件人**: ${emailData.from}\n\n**主题**: ${emailData.subject}\n\n**内容**: ${emailData.text?.substring(0, 500)}...`
    }
  };
}

/**
 * 格式化飞书消息
 */
function formatFeishuMessage(emailData: any): any {
  return {
    msg_type: 'interactive',
    card: {
      header: {
        title: {
          tag: 'plain_text',
          content: `新邮件: ${emailData.subject}`
        }
      },
      elements: [
        {
          tag: 'div',
          fields: [
            {
              is_short: true,
              text: {
                tag: 'lark_md',
                content: `**发件人**\n${emailData.from}`
              }
            },
            {
              is_short: true,
              text: {
                tag: 'lark_md',
                content: `**时间**\n${new Date().toLocaleString()}`
              }
            }
          ]
        },
        {
          tag: 'div',
          text: {
            tag: 'lark_md',
            content: `**内容**\n${emailData.text?.substring(0, 500)}...`
          }
        }
      ]
    }
  };
}

/**
 * 生成Webhook签名
 */
async function generateWebhookSignature(payload: any, secret: string): Promise<string> {
  const message = JSON.stringify(payload);
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const key = encoder.encode(secret);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * 生成邮件ID
 */
function generateMessageId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * 定时清理任务
 */
async function handleScheduledCleanup(env: Env): Promise<void> {
  try {
    console.log('开始执行定时清理任务');
    
    // 获取清理配置
    const cleanupDays = await getSystemSetting(env.DB, 'cleanup_days', '7');
    const daysAgo = parseInt(cleanupDays);
    
    // 查找需要清理的邮件
    const oldEmails = await env.DB.prepare(`
      SELECT id FROM emails 
      WHERE created_at < datetime('now', '-${daysAgo} days')
    `).all();
    
    for (const email of oldEmails.results) {
      // 删除R2中的附件
      const attachments = await env.DB.prepare(`
        SELECT r2_key FROM attachments WHERE email_id = ?
      `).bind(email.id).all();
      
      for (const attachment of attachments.results) {
        try {
          await env.R2.delete(attachment.r2_key as string);
        } catch (error) {
          console.error('删除R2附件失败:', attachment.r2_key, error);
        }
      }
      
      // 删除数据库记录（附件会因为外键约束自动删除）
      await env.DB.prepare(`DELETE FROM emails WHERE id = ?`).bind(email.id).run();
    }
    
    console.log(`清理完成，删除了 ${oldEmails.results.length} 封邮件`);
    
  } catch (error) {
    console.error('定时清理任务失败:', error);
  }
}

/**
 * 获取系统设置
 */
async function getSystemSetting(db: D1Database, key: string, defaultValue: string): Promise<string> {
  const result = await db.prepare(`
    SELECT value FROM system_settings WHERE key = ?
  `).bind(key).first();
  
  return result?.value as string || defaultValue;
}

// ============= API路由定义 =============

/**
 * 用户注册
 */
app.post('/api/register', async (c) => {
  try {
    const { email_password } = await c.req.json();
    
    if (!email_password || email_password.length < 6) {
      throw new HTTPException(400, { message: '密码长度至少6位' });
    }
    
    // 检查是否允许注册
    const allowRegistration = await getSystemSetting(c.env.DB, 'allow_registration', 'true');
    if (allowRegistration !== 'true') {
      throw new HTTPException(403, { message: '当前不允许新用户注册' });
    }
    
    // 生成随机邮件前缀
    const emailPrefix = generateRandomPrefix();
    
    // 检查前缀是否已存在
    const existingUser = await findUserByPrefix(c.env.DB, emailPrefix);
    if (existingUser) {
      throw new HTTPException(409, { message: '前缀冲突，请重试' });
    }
    
    // 创建用户
    const hashedPassword = await hashPassword(email_password);
    const result = await c.env.DB.prepare(`
      INSERT INTO users (email_prefix, email_password, user_type)
      VALUES (?, ?, 'user')
    `).bind(emailPrefix, hashedPassword).run();
    
    const userId = result.meta.last_row_id as number;
    const domain = c.env.DOMAIN;
    
    return c.json({
      success: true,
      data: {
        user_id: userId,
        email_address: `${emailPrefix}@${domain}`,
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
 * 生成随机邮件前缀
 */
function generateRandomPrefix(): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 8; i++) {
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
  
  return await jwt.sign(jwtPayload, secret);
}

// ============= 更多 API 端点 =============

/**
 * 获取邮件列表
 */
app.get('/api/mails', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    const { limit = 20, offset = 0, sender, keyword, startDate, endDate } = c.req.query();
    
    let query = `
      SELECT e.*, u.email_prefix, 
             GROUP_CONCAT(a.filename) as attachment_names,
             GROUP_CONCAT(a.size_bytes) as attachment_sizes
      FROM emails e
      LEFT JOIN users u ON e.user_id = u.id
      LEFT JOIN attachments a ON e.id = a.email_id
    `;
    
    const conditions = [];
    const params = [];
    
    // 普通用户只能查看自己的邮件
    if (payload.user_type !== 'admin') {
      conditions.push('e.user_id = ?');
      params.push(payload.user_id);
    }
    
    // 发件人过滤
    if (sender) {
      conditions.push('e.sender_email LIKE ?');
      params.push(`%${sender}%`);
    }
    
    // 关键字过滤
    if (keyword) {
      conditions.push('(e.subject LIKE ? OR e.text_content LIKE ?)');
      params.push(`%${keyword}%`, `%${keyword}%`);
    }
    
    // 日期过滤
    if (startDate) {
      conditions.push('e.received_at >= ?');
      params.push(startDate);
    }
    if (endDate) {
      conditions.push('e.received_at <= ?');
      params.push(endDate);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' GROUP BY e.id ORDER BY e.received_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    const result = await c.env.DB.prepare(query).bind(...params).all();
    
    // 获取总数
    let countQuery = 'SELECT COUNT(DISTINCT e.id) as total FROM emails e';
    if (conditions.length > 0) {
      countQuery += ' WHERE ' + conditions.join(' AND ');
    }
    const countResult = await c.env.DB.prepare(countQuery).bind(...params.slice(0, -2)).first();
    
    return c.json({
      success: true,
      data: {
        mails: result.results,
        total: countResult.total,
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });
    
  } catch (error) {
    console.error('获取邮件列表失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '获取邮件列表失败' });
  }
});

/**
 * 获取单封邮件详情
 */
app.get('/api/mails/:id', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    const mailId = c.req.param('id');
    
    // 获取邮件信息
    const mail = await c.env.DB.prepare(`
      SELECT e.*, u.email_prefix
      FROM emails e
      LEFT JOIN users u ON e.user_id = u.id
      WHERE e.id = ?
    `).bind(mailId).first();
    
    if (!mail) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }
    
    // 检查权限
    if (payload.user_type !== 'admin' && mail.user_id !== payload.user_id) {
      throw new HTTPException(403, { message: '无权限访问此邮件' });
    }
    
    // 获取附件信息
    const attachments = await c.env.DB.prepare(`
      SELECT id, filename, content_type, size_bytes, r2_key
      FROM attachments
      WHERE email_id = ?
    `).bind(mailId).all();
    
    return c.json({
      success: true,
      data: {
        ...mail,
        attachments: attachments.results
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
app.delete('/api/mails/:id', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    const mailId = c.req.param('id');
    
    // 获取邮件信息
    const mail = await c.env.DB.prepare(`
      SELECT user_id FROM emails WHERE id = ?
    `).bind(mailId).first();
    
    if (!mail) {
      throw new HTTPException(404, { message: '邮件不存在' });
    }
    
    // 检查权限
    if (payload.user_type !== 'admin' && mail.user_id !== payload.user_id) {
      throw new HTTPException(403, { message: '无权限删除此邮件' });
    }
    
    // 删除附件（R2 中的文件）
    const attachments = await c.env.DB.prepare(`
      SELECT r2_key FROM attachments WHERE email_id = ?
    `).bind(mailId).all();
    
    for (const attachment of attachments.results) {
      try {
        await c.env.R2.delete(attachment.r2_key);
      } catch (error) {
        console.error('删除R2附件失败:', attachment.r2_key, error);
      }
    }
    
    // 删除邮件（附件会因为外键约束自动删除）
    await c.env.DB.prepare(`DELETE FROM emails WHERE id = ?`).bind(mailId).run();
    
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
 * 下载附件
 */
app.get('/api/attachments/:id/download', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    const attachmentId = c.req.param('id');
    
    // 获取附件信息
    const attachment = await c.env.DB.prepare(`
      SELECT a.*, e.user_id, u.email_prefix
      FROM attachments a
      JOIN emails e ON a.email_id = e.id
      JOIN users u ON e.user_id = u.id
      WHERE a.id = ?
    `).bind(attachmentId).first();
    
    if (!attachment) {
      throw new HTTPException(404, { message: '附件不存在' });
    }
    
    // 检查权限
    if (payload.user_type !== 'admin' && attachment.user_id !== payload.user_id) {
      throw new HTTPException(403, { message: '无权限访问此附件' });
    }
    
    // 从 R2 获取文件
    const file = await c.env.R2.get(attachment.r2_key);
    if (!file) {
      throw new HTTPException(404, { message: '文件不存在' });
    }
    
    return new Response(file.body, {
      headers: {
        'Content-Type': attachment.content_type || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${attachment.filename}"`,
        'Content-Length': attachment.size_bytes.toString()
      }
    });
    
  } catch (error) {
    console.error('下载附件失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '下载附件失败' });
  }
});

/**
 * 更新用户设置
 */
app.put('/api/user/settings', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    const { webhook_url, webhook_secret, email_password } = await c.req.json();
    
    const updates = [];
    const params = [];
    
    if (webhook_url !== undefined) {
      updates.push('webhook_url = ?');
      params.push(webhook_url);
    }
    
    if (webhook_secret !== undefined) {
      updates.push('webhook_secret = ?');
      params.push(webhook_secret);
    }
    
    if (email_password && email_password.length >= 6) {
      const hashedPassword = await hashPassword(email_password);
      updates.push('email_password = ?');
      params.push(hashedPassword);
    }
    
    if (updates.length === 0) {
      throw new HTTPException(400, { message: '没有需要更新的内容' });
    }
    
    params.push(payload.user_id);
    
    await c.env.DB.prepare(`
      UPDATE users SET ${updates.join(', ')}, updated_at = datetime('now')
      WHERE id = ?
    `).bind(...params).run();
    
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

/**
 * 获取用户设置
 */
app.get('/api/user/settings', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    
    const user = await c.env.DB.prepare(`
      SELECT id, email_prefix, user_type, webhook_url, created_at
      FROM users WHERE id = ?
    `).bind(payload.user_id).first();
    
    if (!user) {
      throw new HTTPException(404, { message: '用户不存在' });
    }
    
    return c.json({
      success: true,
      data: {
        ...user,
        email_address: `${user.email_prefix}@${c.env.DOMAIN}`
      }
    });
    
  } catch (error) {
    console.error('获取用户设置失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '获取设置失败' });
  }
});

/**
 * 管理员：获取所有用户列表
 */
app.get('/api/admin/users', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    if (payload.user_type !== 'admin') {
      throw new HTTPException(403, { message: '需要管理员权限' });
    }
    
    const { limit = 50, offset = 0 } = c.req.query();
    
    const users = await c.env.DB.prepare(`
      SELECT id, email_prefix, user_type, webhook_url, created_at, updated_at
      FROM users
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).bind(parseInt(limit), parseInt(offset)).all();
    
    const countResult = await c.env.DB.prepare(`
      SELECT COUNT(*) as total FROM users
    `).first();
    
    return c.json({
      success: true,
      data: {
        users: users.results,
        total: countResult.total,
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });
    
  } catch (error) {
    console.error('获取用户列表失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '获取用户列表失败' });
  }
});

/**
 * 管理员：创建用户
 */
app.post('/api/admin/users', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    if (payload.user_type !== 'admin') {
      throw new HTTPException(403, { message: '需要管理员权限' });
    }
    
    const { email_prefix, email_password, user_type = 'user' } = await c.req.json();
    
    if (!email_prefix || !email_password) {
      throw new HTTPException(400, { message: '邮件前缀和密码不能为空' });
    }
    
    if (email_password.length < 6) {
      throw new HTTPException(400, { message: '密码长度至少6位' });
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
    
    const userId = result.meta.last_row_id as number;
    
    return c.json({
      success: true,
      data: {
        user_id: userId,
        email_address: `${email_prefix}@${c.env.DOMAIN}`,
        email_prefix: email_prefix,
        user_type: user_type
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
 * 管理员：删除用户
 */
app.delete('/api/admin/users/:id', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    if (payload.user_type !== 'admin') {
      throw new HTTPException(403, { message: '需要管理员权限' });
    }
    
    const userId = c.req.param('id');
    
    // 检查是否为管理员自己
    if (parseInt(userId) === payload.user_id) {
      throw new HTTPException(400, { message: '不能删除自己的账户' });
    }
    
    // 删除用户的所有邮件和附件
    const emails = await c.env.DB.prepare(`
      SELECT id FROM emails WHERE user_id = ?
    `).bind(userId).all();
    
    for (const email of emails.results) {
      // 删除附件
      const attachments = await c.env.DB.prepare(`
        SELECT r2_key FROM attachments WHERE email_id = ?
      `).bind(email.id).all();
      
      for (const attachment of attachments.results) {
        try {
          await c.env.R2.delete(attachment.r2_key);
        } catch (error) {
          console.error('删除R2附件失败:', attachment.r2_key, error);
        }
      }
    }
    
    // 删除用户（邮件和附件会因为外键约束自动删除）
    await c.env.DB.prepare(`DELETE FROM users WHERE id = ?`).bind(userId).run();
    
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
 * 管理员：获取系统设置
 */
app.get('/api/admin/settings', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    if (payload.user_type !== 'admin') {
      throw new HTTPException(403, { message: '需要管理员权限' });
    }
    
    const settings = await c.env.DB.prepare(`
      SELECT * FROM system_settings
    `).all();
    
    return c.json({
      success: true,
      data: settings.results
    });
    
  } catch (error) {
    console.error('获取系统设置失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '获取系统设置失败' });
  }
});

/**
 * 管理员：更新系统设置
 */
app.put('/api/admin/settings', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    if (payload.user_type !== 'admin') {
      throw new HTTPException(403, { message: '需要管理员权限' });
    }
    
    const settings = await c.req.json();
    
    for (const [key, value] of Object.entries(settings)) {
      await c.env.DB.prepare(`
        INSERT OR REPLACE INTO system_settings (key, value, updated_at)
        VALUES (?, ?, datetime('now'))
      `).bind(key, value).run();
    }
    
    return c.json({
      success: true,
      message: '系统设置更新成功'
    });
    
  } catch (error) {
    console.error('更新系统设置失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '更新系统设置失败' });
  }
});

/**
 * 管理员：获取转发规则列表
 */
app.get('/api/admin/forward-rules', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    if (payload.user_type !== 'admin') {
      throw new HTTPException(403, { message: '需要管理员权限' });
    }
    
    const rules = await c.env.DB.prepare(`
      SELECT * FROM forward_rules ORDER BY created_at DESC
    `).all();
    
    return c.json({
      success: true,
      data: rules.results
    });
    
  } catch (error) {
    console.error('获取转发规则失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '获取转发规则失败' });
  }
});

/**
 * 管理员：创建转发规则
 */
app.post('/api/admin/forward-rules', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    if (payload.user_type !== 'admin') {
      throw new HTTPException(403, { message: '需要管理员权限' });
    }
    
    const { rule_name, sender_filter, keyword_filter, recipient_filter, webhook_url, webhook_secret, webhook_type = 'custom' } = await c.req.json();
    
    if (!rule_name || !webhook_url) {
      throw new HTTPException(400, { message: '规则名称和webhook地址不能为空' });
    }
    
    const result = await c.env.DB.prepare(`
      INSERT INTO forward_rules (rule_name, sender_filter, keyword_filter, recipient_filter, webhook_url, webhook_secret, webhook_type)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(rule_name, sender_filter, keyword_filter, recipient_filter, webhook_url, webhook_secret, webhook_type).run();
    
    const ruleId = result.meta.last_row_id as number;
    
    return c.json({
      success: true,
      data: {
        id: ruleId,
        rule_name,
        sender_filter,
        keyword_filter,
        recipient_filter,
        webhook_url,
        webhook_type
      }
    });
    
  } catch (error) {
    console.error('创建转发规则失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '创建转发规则失败' });
  }
});

/**
 * 管理员：更新转发规则
 */
app.put('/api/admin/forward-rules/:id', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    if (payload.user_type !== 'admin') {
      throw new HTTPException(403, { message: '需要管理员权限' });
    }
    
    const ruleId = c.req.param('id');
    const updates = await c.req.json();
    
    const updateFields = [];
    const params = [];
    
    for (const [key, value] of Object.entries(updates)) {
      if (key !== 'id' && key !== 'created_at') {
        updateFields.push(`${key} = ?`);
        params.push(value);
      }
    }
    
    if (updateFields.length === 0) {
      throw new HTTPException(400, { message: '没有需要更新的内容' });
    }
    
    updateFields.push('updated_at = datetime("now")');
    params.push(ruleId);
    
    await c.env.DB.prepare(`
      UPDATE forward_rules SET ${updateFields.join(', ')}
      WHERE id = ?
    `).bind(...params).run();
    
    return c.json({
      success: true,
      message: '转发规则更新成功'
    });
    
  } catch (error) {
    console.error('更新转发规则失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '更新转发规则失败' });
  }
});

/**
 * 管理员：删除转发规则
 */
app.delete('/api/admin/forward-rules/:id', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    if (payload.user_type !== 'admin') {
      throw new HTTPException(403, { message: '需要管理员权限' });
    }
    
    const ruleId = c.req.param('id');
    
    await c.env.DB.prepare(`DELETE FROM forward_rules WHERE id = ?`).bind(ruleId).run();
    
    return c.json({
      success: true,
      message: '转发规则删除成功'
    });
    
  } catch (error) {
    console.error('删除转发规则失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '删除转发规则失败' });
  }
});

/**
 * 管理员：获取转发日志
 */
app.get('/api/admin/forward-logs', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: '未授权访问' });
    }
    
    const payload = await jwt.verify(token, c.env.JWT_SECRET);
    if (payload.user_type !== 'admin') {
      throw new HTTPException(403, { message: '需要管理员权限' });
    }
    
    const { limit = 50, offset = 0, status } = c.req.query();
    
    let query = `
      SELECT fl.*, e.subject, e.sender_email, u.email_prefix, fr.rule_name
      FROM forward_logs fl
      JOIN emails e ON fl.email_id = e.id
      JOIN users u ON e.user_id = u.id
      LEFT JOIN forward_rules fr ON fl.rule_id = fr.id
    `;
    
    const params = [];
    
    if (status) {
      query += ' WHERE fl.status = ?';
      params.push(status);
    }
    
    query += ' ORDER BY fl.sent_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    const logs = await c.env.DB.prepare(query).bind(...params).all();
    
    const countQuery = status ? 
      'SELECT COUNT(*) as total FROM forward_logs WHERE status = ?' :
      'SELECT COUNT(*) as total FROM forward_logs';
    
    const countResult = await c.env.DB.prepare(countQuery).bind(status ? [status] : []).first();
    
    return c.json({
      success: true,
      data: {
        logs: logs.results,
        total: countResult.total,
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });
    
  } catch (error) {
    console.error('获取转发日志失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '获取转发日志失败' });
  }
});

/**
 * 健康检查端点
 */
app.get('/health', (c) => {
  return c.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

/**
 * 根路径 - 返回前端页面
 */
app.get('*', (c) => {
  // 这里应该返回前端页面，或者重定向到前端应用
  return c.redirect('/');
});