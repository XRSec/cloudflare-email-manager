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
  // 这里需要实现邮件解析逻辑
  // 可以参考原项目的mail-parser-wasm或使用其他解析方法
  return {
    subject: message.headers.get('Subject') || '',
    text: await message.text() || '',
    html: '', // 需要解析HTML内容
    attachments: [] // 需要解析附件
  };
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