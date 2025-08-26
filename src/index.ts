/**
 * 完整的临时邮箱系统 - 单文件版本
 * 所有功能都整合在这个文件中，便于部署
 */

import {Hono} from 'hono';
import {cors} from 'hono/cors';
import {HTTPException} from 'hono/http-exception';

// Cloudflare Workers 类型导入
type ExecutionContext = import('@cloudflare/workers-types').ExecutionContext;
type ScheduledEvent = import('@cloudflare/workers-types').ScheduledEvent;
type D1Database = import('@cloudflare/workers-types').D1Database;
type R2Bucket = import('@cloudflare/workers-types').R2Bucket;
type KVNamespace = import('@cloudflare/workers-types').KVNamespace;

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

interface User {
    id: number;
    email_prefix: string;
    email_password: string;
    user_type: 'admin' | 'user';
    webhook_url?: string;
    webhook_secret?: string;
    created_at?: string;
    updated_at?: string;
}

interface Email {
    id: number;
    message_id: string;
    user_id: number;
    sender_email: string;
    recipient_email: string;
    subject?: string;
    text_content?: string;
    html_content?: string;
    raw_email?: string;
    has_attachments: number;
    received_at: string;
    created_at?: string;
    updated_at?: string;
}

interface Attachment {
    id: number;
    email_id: number;
    filename: string;
    content_type: string;
    size_bytes: number;
    r2_key: string;
    created_at?: string;
    updated_at?: string;
}

interface ForwardRule {
    id: number;
    rule_name: string;
    sender_filter?: string;
    keyword_filter?: string;
    recipient_filter?: string;
    webhook_url: string;
    webhook_secret?: string;
    webhook_type: 'dingtalk' | 'feishu' | 'custom';
    enabled: number;
    created_at?: string;
    updated_at?: string;
}

interface SystemSetting {
    key: string;
    value: string;
    description?: string;
    created_at?: string;
    updated_at?: string;
}

// ============= 工具函数 =============

function generateRandomString(length: number = 8): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

async function hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
    const hash = await hashPassword(password);
    return hash === hashedPassword;
}

async function generateJWT(payload: any, secret: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + (24 * 60 * 60);

    const jwtPayload = {...payload, iat: now, exp: exp};

    const header = btoa(JSON.stringify({alg: 'HS256', typ: 'JWT'}));
    const payloadStr = btoa(JSON.stringify(jwtPayload));
    const signature = await signJWT(`${header}.${payloadStr}`, secret);
    return `${header}.${payloadStr}.${signature}`;
}

async function signJWT(data: string, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const dataToSign = encoder.encode(data);

    const key = await crypto.subtle.importKey(
        'raw', keyData, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, dataToSign);
    const uint8Array = new Uint8Array(signature);
    return btoa(String.fromCharCode.apply(null, Array.from(uint8Array)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

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

async function findUserByPrefix(db: D1Database, prefix: string): Promise<User | null> {
    const result = await db.prepare(`
        SELECT id, email_prefix, email_password, user_type, webhook_url, webhook_secret, created_at, updated_at
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

// 系统设置相关函数
async function getSystemSetting(db: D1Database, key: string): Promise<string | null> {
    const result = await db.prepare(`
        SELECT value FROM system_settings WHERE key = ?
    `).bind(key).first();
    
    return result ? result.value as string : null;
}

async function setSystemSetting(db: D1Database, key: string, value: string): Promise<void> {
    await db.prepare(`
        INSERT OR REPLACE INTO system_settings (key, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    `).bind(key, value).run();
}

// Webhook相关函数
async function sendWebhook(url: string, data: any, secret?: string, type: string = 'custom'): Promise<boolean> {
    try {
        let payload: any;
        let headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'User-Agent': 'CloudflareTempEmail/1.0'
        };

        // 根据webhook类型构造不同的消息格式
        switch (type) {
            case 'dingtalk':
                payload = {
                    msgtype: 'text',
                    text: {
                        content: `新邮件通知\n发件人: ${data.sender_email}\n主题: ${data.subject || '(无主题)'}\n内容: ${data.text_content?.substring(0, 200) || '(无内容)'}...`
                    }
                };
                break;
            case 'feishu':
                payload = {
                    msg_type: 'text',
                    content: {
                        text: `新邮件通知\n发件人: ${data.sender_email}\n主题: ${data.subject || '(无主题)'}\n内容: ${data.text_content?.substring(0, 200) || '(无内容)'}...`
                    }
                };
                break;
            default:
                payload = data;
                break;
        }

        // 添加签名验证
        if (secret) {
            const timestamp = Math.floor(Date.now() / 1000).toString();
            const signString = timestamp + JSON.stringify(payload);
            const signature = await signJWT(signString, secret);
            headers['X-Timestamp'] = timestamp;
            headers['X-Signature'] = signature;
        }

        const response = await fetch(url, {
            method: 'POST',
            headers,
            body: JSON.stringify(payload)
        });

        return response.ok;
    } catch (error) {
        console.error('Webhook发送失败:', error);
        return false;
    }
}

// 邮件过滤函数
function matchForwardRule(email: Email, rule: ForwardRule): boolean {
    // 检查发件人过滤器
    if (rule.sender_filter) {
        const senderPattern = rule.sender_filter.toLowerCase();
        if (!email.sender_email.toLowerCase().includes(senderPattern)) {
            return false;
        }
    }

    // 检查收件人过滤器
    if (rule.recipient_filter) {
        const recipientPattern = rule.recipient_filter.toLowerCase();
        if (!email.recipient_email.toLowerCase().includes(recipientPattern)) {
            return false;
        }
    }

    // 检查关键字过滤器
    if (rule.keyword_filter) {
        const keyword = rule.keyword_filter.toLowerCase();
        const subject = (email.subject || '').toLowerCase();
        const content = (email.text_content || '').toLowerCase();
        if (!subject.includes(keyword) && !content.includes(keyword)) {
            return false;
        }
    }

    return true;
}

// MIME解析函数（改进版）
async function parseEmailAttachments(rawEmail: string, env: Env): Promise<Attachment[]> {
    const attachments: Attachment[] = [];
    
    try {
        // 简单的MIME解析实现
        // 在生产环境中，建议使用专门的MIME解析库
        
        // 查找boundary
        const boundaryMatch = rawEmail.match(/boundary="?([^"\s;]+)"?/i);
        if (!boundaryMatch) {
            return attachments;
        }
        
        const boundary = boundaryMatch[1];
        const parts = rawEmail.split(`--${boundary}`);
        
        for (const part of parts) {
            // 跳过非附件部分
            if (!part.includes('Content-Disposition: attachment') && 
                !part.includes('Content-Disposition: inline')) {
                continue;
            }
            
            // 提取文件名
            const filenameMatch = part.match(/filename[*]?="?([^";\r\n]+)"?/i);
            if (!filenameMatch) continue;
            
            const filename = filenameMatch[1];
            
            // 提取Content-Type
            const contentTypeMatch = part.match(/Content-Type:\s*([^;\r\n]+)/i);
            const contentType = contentTypeMatch ? contentTypeMatch[1].trim() : 'application/octet-stream';
            
            // 提取编码方式
            const encodingMatch = part.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i);
            const encoding = encodingMatch ? encodingMatch[1].trim().toLowerCase() : '';
            
            // 提取内容
            const contentStartIndex = part.indexOf('\r\n\r\n');
            if (contentStartIndex === -1) continue;
            
            let content = part.substring(contentStartIndex + 4);
            content = content.replace(/\r\n$/, ''); // 移除末尾换行
            
            // 解码内容
            let decodedContent: ArrayBuffer;
            try {
                if (encoding === 'base64') {
                    // Base64解码
                    const binaryString = atob(content.replace(/\s/g, ''));
                    const bytes = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    decodedContent = bytes.buffer;
                } else {
                    // 其他编码方式，暂时按原文处理
                    const encoder = new TextEncoder();
                    decodedContent = encoder.encode(content);
                }
            } catch (error) {
                console.warn('解码附件内容失败:', filename, error);
                continue;
            }
            
            // 检查文件大小
            const maxSize = parseInt(await getSystemSetting(env.DB, 'max_attachment_size') || env.MAX_ATTACHMENT_SIZE || '52428800');
            if (decodedContent.byteLength > maxSize) {
                console.warn(`附件过大，跳过: ${filename} (${decodedContent.byteLength} bytes)`);
                continue;
            }
            
            attachments.push({
                id: 0,
                email_id: 0,
                filename: filename,
                content_type: contentType,
                size_bytes: decodedContent.byteLength,
                r2_key: '' // 将在调用处设置
            });
        }
    } catch (error) {
        console.error('MIME解析失败:', error);
    }
    
    return attachments;
}

// ============= Hono 应用 =============

const app = new Hono();

app.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
}));

// JWT认证中间件
app.use('/api/protected/*', async (c, next) => {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new HTTPException(401, {message: '缺少认证令牌'});
    }

    const token = authHeader.substring(7);
    try {
        const payload = await verifyJWT(token, (c.env as unknown as Env).JWT_SECRET);
        (c as any).set('jwtPayload', payload);
        await next();
    } catch (error) {
        throw new HTTPException(401, {message: '无效的认证令牌'});
    }
});

// 管理员权限检查中间件
app.use('/api/admin/*', async (c, next) => {
    const payload = (c as any).get('jwtPayload');
    if (!payload || payload.user_type !== 'admin') {
        throw new HTTPException(403, {message: '需要管理员权限'});
    }
    await next();
});

// ============= API 路由 =============

app.post('/api/register', async (c) => {
    try {
        const {email_password} = await c.req.json();

        if (!email_password || email_password.length < 6) {
            throw new HTTPException(400, {message: '密码长度至少6位'});
        }

        const env = c.env as unknown as Env;
        
        // 从数据库系统设置读取注册开关
        const allowRegistrationSetting = await getSystemSetting(env.DB, 'allow_registration');
        const allowRegistration = allowRegistrationSetting !== 'false';
        
        if (!allowRegistration) {
            throw new HTTPException(403, {message: '当前不允许新用户注册'});
        }

        let emailPrefix: string;
        let attempts = 0;
        do {
            emailPrefix = generateRandomString(8);
            const existingUser = await findUserByPrefix(env.DB, emailPrefix);
            if (!existingUser) break;
            attempts++;
        } while (attempts < 10);

        if (attempts >= 10) {
            throw new HTTPException(500, {message: '生成邮箱前缀失败，请重试'});
        }

        const hashedPassword = await hashPassword(email_password);
        const result = await env.DB.prepare(`
            INSERT INTO users (email_prefix, email_password, user_type)
            VALUES (?, ?, 'user')
        `).bind(emailPrefix, hashedPassword).run();

        const userId = result.meta.last_row_id as number;

        return c.json({
            success: true,
            data: {
                user_id: userId,
                email_address: `${emailPrefix}@${env.DOMAIN}`,
                email_prefix: emailPrefix
            }
        });

    } catch (error) {
        console.error('用户注册失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '注册失败'});
    }
});

app.post('/api/login', async (c) => {
    try {
        const body = await c.req.json();
        const {email_prefix, email_password} = body;

        if (!email_prefix || !email_password) {
            console.warn('[Login] 缺少 email_prefix 或 email_password');
            throw new HTTPException(400, {message: '邮件前缀和密码不能为空'});
        }

        const env = c.env as unknown as Env;
        console.log('[Login] 从环境获取 DB 和 JWT_SECRET');

        const user = await findUserByPrefix(env.DB, email_prefix);
        if (!user) {
            console.warn(`[Login] 用户不存在: ${email_prefix}`);
            throw new HTTPException(401, {message: '用户不存在'});
        }
        console.log('[Login] 找到用户:', {id: user.id, email_prefix: user.email_prefix});

        const isValidPassword = await verifyPassword(email_password, user.email_password);
        console.log('[Login] 密码验证结果:', isValidPassword);
        if (!isValidPassword) {
            console.warn(`[Login] 密码错误: ${email_prefix}`);
            throw new HTTPException(401, {message: '密码错误'});
        }

        const token = await generateJWT(
            {
                user_id: user.id,
                email_prefix: user.email_prefix,
                user_type: user.user_type,
            },
            env.JWT_SECRET
        );
        console.log('[Login] JWT 生成成功');

        const responseData = {
            success: true,
            data: {
                token: token,
                user: {
                    id: user.id,
                    email_prefix: user.email_prefix,
                    user_type: user.user_type,
                    email_address: `${user.email_prefix}@${env.DOMAIN}`,
                },
            },
        };
        console.log('[Login] 返回响应数据:', responseData);

        return c.json(responseData);

    } catch (error) {
        console.error('[Login] 用户登录失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '登录失败'});
    }
});


app.get('/api/protected/emails', async (c) => {
    try {
        const payload = (c as any).get('jwtPayload');
        const {page = 1, limit = 20} = c.req.query();

        const userId = payload.user_id;
        const offset = (parseInt(page as string) - 1) * parseInt(limit as string);
        const env = c.env as unknown as Env;

        const emails = await env.DB.prepare(`
            SELECT e.id,
                   e.message_id,
                   e.sender_email,
                   e.recipient_email,
                   e.subject,
                   e.text_content,
                   e.has_attachments,
                   e.received_at
            FROM emails e
            WHERE e.user_id = ?
            ORDER BY e.received_at DESC LIMIT ?
            OFFSET ?
        `).bind(userId, parseInt(limit as string), offset).all();

        const countResult = await env.DB.prepare(`SELECT COUNT(*) as total
                                                  FROM emails
                                                  WHERE user_id = ?`).bind(userId).first();

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
        throw new HTTPException(500, {message: '获取邮件列表失败'});
    }
});

// ============= 用户设置API =============

// 获取用户设置
app.get('/api/protected/user/settings', async (c) => {
    try {
        const payload = (c as any).get('jwtPayload');
        const env = c.env as unknown as Env;

        const user = await findUserByPrefix(env.DB, payload.email_prefix);
        if (!user) {
            throw new HTTPException(404, {message: '用户不存在'});
        }

        return c.json({
            success: true,
            data: {
                email_prefix: user.email_prefix,
                email_address: `${user.email_prefix}@${env.DOMAIN}`,
                user_type: user.user_type,
                webhook_url: user.webhook_url || '',
                webhook_secret: user.webhook_secret ? '已设置' : '',
                created_at: user.created_at
            }
        });
    } catch (error) {
        console.error('获取用户设置失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '获取用户设置失败'});
    }
});

// 更新用户设置
app.put('/api/protected/user/settings', async (c) => {
    try {
        const payload = (c as any).get('jwtPayload');
        const env = c.env as unknown as Env;
        const {email_password, webhook_url, webhook_secret} = await c.req.json();

        const userId = payload.user_id;
        const updates: string[] = [];
        const values: any[] = [];

        // 检查是否需要更新密码
        if (email_password && email_password.trim() !== '') {
            if (email_password.length < 6) {
                throw new HTTPException(400, {message: '密码长度至少6位'});
            }
            const hashedPassword = await hashPassword(email_password);
            updates.push('email_password = ?');
            values.push(hashedPassword);
        }

        // 检查是否需要更新webhook URL
        if (webhook_url !== undefined) {
            updates.push('webhook_url = ?');
            values.push(webhook_url.trim() || null);
        }

        // 检查是否需要更新webhook secret
        if (webhook_secret !== undefined && webhook_secret.trim() !== '') {
            updates.push('webhook_secret = ?');
            values.push(webhook_secret.trim());
        }

        if (updates.length === 0) {
            throw new HTTPException(400, {message: '没有需要更新的内容'});
        }

        updates.push('updated_at = CURRENT_TIMESTAMP');
        values.push(userId);

        await env.DB.prepare(`
            UPDATE users 
            SET ${updates.join(', ')}
            WHERE id = ?
        `).bind(...values).run();

        return c.json({
            success: true,
            message: '设置更新成功'
        });

    } catch (error) {
        console.error('更新用户设置失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '更新用户设置失败'});
    }
});

// ============= 邮件管理API =============

// 获取邮件详情
app.get('/api/protected/emails/:id', async (c) => {
    try {
        const payload = (c as any).get('jwtPayload');
        const env = c.env as unknown as Env;
        const emailId = c.req.param('id');

        let whereClause = 'WHERE e.id = ?';
        let params = [emailId];

        // 非管理员只能查看自己的邮件
        if (payload.user_type !== 'admin') {
            whereClause += ' AND e.user_id = ?';
            params.push(payload.user_id);
        }

        const email = await env.DB.prepare(`
            SELECT e.*, u.email_prefix 
            FROM emails e
            JOIN users u ON e.user_id = u.id
            ${whereClause}
        `).bind(...params).first();

        if (!email) {
            throw new HTTPException(404, {message: '邮件不存在'});
        }

        // 获取附件信息
        const attachments = await env.DB.prepare(`
            SELECT id, filename, content_type, size_bytes, created_at
            FROM attachments
            WHERE email_id = ?
        `).bind(emailId).all();

        return c.json({
            success: true,
            data: {
                email,
                attachments: attachments.results
            }
        });

    } catch (error) {
        console.error('获取邮件详情失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '获取邮件详情失败'});
    }
});

// 删除邮件
app.delete('/api/protected/emails/:id', async (c) => {
    try {
        const payload = (c as any).get('jwtPayload');
        const env = c.env as unknown as Env;
        const emailId = c.req.param('id');

        let whereClause = 'WHERE id = ?';
        let params = [emailId];

        // 非管理员只能删除自己的邮件
        if (payload.user_type !== 'admin') {
            whereClause += ' AND user_id = ?';
            params.push(payload.user_id);
        }

        // 首先获取要删除的附件信息
        const attachments = await env.DB.prepare(`
            SELECT r2_key FROM attachments 
            WHERE email_id = ?
        `).bind(emailId).all();

        // 删除R2中的附件文件
        for (const attachment of attachments.results) {
            try {
                await env.R2.delete(attachment.r2_key as string);
            } catch (error) {
                console.warn('删除R2文件失败:', attachment.r2_key, error);
            }
        }

        // 删除数据库中的邮件记录（级联删除会自动删除附件记录）
        const result = await env.DB.prepare(`
            DELETE FROM emails ${whereClause}
        `).bind(...params).run();

        if (result.meta?.changes === 0) {
            throw new HTTPException(404, {message: '邮件不存在或无权限删除'});
        }

        return c.json({
            success: true,
            message: '邮件删除成功'
        });

    } catch (error) {
        console.error('删除邮件失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '删除邮件失败'});
    }
});

// 下载附件
app.get('/api/protected/attachments/:id/download', async (c) => {
    try {
        const payload = (c as any).get('jwtPayload');
        const env = c.env as unknown as Env;
        const attachmentId = c.req.param('id');

        // 获取附件信息并检查权限
        let query = `
            SELECT a.*, e.user_id 
            FROM attachments a
            JOIN emails e ON a.email_id = e.id
            WHERE a.id = ?
        `;
        let params = [attachmentId];

        if (payload.user_type !== 'admin') {
            query += ' AND e.user_id = ?';
            params.push(payload.user_id);
        }

        const attachment = await env.DB.prepare(query).bind(...params).first();

        if (!attachment) {
            throw new HTTPException(404, {message: '附件不存在或无权限访问'});
        }

        // 从R2获取文件
        const object = await env.R2.get(attachment.r2_key as string);
        if (!object) {
            throw new HTTPException(404, {message: '附件文件不存在'});
        }

        const response = new Response(object.body, {
            headers: {
                'Content-Type': attachment.content_type as string,
                'Content-Disposition': `attachment; filename="${attachment.filename}"`,
                'Content-Length': attachment.size_bytes?.toString() || '0'
            }
        });

        return response;

    } catch (error) {
        console.error('下载附件失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '下载附件失败'});
    }
});

// ============= 管理员API =============

// 获取所有用户列表
app.get('/api/admin/users', async (c) => {
    try {
        const env = c.env as unknown as Env;
        const {page = 1, limit = 20, search = ''} = c.req.query();

        const offset = (parseInt(page as string) - 1) * parseInt(limit as string);
        
        let whereClause = '';
        let params: any[] = [];

        if (search) {
            whereClause = 'WHERE email_prefix LIKE ?';
            params.push(`%${search}%`);
        }

        const users = await env.DB.prepare(`
            SELECT id, email_prefix, user_type, webhook_url, created_at, updated_at
            FROM users 
            ${whereClause}
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?
        `).bind(...params, parseInt(limit as string), offset).all();

        const countResult = await env.DB.prepare(`
            SELECT COUNT(*) as total FROM users ${whereClause}
        `).bind(...params).first();

        return c.json({
            success: true,
            data: {
                users: users.results,
                total: countResult?.total || 0,
                page: parseInt(page as string),
                limit: parseInt(limit as string)
            }
        });

    } catch (error) {
        console.error('获取用户列表失败:', error);
        throw new HTTPException(500, {message: '获取用户列表失败'});
    }
});

// 创建用户
app.post('/api/admin/users', async (c) => {
    try {
        const env = c.env as unknown as Env;
        const {email_password, user_type = 'user', webhook_url, webhook_secret} = await c.req.json();

        if (!email_password || email_password.length < 6) {
            throw new HTTPException(400, {message: '密码长度至少6位'});
        }

        if (!['admin', 'user'].includes(user_type)) {
            throw new HTTPException(400, {message: '用户类型无效'});
        }

        // 生成唯一的邮箱前缀
        let emailPrefix: string;
        let attempts = 0;
        do {
            emailPrefix = generateRandomString(8);
            const existingUser = await findUserByPrefix(env.DB, emailPrefix);
            if (!existingUser) break;
            attempts++;
        } while (attempts < 10);

        if (attempts >= 10) {
            throw new HTTPException(500, {message: '生成邮箱前缀失败，请重试'});
        }

        const hashedPassword = await hashPassword(email_password);
        const result = await env.DB.prepare(`
            INSERT INTO users (email_prefix, email_password, user_type, webhook_url, webhook_secret)
            VALUES (?, ?, ?, ?, ?)
        `).bind(emailPrefix, hashedPassword, user_type, webhook_url || null, webhook_secret || null).run();

        const userId = result.meta.last_row_id as number;

        return c.json({
            success: true,
            data: {
                user_id: userId,
                email_address: `${emailPrefix}@${env.DOMAIN}`,
                email_prefix: emailPrefix,
                user_type: user_type
            }
        });

    } catch (error) {
        console.error('创建用户失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '创建用户失败'});
    }
});

// 删除用户
app.delete('/api/admin/users/:id', async (c) => {
    try {
        const env = c.env as unknown as Env;
        const userId = c.req.param('id');

        // 检查用户是否存在
        const user = await env.DB.prepare(`
            SELECT id, email_prefix FROM users WHERE id = ?
        `).bind(userId).first();

        if (!user) {
            throw new HTTPException(404, {message: '用户不存在'});
        }

        // 删除用户的所有邮件附件文件
        const attachments = await env.DB.prepare(`
            SELECT a.r2_key
            FROM attachments a
            JOIN emails e ON a.email_id = e.id
            WHERE e.user_id = ?
        `).bind(userId).all();

        for (const attachment of attachments.results) {
            try {
                await env.R2.delete(attachment.r2_key as string);
            } catch (error) {
                console.warn('删除R2文件失败:', attachment.r2_key, error);
            }
        }

        // 删除用户（级联删除会自动删除相关邮件和附件记录）
        await env.DB.prepare(`
            DELETE FROM users WHERE id = ?
        `).bind(userId).run();

        return c.json({
            success: true,
            message: '用户删除成功'
        });

    } catch (error) {
        console.error('删除用户失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '删除用户失败'});
    }
});

// 获取转发规则列表
app.get('/api/admin/forward-rules', async (c) => {
    try {
        const env = c.env as unknown as Env;
        const {page = 1, limit = 20} = c.req.query();

        const offset = (parseInt(page as string) - 1) * parseInt(limit as string);

        const rules = await env.DB.prepare(`
            SELECT id, rule_name, sender_filter, keyword_filter, recipient_filter, 
                   webhook_url, webhook_type, enabled, created_at, updated_at
            FROM forward_rules 
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?
        `).bind(parseInt(limit as string), offset).all();

        const countResult = await env.DB.prepare(`
            SELECT COUNT(*) as total FROM forward_rules
        `).first();

        return c.json({
            success: true,
            data: {
                rules: rules.results,
                total: countResult?.total || 0,
                page: parseInt(page as string),
                limit: parseInt(limit as string)
            }
        });

    } catch (error) {
        console.error('获取转发规则失败:', error);
        throw new HTTPException(500, {message: '获取转发规则失败'});
    }
});

// 创建转发规则
app.post('/api/admin/forward-rules', async (c) => {
    try {
        const env = c.env as unknown as Env;
        const {
            rule_name, sender_filter, keyword_filter, recipient_filter,
            webhook_url, webhook_secret, webhook_type = 'custom', enabled = 1
        } = await c.req.json();

        if (!rule_name || !webhook_url) {
            throw new HTTPException(400, {message: '规则名称和Webhook URL不能为空'});
        }

        if (!['dingtalk', 'feishu', 'custom'].includes(webhook_type)) {
            throw new HTTPException(400, {message: 'Webhook类型无效'});
        }

        const result = await env.DB.prepare(`
            INSERT INTO forward_rules (rule_name, sender_filter, keyword_filter, recipient_filter,
                                       webhook_url, webhook_secret, webhook_type, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
            rule_name, sender_filter || null, keyword_filter || null, recipient_filter || null,
            webhook_url, webhook_secret || null, webhook_type, enabled
        ).run();

        return c.json({
            success: true,
            data: {
                rule_id: result.meta.last_row_id
            }
        });

    } catch (error) {
        console.error('创建转发规则失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '创建转发规则失败'});
    }
});

// 更新转发规则
app.put('/api/admin/forward-rules/:id', async (c) => {
    try {
        const env = c.env as unknown as Env;
        const ruleId = c.req.param('id');
        const {
            rule_name, sender_filter, keyword_filter, recipient_filter,
            webhook_url, webhook_secret, webhook_type, enabled
        } = await c.req.json();

        const updates: string[] = [];
        const values: any[] = [];

        if (rule_name !== undefined) {
            updates.push('rule_name = ?');
            values.push(rule_name);
        }
        if (sender_filter !== undefined) {
            updates.push('sender_filter = ?');
            values.push(sender_filter || null);
        }
        if (keyword_filter !== undefined) {
            updates.push('keyword_filter = ?');
            values.push(keyword_filter || null);
        }
        if (recipient_filter !== undefined) {
            updates.push('recipient_filter = ?');
            values.push(recipient_filter || null);
        }
        if (webhook_url !== undefined) {
            updates.push('webhook_url = ?');
            values.push(webhook_url);
        }
        if (webhook_secret !== undefined) {
            updates.push('webhook_secret = ?');
            values.push(webhook_secret || null);
        }
        if (webhook_type !== undefined) {
            updates.push('webhook_type = ?');
            values.push(webhook_type);
        }
        if (enabled !== undefined) {
            updates.push('enabled = ?');
            values.push(enabled);
        }

        if (updates.length === 0) {
            throw new HTTPException(400, {message: '没有需要更新的内容'});
        }

        updates.push('updated_at = CURRENT_TIMESTAMP');
        values.push(ruleId);

        const result = await env.DB.prepare(`
            UPDATE forward_rules 
            SET ${updates.join(', ')}
            WHERE id = ?
        `).bind(...values).run();

        if (result.meta?.changes === 0) {
            throw new HTTPException(404, {message: '转发规则不存在'});
        }

        return c.json({
            success: true,
            message: '转发规则更新成功'
        });

    } catch (error) {
        console.error('更新转发规则失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '更新转发规则失败'});
    }
});

// 删除转发规则
app.delete('/api/admin/forward-rules/:id', async (c) => {
    try {
        const env = c.env as unknown as Env;
        const ruleId = c.req.param('id');

        const result = await env.DB.prepare(`
            DELETE FROM forward_rules WHERE id = ?
        `).bind(ruleId).run();

        if (result.meta?.changes === 0) {
            throw new HTTPException(404, {message: '转发规则不存在'});
        }

        return c.json({
            success: true,
            message: '转发规则删除成功'
        });

    } catch (error) {
        console.error('删除转发规则失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '删除转发规则失败'});
    }
});

// 获取系统设置
app.get('/api/admin/settings', async (c) => {
    try {
        const env = c.env as unknown as Env;

        const settings = await env.DB.prepare(`
            SELECT key, value, description, updated_at
            FROM system_settings
            ORDER BY key
        `).all();

        return c.json({
            success: true,
            data: {
                settings: settings.results
            }
        });

    } catch (error) {
        console.error('获取系统设置失败:', error);
        throw new HTTPException(500, {message: '获取系统设置失败'});
    }
});

// 更新系统设置
app.put('/api/admin/settings', async (c) => {
    try {
        const env = c.env as unknown as Env;
        const settings = await c.req.json();

        if (!settings || typeof settings !== 'object') {
            throw new HTTPException(400, {message: '设置数据格式错误'});
        }

        // 批量更新设置
        for (const [key, value] of Object.entries(settings)) {
            if (typeof value === 'string') {
                await setSystemSetting(env.DB, key, value);
            }
        }

        return c.json({
            success: true,
            message: '系统设置更新成功'
        });

    } catch (error) {
        console.error('更新系统设置失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '更新系统设置失败'});
    }
});

// 获取所有邮件（管理员）
app.get('/api/admin/emails', async (c) => {
    try {
        const env = c.env as unknown as Env;
        const {
            page = 1, limit = 20, search = '', sender = '', 
            start_date = '', end_date = '', has_attachments = ''
        } = c.req.query();

        const offset = (parseInt(page as string) - 1) * parseInt(limit as string);
        
        let whereConditions: string[] = [];
        let params: any[] = [];

        // 搜索条件
        if (search) {
            whereConditions.push('(e.subject LIKE ? OR e.text_content LIKE ?)');
            params.push(`%${search}%`, `%${search}%`);
        }

        if (sender) {
            whereConditions.push('e.sender_email LIKE ?');
            params.push(`%${sender}%`);
        }

        if (start_date) {
            whereConditions.push('e.received_at >= ?');
            params.push(start_date);
        }

        if (end_date) {
            whereConditions.push('e.received_at <= ?');
            params.push(end_date);
        }

        if (has_attachments) {
            whereConditions.push('e.has_attachments = ?');
            params.push(has_attachments === 'true' ? 1 : 0);
        }

        const whereClause = whereConditions.length > 0 ? 
            `WHERE ${whereConditions.join(' AND ')}` : '';

        const emails = await env.DB.prepare(`
            SELECT e.id, e.message_id, e.sender_email, e.recipient_email, 
                   e.subject, e.text_content, e.has_attachments, e.received_at,
                   u.email_prefix
            FROM emails e
            JOIN users u ON e.user_id = u.id
            ${whereClause}
            ORDER BY e.received_at DESC 
            LIMIT ? OFFSET ?
        `).bind(...params, parseInt(limit as string), offset).all();

        const countResult = await env.DB.prepare(`
            SELECT COUNT(*) as total 
            FROM emails e
            JOIN users u ON e.user_id = u.id
            ${whereClause}
        `).bind(...params).first();

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
        throw new HTTPException(500, {message: '获取邮件列表失败'});
    }
});

// 发送用户信息到邮箱（管理员功能）
app.post('/api/admin/users/:id/send-info', async (c) => {
    try {
        const env = c.env as unknown as Env;
        const userId = c.req.param('id');

        const user = await env.DB.prepare(`
            SELECT email_prefix, user_type FROM users WHERE id = ?
        `).bind(userId).first();

        if (!user) {
            throw new HTTPException(404, {message: '用户不存在'});
        }

        // 这里可以实现发送邮件的逻辑
        // 由于是临时邮箱系统，这个功能可能需要外部邮件服务

        return c.json({
            success: true,
            message: '用户信息发送成功',
            data: {
                email_prefix: user.email_prefix,
                email_address: `${user.email_prefix}@${env.DOMAIN}`
            }
        });

    } catch (error) {
        console.error('发送用户信息失败:', error);
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, {message: '发送用户信息失败'});
    }
});

// 静态文件服务 - 现代化完整版
app.get('/', async (c) => {
    const env = c.env as unknown as Env;
    
    // 从系统设置读取是否允许注册
    const allowRegistrationSetting = await getSystemSetting(env.DB, 'allow_registration');
    const allowRegistration = allowRegistrationSetting !== 'false';

    return c.html(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>临时邮箱管理系统</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; 
            color: #333;
            line-height: 1.6;
        }
        
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px; 
        }
        
        .card { 
            background: white; 
            border-radius: 16px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.1); 
            padding: 30px; 
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
        }
        
        .header { 
            text-align: center; 
            color: white; 
            margin-bottom: 40px; 
        }
        
        .header h1 { 
            font-size: 3rem; 
            margin-bottom: 10px; 
            font-weight: 300; 
            text-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .form-group { 
            margin-bottom: 20px; 
        }
        
        .form-group label { 
            display: block; 
            margin-bottom: 8px; 
            font-weight: 600; 
            color: #555;
        }
        
        .form-control { 
            width: 100%; 
            padding: 15px; 
            border: 2px solid #e9ecef; 
            border-radius: 12px; 
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        .form-control:focus { 
            outline: none; 
            border-color: #667eea; 
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn { 
            padding: 15px 30px; 
            border: none; 
            border-radius: 12px; 
            font-size: 1rem; 
            cursor: pointer; 
            font-weight: 600; 
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            text-align: center;
        }
        
        .btn-primary { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            width: 100%;
        }
        
        .btn-primary:hover { 
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-sm {
            padding: 8px 16px;
            font-size: 0.875rem;
            width: auto;
        }
        
        .tabs { 
            display: flex; 
            margin-bottom: 30px; 
            border-bottom: 2px solid #e9ecef;
            background: #f8f9fa;
            border-radius: 12px 12px 0 0;
            overflow: hidden;
        }
        
        .tab { 
            flex: 1;
            padding: 15px 20px; 
            background: none; 
            border: none; 
            font-size: 1rem; 
            cursor: pointer; 
            color: #6c757d; 
            transition: all 0.3s ease;
        }
        
        .tab.active { 
            color: #667eea; 
            background: white;
            font-weight: 600;
        }
        
        .tab-content { 
            display: none; 
        }
        
        .tab-content.active { 
            display: block; 
        }
        
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 250px;
            height: 100vh;
            background: white;
            box-shadow: 2px 0 10px rgba(0,0,0,0.1);
            transform: translateX(-100%);
            transition: transform 0.3s ease;
            z-index: 1000;
            overflow-y: auto;
        }
        
        .sidebar.active {
            transform: translateX(0);
        }
        
        .sidebar-header {
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .sidebar-menu {
            padding: 20px 0;
        }
        
        .sidebar-item {
            display: block;
            padding: 15px 20px;
            color: #333;
            text-decoration: none;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .sidebar-item:hover, .sidebar-item.active {
            background: #f8f9fa;
            color: #667eea;
            border-right: 4px solid #667eea;
        }
        
        .main-content {
            transition: margin-left 0.3s ease;
        }
        
        .main-content.with-sidebar {
            margin-left: 250px;
        }
        
        .top-bar {
            background: white;
            padding: 15px 30px;
            border-radius: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
        }
        
        .hidden { 
            display: none !important; 
        }
        
        .notification { 
            position: fixed; 
            top: 20px; 
            right: 20px; 
            padding: 15px 25px; 
            border-radius: 12px; 
            color: white; 
            font-weight: 600; 
            z-index: 10000;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .notification.success { 
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%); 
        }
        
        .notification.error { 
            background: linear-gradient(135deg, #dc3545 0%, #e83e8c 100%); 
        }
        
        .email-item {
            border: 1px solid #e9ecef;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .email-item:hover {
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        
        .email-sender {
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
        }
        
        .email-subject {
            color: #667eea;
            margin-bottom: 5px;
            font-weight: 500;
        }
        
        .email-date {
            color: #6c757d;
            font-size: 0.9rem;
        }
        
        .email-attachments {
            margin-top: 10px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .attachment-badge {
            background: #e9ecef;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
            color: #495057;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .table th, .table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }
        
        .table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        
        .table tbody tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .badge-success {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-danger {
            background: #f8d7da;
            color: #721c24;
        }
        
        .badge-primary {
            background: #d1ecf1;
            color: #0c5460;
        }
        
        .form-row {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .form-col {
            flex: 1;
        }
        
        .search-box {
            position: relative;
            margin-bottom: 20px;
        }
        
        .search-input {
            width: 100%;
            padding: 15px 45px 15px 15px;
            border: 2px solid #e9ecef;
            border-radius: 12px;
            font-size: 1rem;
        }
        
        .search-icon {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #6c757d;
        }
        
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 10000;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal-content {
            background: white;
            border-radius: 16px;
            padding: 30px;
            max-width: 500px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #e9ecef;
        }
        
        .modal-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: #333;
        }
        
        .close-btn {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: #6c757d;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: #6c757d;
            font-size: 0.9rem;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .main-content.with-sidebar {
                margin-left: 0;
            }
            
            .sidebar {
                width: 100%;
            }
            
            .form-row {
                flex-direction: column;
                gap: 10px;
            }
        }
    </style>
</head>
<body>
    <!-- 侧边栏 -->
    <div id="sidebar" class="sidebar">
        <div class="sidebar-header">
            <h3>邮箱管理</h3>
            <p id="sidebarUserInfo">用户面板</p>
        </div>
        <div class="sidebar-menu">
            <div class="sidebar-item active" onclick="showSection('emails')">📧 我的邮件</div>
            <div class="sidebar-item" onclick="showSection('settings')">⚙️ 账户设置</div>
            <div id="adminMenuItems" class="hidden">
                <div class="sidebar-item" onclick="showSection('admin-users')">👥 用户管理</div>
                <div class="sidebar-item" onclick="showSection('admin-rules')">🔄 转发规则</div>
                <div class="sidebar-item" onclick="showSection('admin-emails')">📨 全部邮件</div>
                <div class="sidebar-item" onclick="showSection('admin-settings')">🛠️ 系统设置</div>
            </div>
            <div class="sidebar-item" onclick="logout()" style="margin-top: 20px; color: #dc3545;">🚪 退出登录</div>
        </div>
    </div>

    <div class="container">
        <div class="header">
            <h1>临时邮箱管理系统</h1>
            <p>现代化的邮件管理解决方案</p>
        </div>

        <!-- 登录注册界面 -->
        <div id="loginSection" class="card">
            <div class="tabs">
                <button class="tab active" onclick="switchTab('login')">登录</button>
                <button class="tab" onclick="switchTab('register')" ${!allowRegistration ? 'style="display:none"' : ''}>注册</button>
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
        <div id="mainSection" class="main-content hidden">
            <!-- 顶部栏 -->
            <div class="top-bar">
                <div>
                    <button class="btn btn-secondary btn-sm" onclick="toggleSidebar()">☰ 菜单</button>
                </div>
                <div class="user-info">
                    <div class="user-avatar" id="userAvatar">U</div>
                    <div>
                        <div id="userEmail" style="font-weight: 600;"></div>
                        <div id="userType" style="font-size: 0.8rem; color: #6c757d;"></div>
                    </div>
                </div>
            </div>

            <!-- 邮件列表 -->
            <div id="emailsSection" class="card">
                <h2>我的邮件</h2>
                <div class="search-box">
                    <input type="text" class="search-input" placeholder="搜索邮件..." id="emailSearch">
                    <span class="search-icon">🔍</span>
                </div>
                <div id="emailList">加载中...</div>
                <div id="emailPagination" style="margin-top: 20px; text-align: center;"></div>
            </div>

            <!-- 用户设置 -->
            <div id="settingsSection" class="card hidden">
                <h2>账户设置</h2>
                <form id="settingsForm">
                    <div class="form-group">
                        <label for="settingsPassword">新密码（留空表示不修改）</label>
                        <input type="password" id="settingsPassword" class="form-control" placeholder="输入新密码">
                    </div>
                    <div class="form-group">
                        <label for="settingsWebhookUrl">Webhook URL</label>
                        <input type="url" id="settingsWebhookUrl" class="form-control" placeholder="https://example.com/webhook">
                    </div>
                    <div class="form-group">
                        <label for="settingsWebhookSecret">Webhook 签名密钥</label>
                        <input type="text" id="settingsWebhookSecret" class="form-control" placeholder="用于验证webhook的密钥">
                    </div>
                    <button type="button" class="btn btn-primary" onclick="updateSettings()">保存设置</button>
                </form>
            </div>

            <!-- 管理员：用户管理 -->
            <div id="adminUsersSection" class="card hidden">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2>用户管理</h2>
                    <button class="btn btn-success btn-sm" onclick="showCreateUserModal()">➕ 创建用户</button>
                </div>
                <div class="search-box">
                    <input type="text" class="search-input" placeholder="搜索用户..." id="userSearch">
                    <span class="search-icon">🔍</span>
                </div>
                <div id="usersList">加载中...</div>
            </div>

            <!-- 管理员：转发规则 -->
            <div id="adminRulesSection" class="card hidden">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2>转发规则管理</h2>
                    <button class="btn btn-success btn-sm" onclick="showCreateRuleModal()">➕ 创建规则</button>
                </div>
                <div id="rulesList">加载中...</div>
            </div>

            <!-- 管理员：全部邮件 -->
            <div id="adminEmailsSection" class="card hidden">
                <h2>全部邮件管理</h2>
                <div class="form-row">
                    <div class="form-col">
                        <input type="text" class="form-control" placeholder="搜索内容..." id="adminEmailSearch">
                    </div>
                    <div class="form-col">
                        <input type="text" class="form-control" placeholder="发件人..." id="adminSenderSearch">
                    </div>
                    <div class="form-col">
                        <select class="form-control" id="adminAttachmentFilter">
                            <option value="">全部邮件</option>
                            <option value="true">有附件</option>
                            <option value="false">无附件</option>
                        </select>
                    </div>
                </div>
                <div id="adminEmailsList">加载中...</div>
            </div>

            <!-- 管理员：系统设置 -->
            <div id="adminSettingsSection" class="card hidden">
                <h2>系统设置</h2>
                <div id="systemSettingsForm">加载中...</div>
            </div>
        </div>
    </div>

    <!-- 模态框：创建用户 -->
    <div id="createUserModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">创建用户</h3>
                <button class="close-btn" onclick="closeModal('createUserModal')">&times;</button>
            </div>
            <form id="createUserForm">
                <div class="form-group">
                    <label for="newUserPassword">密码</label>
                    <input type="password" id="newUserPassword" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="newUserType">用户类型</label>
                    <select id="newUserType" class="form-control">
                        <option value="user">普通用户</option>
                        <option value="admin">管理员</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="newUserWebhook">Webhook URL（可选）</label>
                    <input type="url" id="newUserWebhook" class="form-control">
                </div>
                <button type="button" class="btn btn-primary" onclick="createUser()">创建用户</button>
            </form>
        </div>
    </div>

    <!-- 模态框：创建转发规则 -->
    <div id="createRuleModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">创建转发规则</h3>
                <button class="close-btn" onclick="closeModal('createRuleModal')">&times;</button>
            </div>
            <form id="createRuleForm">
                <div class="form-group">
                    <label for="newRuleName">规则名称</label>
                    <input type="text" id="newRuleName" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="newRuleWebhookUrl">Webhook URL</label>
                    <input type="url" id="newRuleWebhookUrl" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="newRuleWebhookType">Webhook 类型</label>
                    <select id="newRuleWebhookType" class="form-control">
                        <option value="custom">自定义</option>
                        <option value="dingtalk">钉钉</option>
                        <option value="feishu">飞书</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="newRuleSenderFilter">发件人过滤器（可选）</label>
                    <input type="text" id="newRuleSenderFilter" class="form-control" placeholder="例：@gmail.com">
                </div>
                <div class="form-group">
                    <label for="newRuleKeywordFilter">关键字过滤器（可选）</label>
                    <input type="text" id="newRuleKeywordFilter" class="form-control" placeholder="例：重要">
                </div>
                <div class="form-group">
                    <label for="newRuleWebhookSecret">Webhook 签名密钥（可选）</label>
                    <input type="text" id="newRuleWebhookSecret" class="form-control">
                </div>
                <button type="button" class="btn btn-primary" onclick="createRule()">创建规则</button>
            </form>
        </div>
    </div>

    <script>
        // 全局变量
        let currentUser = null;
        let currentToken = null;
        let currentSection = 'emails';
        let sidebarVisible = false;

        // 初始化
        window.addEventListener('DOMContentLoaded', () => {
            checkLoginStatus();
        });

        // 检查登录状态
        function checkLoginStatus() {
            const token = localStorage.getItem('token');
            if (token) {
                currentToken = token;
                // 这里应该验证token有效性，简化版本直接显示主界面
                // 在实际应用中，应该调用API验证token
            }
        }

        // 切换登录/注册标签
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            document.querySelector(\`[onclick="switchTab('\${tab}')"]\`).classList.add('active');
            document.getElementById(tab + 'Form').classList.add('active');
        }

        // 注册
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

        // 登录
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

        // 显示主界面
        function showMainSection() {
            document.getElementById('loginSection').classList.add('hidden');
            document.getElementById('mainSection').classList.remove('hidden');
            
            // 更新用户信息
            document.getElementById('userEmail').textContent = currentUser.email_address;
            document.getElementById('userType').textContent = currentUser.user_type === 'admin' ? '管理员' : '普通用户';
            document.getElementById('userAvatar').textContent = currentUser.email_prefix[0].toUpperCase();
            document.getElementById('sidebarUserInfo').textContent = currentUser.email_address;
            
            // 显示/隐藏管理员菜单
            if (currentUser.user_type === 'admin') {
                document.getElementById('adminMenuItems').classList.remove('hidden');
            }
            
            // 加载初始数据
            showSection('emails');
            toggleSidebar(); // 自动显示侧边栏
        }

        // 退出登录
        function logout() {
            currentToken = null;
            currentUser = null;
            localStorage.removeItem('token');
            
            document.getElementById('loginSection').classList.remove('hidden');
            document.getElementById('mainSection').classList.add('hidden');
            
            // 重置侧边栏
            sidebarVisible = false;
            document.getElementById('sidebar').classList.remove('active');
            
            showNotification('已退出登录', 'success');
        }

        // 切换侧边栏
        function toggleSidebar() {
            sidebarVisible = !sidebarVisible;
            const sidebar = document.getElementById('sidebar');
            const mainContent = document.getElementById('mainSection');
            
            if (sidebarVisible) {
                sidebar.classList.add('active');
                if (window.innerWidth > 768) {
                    mainContent.classList.add('with-sidebar');
                }
            } else {
                sidebar.classList.remove('active');
                mainContent.classList.remove('with-sidebar');
            }
        }

        // 显示不同的功能区域
        function showSection(section) {
            // 隐藏所有区域
            document.querySelectorAll('[id$="Section"]').forEach(el => {
                if (el.id !== 'loginSection' && el.id !== 'mainSection') {
                    el.classList.add('hidden');
                }
            });
            
            // 更新侧边栏激活状态
            document.querySelectorAll('.sidebar-item').forEach(item => {
                item.classList.remove('active');
            });
            
            // 显示对应区域
            currentSection = section;
            const targetSection = document.getElementById(section + 'Section');
            if (targetSection) {
                targetSection.classList.remove('hidden');
            }
            
            // 激活对应的侧边栏项
            const sidebarItems = document.querySelectorAll('.sidebar-item');
            sidebarItems.forEach(item => {
                if (item.textContent.includes(getSectionName(section))) {
                    item.classList.add('active');
                }
            });
            
            // 加载对应数据
            loadSectionData(section);
            
            // 在移动端自动关闭侧边栏
            if (window.innerWidth <= 768) {
                toggleSidebar();
            }
        }

        // 获取区域显示名称
        function getSectionName(section) {
            const names = {
                'emails': '我的邮件',
                'settings': '账户设置',
                'admin-users': '用户管理',
                'admin-rules': '转发规则',
                'admin-emails': '全部邮件',
                'admin-settings': '系统设置'
            };
            return names[section] || section;
        }

        // 加载区域数据
        async function loadSectionData(section) {
            switch (section) {
                case 'emails':
                    await loadEmails();
                    break;
                case 'settings':
                    await loadUserSettings();
                    break;
                case 'admin-users':
                    if (currentUser.user_type === 'admin') {
                        await loadUsers();
                    }
                    break;
                case 'admin-rules':
                    if (currentUser.user_type === 'admin') {
                        await loadForwardRules();
                    }
                    break;
                case 'admin-emails':
                    if (currentUser.user_type === 'admin') {
                        await loadAllEmails();
                    }
                    break;
                case 'admin-settings':
                    if (currentUser.user_type === 'admin') {
                        await loadSystemSettings();
                    }
                    break;
            }
        }

        // 加载邮件列表
        async function loadEmails() {
            try {
                const response = await fetch('/api/protected/emails', {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });

                const result = await response.json();
                
                if (result.success) {
                    const emailsHtml = result.data.emails.map(email => \`
                        <div class="email-item" onclick="showEmailDetail(\${email.id})">
                            <div class="email-sender">\${email.sender_email}</div>
                            <div class="email-subject">\${email.subject || '(无主题)'}</div>
                            <div class="email-date">\${new Date(email.received_at).toLocaleString()}</div>
                            \${email.has_attachments ? '<div class="attachment-badge">📎 有附件</div>' : ''}
                        </div>
                    \`).join('');

                    document.getElementById('emailList').innerHTML = emailsHtml || '<p style="color: #6c757d; text-align: center; padding: 40px;">暂无邮件</p>';
                }
            } catch (error) {
                console.error('加载邮件失败:', error);
                document.getElementById('emailList').innerHTML = '<p style="color: #dc3545; text-align: center; padding: 40px;">加载失败</p>';
            }
        }

        // 加载用户设置
        async function loadUserSettings() {
            try {
                const response = await fetch('/api/protected/user/settings', {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });

                const result = await response.json();
                
                if (result.success) {
                    document.getElementById('settingsWebhookUrl').value = result.data.webhook_url || '';
                    // 注意：不显示实际的密钥值，只显示是否已设置
                }
            } catch (error) {
                console.error('加载用户设置失败:', error);
            }
        }

        // 更新用户设置
        async function updateSettings() {
            const password = document.getElementById('settingsPassword').value;
            const webhookUrl = document.getElementById('settingsWebhookUrl').value;
            const webhookSecret = document.getElementById('settingsWebhookSecret').value;

            try {
                const response = await fetch('/api/protected/user/settings', {
                    method: 'PUT',
                    headers: { 
                        'Authorization': \`Bearer \${currentToken}\`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email_password: password,
                        webhook_url: webhookUrl,
                        webhook_secret: webhookSecret
                    })
                });

                const result = await response.json();
                
                if (result.success) {
                    showNotification('设置更新成功', 'success');
                    // 清空密码输入框
                    document.getElementById('settingsPassword').value = '';
                    document.getElementById('settingsWebhookSecret').value = '';
                } else {
                    showNotification(result.message || '更新失败', 'error');
                }
            } catch (error) {
                showNotification('更新失败: ' + error.message, 'error');
            }
        }

        // 显示通知
        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = \`notification \${type}\`;
            notification.textContent = message;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }

        // 显示模态框
        function showModal(modalId) {
            document.getElementById(modalId).classList.add('active');
        }

        // 关闭模态框
        function closeModal(modalId) {
            document.getElementById(modalId).classList.remove('active');
        }

        // 管理员功能（需要实现）
        async function loadUsers() {
            // 实现用户列表加载
            document.getElementById('usersList').innerHTML = '<p>功能开发中...</p>';
        }

        async function loadForwardRules() {
            // 实现转发规则加载
            document.getElementById('rulesList').innerHTML = '<p>功能开发中...</p>';
        }

        async function loadAllEmails() {
            // 实现全部邮件加载
            document.getElementById('adminEmailsList').innerHTML = '<p>功能开发中...</p>';
        }

        async function loadSystemSettings() {
            // 实现系统设置加载
            document.getElementById('systemSettingsForm').innerHTML = '<p>功能开发中...</p>';
        }

        function showCreateUserModal() {
            showModal('createUserModal');
        }

        function showCreateRuleModal() {
            showModal('createRuleModal');
        }

        function showEmailDetail(emailId) {
            // 实现邮件详情显示
            console.log('显示邮件详情:', emailId);
        }

        // 响应式处理
        window.addEventListener('resize', () => {
            if (window.innerWidth <= 768 && sidebarVisible) {
                document.getElementById('mainSection').classList.remove('with-sidebar');
            } else if (window.innerWidth > 768 && sidebarVisible) {
                document.getElementById('mainSection').classList.add('with-sidebar');
            }
        });
    </script>
</body>
</html>
  `);
});

// ============= 邮件处理函数 =============

async function handleIncomingEmail(message: any, env: Env): Promise<void> {
    try {
        console.log('收到新邮件:', message.from, '到', message.to);

        const recipientEmail = message.to;
        const emailPrefix = recipientEmail.split('@')[0];

        if (!emailPrefix) {
            console.log('无效的邮箱地址:', recipientEmail);
            return;
        }

        const user = await findUserByPrefix(env.DB, emailPrefix);
        if (!user) {
            console.log('用户不存在:', emailPrefix);
            return;
        }

        // 获取邮件基本信息
        const rawEmail = await message.raw();
        const subject = message.headers.get('Subject') || '';
        const messageId = message.headers.get('Message-ID') || `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        let textContent = '';
        let htmlContent = '';
        try {
            textContent = await message.text() || '';
            // 尝试获取HTML内容
            if (message.html) {
                htmlContent = await message.html() || '';
            }
        } catch (error) {
            console.warn('提取邮件内容失败:', error);
        }

        // 处理附件
        let hasAttachments = 0;
        const attachments: Attachment[] = [];
        
        try {
            if (message.attachments && message.attachments.length > 0) {
                console.log(`处理 ${message.attachments.length} 个附件`);
                
                for (const attachment of message.attachments) {
                    const filename = attachment.filename || 'unknown_attachment';
                    const contentType = attachment.type || 'application/octet-stream';
                    const content = attachment.content;
                    
                    if (!content) {
                        console.warn('附件内容为空:', filename);
                        continue;
                    }

                    // 检查附件大小
                    const maxSize = parseInt(env.MAX_ATTACHMENT_SIZE || '52428800'); // 50MB默认
                    if (content.byteLength > maxSize) {
                        console.warn(`附件过大，跳过: ${filename} (${content.byteLength} bytes)`);
                        continue;
                    }

                    // 生成R2存储键
                    const r2Key = `attachments/${Date.now()}-${Math.random().toString(36).substr(2, 9)}-${filename}`;
                    
                    try {
                        // 存储到R2
                        await env.R2.put(r2Key, content, {
                            httpMetadata: {
                                contentType: contentType,
                                contentDisposition: `attachment; filename="${filename}"`
                            }
                        });

                        attachments.push({
                            id: 0, // 数据库自动生成
                            email_id: 0, // 稍后设置
                            filename: filename,
                            content_type: contentType,
                            size_bytes: content.byteLength,
                            r2_key: r2Key
                        });

                        console.log(`附件已保存: ${filename} -> ${r2Key}`);
                    } catch (error) {
                        console.error(`保存附件失败: ${filename}`, error);
                    }
                }

                hasAttachments = attachments.length > 0 ? 1 : 0;
            }
        } catch (error) {
            console.warn('处理附件时出错:', error);
        }

        // 插入邮件记录
        const emailResult = await env.DB.prepare(`
            INSERT INTO emails (message_id, user_id, sender_email, recipient_email,
                                subject, text_content, html_content, raw_email, has_attachments)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
            messageId,
            user.id,
            message.from,
            recipientEmail,
            subject,
            textContent,
            htmlContent,
            rawEmail,
            hasAttachments
        ).run();

        const emailId = emailResult.meta.last_row_id as number;
        console.log(`邮件已保存，ID: ${emailId}`);

        // 保存附件记录
        for (const attachment of attachments) {
            try {
                await env.DB.prepare(`
                    INSERT INTO attachments (email_id, filename, content_type, size_bytes, r2_key)
                    VALUES (?, ?, ?, ?, ?)
                `).bind(
                    emailId,
                    attachment.filename,
                    attachment.content_type,
                    attachment.size_bytes,
                    attachment.r2_key
                ).run();
                console.log(`附件记录已保存: ${attachment.filename}`);
            } catch (error) {
                console.error(`保存附件记录失败: ${attachment.filename}`, error);
            }
        }

        // 构造邮件对象用于转发
        const emailData: Email = {
            id: emailId,
            message_id: messageId,
            user_id: user.id,
            sender_email: message.from,
            recipient_email: recipientEmail,
            subject: subject,
            text_content: textContent,
            html_content: htmlContent,
            raw_email: rawEmail,
            has_attachments: hasAttachments,
            received_at: new Date().toISOString()
        };

        // 处理邮件转发
        await handleEmailForwarding(emailData, user, env);

        console.log('邮件处理完成, ID:', messageId);

    } catch (error) {
        console.error('处理邮件时发生错误:', error);
    }
}

// 处理邮件转发
async function handleEmailForwarding(email: Email, user: User, env: Env): Promise<void> {
    try {
        // 1. 处理用户个人webhook
        if (user.webhook_url) {
            console.log(`发送用户webhook: ${user.webhook_url}`);
            const success = await sendWebhook(
                user.webhook_url, 
                email, 
                user.webhook_secret,
                'custom'
            );
            
            // 记录转发日志
            await env.DB.prepare(`
                INSERT INTO forward_logs (email_id, webhook_url, status, sent_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            `).bind(
                email.id,
                user.webhook_url,
                success ? 'success' : 'failed'
            ).run();
        }

        // 2. 处理系统转发规则
        const rules = await env.DB.prepare(`
            SELECT * FROM forward_rules WHERE enabled = 1 ORDER BY id
        `).all();

        for (const ruleData of rules.results) {
            const rule: ForwardRule = {
                id: ruleData.id as number,
                rule_name: ruleData.rule_name as string,
                sender_filter: ruleData.sender_filter as string | undefined,
                keyword_filter: ruleData.keyword_filter as string | undefined,
                recipient_filter: ruleData.recipient_filter as string | undefined,
                webhook_url: ruleData.webhook_url as string,
                webhook_secret: ruleData.webhook_secret as string | undefined,
                webhook_type: ruleData.webhook_type as 'dingtalk' | 'feishu' | 'custom',
                enabled: ruleData.enabled as number
            };

            // 检查规则是否匹配
            if (matchForwardRule(email, rule)) {
                console.log(`匹配转发规则: ${rule.rule_name}`);
                
                const success = await sendWebhook(
                    rule.webhook_url,
                    email,
                    rule.webhook_secret,
                    rule.webhook_type
                );

                // 记录转发日志
                await env.DB.prepare(`
                    INSERT INTO forward_logs (email_id, rule_id, webhook_url, status, sent_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                `).bind(
                    email.id,
                    rule.id,
                    rule.webhook_url,
                    success ? 'success' : 'failed'
                ).run();
            }
        }

    } catch (error) {
        console.error('邮件转发处理失败:', error);
    }
}

async function handleScheduledCleanup(env: Env): Promise<void> {
    try {
        console.log('开始执行定时清理任务');

        // 从系统设置读取清理天数
        const cleanupDaysSetting = await getSystemSetting(env.DB, 'cleanup_days');
        const cleanupDays = parseInt(cleanupDaysSetting || env.CLEANUP_DAYS || '7');
        
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - cleanupDays);

        // 获取需要清理的邮件附件
        const attachmentsToDelete = await env.DB.prepare(`
            SELECT a.r2_key
            FROM attachments a
            JOIN emails e ON a.email_id = e.id
            WHERE e.received_at < ?
        `).bind(cutoffDate.toISOString()).all();

        // 删除R2中的附件文件
        let deletedAttachments = 0;
        for (const attachment of attachmentsToDelete.results) {
            try {
                await env.R2.delete(attachment.r2_key as string);
                deletedAttachments++;
            } catch (error) {
                console.warn('删除R2文件失败:', attachment.r2_key, error);
            }
        }

        // 删除数据库中的邮件记录（级联删除会自动删除附件记录）
        const emailResult = await env.DB.prepare(`
            DELETE FROM emails
            WHERE received_at < ?
        `).bind(cutoffDate.toISOString()).run();

        // 清理转发日志（保留最近30天）
        const logCutoffDate = new Date();
        logCutoffDate.setDate(logCutoffDate.getDate() - 30);
        
        const logResult = await env.DB.prepare(`
            DELETE FROM forward_logs
            WHERE sent_at < ?
        `).bind(logCutoffDate.toISOString()).run();

        console.log(`清理完成：删除了 ${emailResult.meta?.changes || 0} 封邮件，${deletedAttachments} 个附件文件，${logResult.meta?.changes || 0} 条转发日志`);

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
