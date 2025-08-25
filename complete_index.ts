/**
 * 完整的临时邮箱系统 - 单文件版本
 * 所有功能都整合在这个文件中，便于部署
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { jwt } from 'hono/jwt';
import { HTTPException } from 'hono/http-exception';

// 环境变量接口
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

// 创建应用实例
const app = new Hono<{ Bindings: Env }>();

// CORS配置
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

// ============= 工具函数 =============

// 生成随机字符串
function generateRandomString(length: number = 8): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// 密码哈希
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// 验证密码
async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
  const hash = await hashPassword(password);
  return hash === hashedPassword;
}

// 生成JWT token
async function generateJWT(payload: any, secret: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (24 * 60 * 60); // 24小时过期
  
  const jwtPayload = {
    ...payload,
    iat: now,
    exp: exp
  };
  
  // 简单的JWT实现
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadStr = btoa(JSON.stringify(jwtPayload));
  const signature = await signJWT(`${header}.${payloadStr}`, secret);
  return `${header}.${payloadStr}.${signature}`;
}

// JWT签名
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

// 验证JWT token
async function verifyJWT(token: string, secret: string): Promise<any> {
  try {
    const [header, payload, signature] = token.split('.');
    const expectedSignature = await signJWT(`${header}.${payload}`, secret);
    
    if (signature !== expectedSignature) {
      throw new Error('Invalid signature');
    }
    
    const decodedPayload = JSON.parse(atob(payload));
    
    // 检查过期时间
    if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired');
    }
    
    return decodedPayload;
  } catch (error) {
    throw new Error('Invalid token');
  }
}

// ============= API 路由 =============

// 用户注册
app.post('/api/register', async (c) => {
  try {
    const { email_password } = await c.req.json();
    
    if (!email_password || email_password.length < 6) {
      throw new HTTPException(400, { message: '密码长度至少6位' });
    }
    
    // 检查是否允许注册
    const allowRegistration = c.env.ALLOW_REGISTRATION !== 'false';
    if (!allowRegistration) {
      throw new HTTPException(403, { message: '当前不允许新用户注册' });
    }
    
    // 生成随机邮件前缀
    const emailPrefix = generateRandomString(8);
    
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

// 用户登录
app.post('/api/login', async (c) => {
  try {
    const { email_prefix, email_password } = await c.req.json();
    
    if (!email_prefix || !email_password) {
      throw new HTTPException(400, { message: '邮件前缀和密码不能为空' });
    }
    
    // 查找用户
    const user = await c.env.DB.prepare(`
      SELECT id, email_prefix, email_password, user_type
      FROM users WHERE email_prefix = ?
    `).bind(email_prefix).first();
    
    if (!user) {
      throw new HTTPException(401, { message: '用户不存在' });
    }
    
    // 验证密码
    const isValidPassword = await verifyPassword(email_password, user.email_password as string);
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

// JWT中间件
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

// 获取用户邮件列表
app.get('/api/protected/emails', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const { page = 1, limit = 20 } = c.req.query();
    
    const userId = payload.user_id;
    const offset = (parseInt(page as string) - 1) * parseInt(limit as string);
    
    // 查询邮件列表
    const emails = await c.env.DB.prepare(`
      SELECT 
        e.id, e.message_id, e.sender_email, e.recipient_email,
        e.subject, e.text_content, e.has_attachments, e.received_at,
        COUNT(a.id) as attachment_count
      FROM emails e
      LEFT JOIN attachments a ON e.id = a.email_id
      WHERE e.user_id = ?
      GROUP BY e.id
      ORDER BY e.received_at DESC
      LIMIT ? OFFSET ?
    `).bind(userId, parseInt(limit as string), offset).all();
    
    // 查询总数
    const countResult = await c.env.DB.prepare(`
      SELECT COUNT(*) as total FROM emails WHERE user_id = ?
    `).bind(userId).first();
    
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

// 获取邮件详情
app.get('/api/protected/emails/:id', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const emailId = c.req.param('id');
    const userId = payload.user_id;
    
    // 查询邮件详情
    const email = await c.env.DB.prepare(`
      SELECT * FROM emails WHERE id = ? AND user_id = ?
    `).bind(emailId, userId).first();
    
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在或无权限访问' });
    }
    
    // 查询附件列表
    const attachments = await c.env.DB.prepare(`
      SELECT id, filename, content_type, size_bytes, created_at
      FROM attachments WHERE email_id = ?
    `).bind(emailId).all();
    
    return c.json({
      success: true,
      data: {
        email: email,
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

// 删除邮件
app.delete('/api/protected/emails/:id', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const emailId = c.req.param('id');
    const userId = payload.user_id;
    
    // 先查询要删除的邮件的附件
    const attachments = await c.env.DB.prepare(`
      SELECT r2_key FROM attachments a
      JOIN emails e ON a.email_id = e.id
      WHERE e.id = ? AND e.user_id = ?
    `).bind(emailId, userId).all();
    
    // 删除R2中的附件
    for (const attachment of attachments.results) {
      try {
        await c.env.R2.delete(attachment.r2_key as string);
      } catch (error) {
        console.warn('删除R2附件失败:', attachment.r2_key, error);
      }
    }
    
    // 删除邮件记录
    const result = await c.env.DB.prepare(`
      DELETE FROM emails WHERE id = ? AND user_id = ?
    `).bind(emailId, userId).run();
    
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

// 静态文件服务
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
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
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
               font-size: 1rem; cursor: pointer; font-weight: 500; width: 100%; }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5a6fd8; }
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
        .email-address { font-size: 1.2rem; font-weight: 600; color: #667eea; }
        .notification { position: fixed; top: 20px; right: 20px; 
                        padding: 15px 20px; border-radius: 8px; color: white; 
                        font-weight: 500; z-index: 1000; }
        .notification.success { background: #28a745; }
        .notification.error { background: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>临时邮箱</h1>
            <p>简洁高效的邮件服务</p>
        </div>

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

        <div id="mainSection" class="hidden">
            <div class="card">
                <div class="email-display">
                    <div class="email-address" id="userEmail"></div>
                    <button class="btn btn-primary" style="margin-top: 10px; width: auto;" onclick="logout()">退出登录</button>
                </div>
                <div id="emailList">
                    <h3>邮件列表</h3>
                    <div id="emails"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentUser = null;
        let currentToken = null;

        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            document.querySelector(\`[onclick="switchTab('\${tab}')"]\`).classList.add('active');
            document.getElementById(tab + 'Form').classList.add('active');
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
            loadEmails();
        }

        async function loadEmails() {
            try {
                const response = await fetch('/api/protected/emails', {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });

                const result = await response.json();
                
                if (result.success) {
                    const emailsHtml = result.data.emails.map(email => \`
                        <div style="border: 1px solid #dee2e6; border-radius: 8px; padding: 15px; margin-bottom: 10px;">
                            <div style="font-weight: 600;">\${email.sender_email}</div>
                            <div style="color: #667eea; margin: 5px 0;">\${email.subject || '(无主题)'}</div>
                            <div style="color: #6c757d; font-size: 0.9rem;">\${new Date(email.received_at).toLocaleString()}</div>
                        </div>
                    \`).join('');
                    
                    document.getElementById('emails').innerHTML = emailsHtml || '<p style="color: #6c757d;">暂无邮件</p>';
                }
            } catch (error) {
                console.error('加载邮件失败:', error);
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

        // 检查是否已登录
        window.addEventListener('DOMContentLoaded', () => {
            const token = localStorage.getItem('token');
            if (token) {
                currentToken = token;
                // 这里可以验证token有效性
            }
        });
    </script>
</body>
</html>
  `);
});

// ============= 邮件处理 =============

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
    const user = await env.DB.prepare(`
      SELECT id FROM users WHERE email_prefix = ?
    `).bind(emailPrefix).first();
    
    if (!user) {
      console.log('用户不存在:', emailPrefix);
      return;
    }

    // 读取邮件内容
    const rawEmail = await message.raw();
    const subject = message.headers.get('Subject') || '';
    const messageId = message.headers.get('Message-ID') || `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
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
      '', // 简化版本暂不解析邮件内容
      rawEmail
    ).run();

    console.log('邮件处理完成');
    
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