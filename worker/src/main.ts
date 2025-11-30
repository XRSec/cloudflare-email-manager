/**
 * Cloudflare 临时邮箱管理系统 - 主入口文件
 * 模块化重构版本
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { HTTPException } from 'hono/http-exception';

// 工具和中间件
import { initDebugMode } from './utils/debug';
import { initializeSystemSettings, getSystemConfig } from './services/settings';
import { jwtAuthMiddleware, adminAuthMiddleware } from './middleware/auth';
import { debugModeMiddleware } from './middleware/debug';
import { rateLimitMiddleware } from './middleware/rate-limit';
// 动态配置生成已移除，前端独立处理配置

// 路由模块
import { api } from './routes/api';

// 处理器模块
import emailHandler from './handlers/email';
import scheduledHandler from './handlers/scheduled';

// 静态资源服务已完全移除，前端独立处理所有静态资源

import type { Env, ExecutionContext, ScheduledEvent } from './types';

// 创建 Hono 应用
const app = new Hono<{ Bindings: Env }>();

// 全局 CORS 配置
app.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
}));

// 静态资源处理中间件 - 通过 ASSETS 绑定处理
app.use('*', async (c, next) => {
    // 检查是否为静态文件请求
    if (c.env.ASSETS && !c.req.path.startsWith('/api/')) {
        const url = new URL(c.req.raw.url);
        const pathname = url.pathname;

        // 如果是 SPA 路由（没有文件扩展名），重定向到根路径
        if (!pathname.includes('.')) {
            url.pathname = '/';
        }

        // 通过 ASSETS 绑定获取静态资源
        const response = await c.env.ASSETS.fetch(url.toString());

        // 为静态资源设置合适的 Cache-Control 头
        if (response && response.status === 200) {
            const newResponse = new Response(response.body, response);

            // 根据文件类型设置不同的缓存策略
            if (pathname.endsWith('.html') || pathname === '/' || !pathname.includes('.')) {
                // HTML 文件：不缓存或短缓存（因为可能包含动态内容）
                newResponse.headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
                newResponse.headers.set('Pragma', 'no-cache');
                newResponse.headers.set('Expires', '0');
            } else if (pathname.match(/\.(css|js|woff|woff2|ttf|eot|svg|png|jpg|jpeg|gif|ico|webp)$/i)) {
                // CSS、JS、字体、图片等静态资源：长期缓存（1年）
                // 这些文件通常有版本号或 hash，可以安全地长期缓存
                newResponse.headers.set('Cache-Control', 'public, max-age=31536000, immutable');
            } else {
                // 其他静态资源：中等缓存（1小时）
                newResponse.headers.set('Cache-Control', 'public, max-age=3600');
            }

            return newResponse;
        }

        return response;
    }

    await next();
});

// API频率限制中间件（在缓存头之前应用，以便在限制时也能设置响应头）
app.use('*', rateLimitMiddleware);

// 全局缓存头中间件
app.use('*', async (c, next) => {
    await next();

    // 为 API 响应添加缓存头
    const path = c.req.path;

    // 排除需要自定义缓存策略的路径：
    const isAttachment = path.includes('/attachments/');      // 附件下载（长期缓存）
    const isRawEmail = path.includes('/raw');                 // 原始邮件（长期缓存）
    const isEmailDetail = path.match(/^\/api\/emails\/[^\/]+$/) && c.req.method === 'GET'; // 邮件详情（长期缓存）

    if (c.req.path.startsWith('/api/') && !isAttachment && !isRawEmail && !isEmailDetail) {
        // 其他 API：禁用缓存
        c.header('Cache-Control', 'no-cache, no-store, must-revalidate');
        c.header('Pragma', 'no-cache');
        c.header('Expires', '0');
    } else if (isEmailDetail && c.res.status === 200) {
        // 邮件详情：长期缓存（1 年）
        // 邮件内容是不可变的，is_read 状态通过专门的 PATCH 接口更新
        c.header('Cache-Control', 'public, max-age=31536000, immutable');
        c.header('Vary', 'Authorization');
    }
});

// 全局错误处理
app.onError((err: any, c: any) => {
    // HTTPException 是预期的业务错误，静默处理，不打印任何日志
    if (err instanceof HTTPException) {
        // 直接返回响应，不打印堆栈信息
        return err.getResponse();
    }

    // 只有非预期的错误才打印 error 日志（但不打印完整堆栈，避免噪音）
    const errorMessage = err instanceof Error ? err.message : String(err);
    console.error('[ERROR] [系统] 全局错误处理 - 未预期的错误:', errorMessage);

    return c.json({
        success: false,
        error: '服务器内部错误'
    }, 500);
});

// 404 处理
app.notFound((c: any) => {
    return c.json({
        success: false,
        error: '接口不存在'
    }, 404);
});

// 注册统一API路由
app.route('/api', api);

// 调试接口（仅在调试模式下启用，且仅管理员可访问）
app.get('/api/debug', jwtAuthMiddleware, adminAuthMiddleware, debugModeMiddleware, async (c: any) => {
    // 从系统设置获取调试模式状态
    const config = await getSystemConfig(c.env.DB);

    return c.json({
        success: true,
        data: {
            message: '调试模式已启用',
            timestamp: new Date().toISOString(),
            environment: {
                debug_mode: config.debug_mode,
            }
        }
    });
});

/**
 * 生成符合 RFC 822 标准的原始邮件格式
 * 
 * @param from 发件人邮箱
 * @param to 收件人邮箱
 * @param subject 邮件主题
 * @param content 邮件内容
 * @param contentType 内容类型 ('text' | 'html')
 * @returns RFC 822 格式的原始邮件字符串
 * 
 * @description
 * RFC 822 邮件格式说明:
 * 1. 邮件头（Headers）必须包含：From, To, Subject, Date, Message-ID
 * 2. 头部和正文之间必须用空行分隔
 * 3. 每行头部字段格式：字段名: 字段值
 * 4. 日期格式：RFC 2822 格式（如：Mon, 1 Jan 2024 12:00:00 +0000）
 * 5. Message-ID 格式：<唯一标识符@域名>
 */
function generateRFC822RawEmail(
    from: string,
    to: string,
    subject: string,
    content: string,
    contentType: 'text' | 'html' = 'text'
): string {
    const now = new Date();
    const messageId = `<test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@debug.local>`;

    // 格式化日期为 RFC 2822 格式
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const dayName = days[now.getUTCDay()];
    const monthName = months[now.getUTCMonth()];
    const day = String(now.getUTCDate()).padStart(2, '0');
    const hours = String(now.getUTCHours()).padStart(2, '0');
    const minutes = String(now.getUTCMinutes()).padStart(2, '0');
    const seconds = String(now.getUTCSeconds()).padStart(2, '0');
    const year = now.getUTCFullYear();
    const timezone = '+0000'; // UTC
    const dateStr = `${dayName}, ${day} ${monthName} ${year} ${hours}:${minutes}:${seconds} ${timezone}`;

    // 构建邮件头
    const headers = [
        `From: ${from}`,
        `To: ${to}`,
        `Subject: ${subject || '测试邮件'}`,
        `Date: ${dateStr}`,
        `Message-ID: ${messageId}`,
        `MIME-Version: 1.0`,
        `Content-Type: ${contentType === 'html' ? 'text/html' : 'text/plain'}; charset=UTF-8`,
        `Content-Transfer-Encoding: 8bit`
    ];

    // RFC 822 格式：头部 + 空行 + 正文
    return headers.join('\r\n') + '\r\n\r\n' + content;
}

// 模拟邮件接收接口（仅在调试模式下启用，且仅管理员可访问）
app.post('/api/debug/simulate-email', jwtAuthMiddleware, adminAuthMiddleware, debugModeMiddleware, async (c: any) => {

    try {
        const { to, from, subject, content, content_type } = await c.req.json();

        if (!to || !from) {
            return c.json({
                success: false,
                error: '收件人和发件人不能为空'
            }, 400);
        }

        const emailContent = content || '这是一封测试邮件';
        const contentType = (content_type || 'text') as 'text' | 'html';

        // 生成符合 RFC 822 标准的原始邮件
        const rawEmail = generateRFC822RawEmail(from, to, subject || '测试邮件', emailContent, contentType);

        // 构造模拟邮件对象
        const mockMessage = {
            to,
            from,
            headers: new Map([
                ['Subject', subject || '测试邮件'],
                ['Message-ID', rawEmail.match(/Message-ID:\s*(.+)/)?.[1] || `test-${Date.now()}@debug.local`],
                ['Date', rawEmail.match(/Date:\s*(.+)/)?.[1] || new Date().toUTCString()],
                ['Content-Type', contentType === 'html' ? 'text/html; charset=UTF-8' : 'text/plain; charset=UTF-8']
            ]),
            text: () => Promise.resolve(contentType === 'text' ? emailContent : ''),
            html: () => Promise.resolve(contentType === 'html' ? emailContent : ''),
            raw: () => Promise.resolve(rawEmail) // 返回符合 RFC 822 标准的原始邮件
        };

        await emailHandler.email(mockMessage, c.env, {});

        return c.json({
            success: true,
            message: '模拟邮件发送成功',
            raw_email_preview: rawEmail.substring(0, 500) + (rawEmail.length > 500 ? '...' : '') // 返回前500字符预览
        });

    } catch (error) {
        const { errorLog } = await import('./utils/debug');
        errorLog('邮件测试', '模拟邮件发送失败:', error);
        return c.json({
            success: false,
            error: error instanceof Error ? error.message : '模拟邮件发送失败'
        }, 500);
    }
});

// 静态资源路由 - 通过 ASSETS 绑定处理所有前端资源
app.get('*', async (c: any) => {
    const path = c.req.path;

    // 如果是API路径，跳过静态资源处理
    if (path.startsWith('/api/')) {
        return c.notFound();
    }

    // 通过 ASSETS 绑定获取静态资源
    if (c.env.ASSETS) {
        const url = new URL(c.req.raw.url);
        const pathname = url.pathname;

        // 如果是 SPA 路由（没有文件扩展名），重定向到根路径
        if (!pathname.includes('.')) {
            url.pathname = '/';
        }

        const response = await c.env.ASSETS.fetch(url.toString());

        // 为静态资源设置合适的 Cache-Control 头
        if (response && response.status === 200) {
            const newResponse = new Response(response.body, response);

            // 根据文件类型设置不同的缓存策略
            if (pathname.endsWith('.html') || pathname === '/' || !pathname.includes('.')) {
                // HTML 文件：不缓存或短缓存（因为可能包含动态内容）
                newResponse.headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
                newResponse.headers.set('Pragma', 'no-cache');
                newResponse.headers.set('Expires', '0');
            } else if (pathname.match(/\.(css|js|woff|woff2|ttf|eot|svg|png|jpg|jpeg|gif|ico|webp)$/i)) {
                // CSS、JS、字体、图片等静态资源：长期缓存（1年）
                // 这些文件通常有版本号或 hash，可以安全地长期缓存
                newResponse.headers.set('Cache-Control', 'public, max-age=31536000, immutable');
            } else {
                // 其他静态资源：中等缓存（1小时）
                newResponse.headers.set('Cache-Control', 'public, max-age=3600');
            }

            return newResponse;
        }

        return response;
    }

    // 如果没有 ASSETS 绑定，返回404
    return c.text('前端资源不可用', 404);
});

/**
 * Workers 主要导出对象
 */
export default {
    /**
     * HTTP 请求处理
     */
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        // 初始化调试模式
        await initDebugMode(env);

        // 初始化系统设置
        try {
            await initializeSystemSettings(env.DB);
        } catch (error) {
            const { errorLog } = await import('./utils/debug');
            errorLog('系统初始化', '初始化系统设置失败:', error);
        }

        return app.fetch(request, env, ctx);
    },

    /**
     * 邮件处理
     */
    async email(message: any, env: Env, ctx: ExecutionContext): Promise<void> {
        const { debugLog, infoLog } = await import('./utils/debug');

        infoLog('邮件接收', '========== Cloudflare Email Routing 入口 ==========');
        infoLog('邮件接收', '时间: ' + new Date().toISOString());

        // 打印 Cloudflare Email 事件信息
        if (message) {
            debugLog('邮件接收', '基本信息:');
            debugLog('邮件接收', '  - rcptTo (收件人):', message.to || message.rcptTo);
            debugLog('邮件接收', '  - mailFrom (发件人):', message.from || message.mailFrom);
            debugLog('邮件接收', '  - rawSize (原始大小):', message.rawSize || '未知');

            // 尝试获取 requestId（可能在 ctx 或其他地方）
            const requestId = (ctx as any)?.requestId || (message as any)?.requestId || '未知';
            debugLog('邮件接收', '  - requestId:', requestId);

            // 打印消息对象的所有键，方便调试
            debugLog('邮件接收', '  - message 对象键:', Object.keys(message));
            debugLog('邮件接收', '  - message.from:', message.from);
            debugLog('邮件接收', '  - message.to:', message.to);

            // 检查是否有额外的元数据
            if ((message as any).$metadata) {
                debugLog('邮件接收', '  - $metadata:', JSON.stringify((message as any).$metadata));
            }
            if ((message as any).$workers) {
                debugLog('邮件接收', '  - $workers.event:', JSON.stringify((message as any).$workers?.event));
            }
        }

        debugLog('邮件接收', '环境变量检查:');
        debugLog('邮件接收', '- DB 存在:', !!env.DB);
        debugLog('邮件接收', '- R2 存在:', !!env.R2);
        debugLog('邮件接收', '==================================================');

        await initDebugMode(env);
        await emailHandler.email(message, env, ctx);
    },

    /**
     * 定时任务处理
     */
    async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
        await initDebugMode(env);
        await scheduledHandler.scheduled(event, env, ctx);
    }
};
