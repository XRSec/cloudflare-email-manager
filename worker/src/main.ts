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
import { generateConfigScript, generateEnvScript } from './utils/dynamic-config';

// 路由模块
import { api } from './routes/api';

// 处理器模块
import emailHandler from './handlers/email';
import scheduledHandler from './handlers/scheduled';

// 静态资源服务已移除，现在使用 ASSETS 绑定

import type { Env, ExecutionContext, ScheduledEvent } from './types';

/**
 * 注入动态配置到HTML中
 */
async function injectDynamicConfig(html: string, db: D1Database): Promise<string> {
    try {
        // 生成配置脚本
        const configScript = await generateConfigScript(db);
        const envScript = generateEnvScript();

        // 在</head>标签前注入配置
        const injectionPoint = '</head>';
        const scripts = `
    <script>
        ${envScript}
    </script>
    <script>
        ${configScript}
    </script>
`;

        return html.replace(injectionPoint, scripts + injectionPoint);
    } catch (error) {
        console.error('注入动态配置失败:', error);
        // 如果注入失败，返回原始HTML
        return html;
    }
}

// 创建 Hono 应用
const app = new Hono<{ Bindings: Env }>();

// 全局 CORS 配置
app.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
}));

// 静态资源处理中间件 - 参考 cloudflare_temp_email 实现
app.use('*', async (c, next) => {
    // 检查是否为静态文件请求
    if (c.env.ASSETS && !c.req.path.startsWith('/api/')) {
        const url = new URL(c.req.raw.url);

        // 如果是 SPA 路由（没有文件扩展名），重定向到根路径
        if (!url.pathname.includes('.')) {
            url.pathname = '/';
        }

        // 通过 ASSETS 绑定获取静态资源
        return c.env.ASSETS.fetch(url.toString());
    }

    await next();
});

// 全局缓存头中间件
app.use('*', async (c, next) => {
    await next();

    // 为 API 响应添加缓存头
    if (c.req.path.startsWith('/api/')) {
        c.header('Cache-Control', 'no-cache, no-store, must-revalidate');
        c.header('Pragma', 'no-cache');
        c.header('Expires', '0');
    }
});

// 全局错误处理
app.onError((err: any, c: any) => {
    console.error('全局错误处理:', err);

    if (err instanceof HTTPException) {
        return err.getResponse();
    }

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
app.get('/api/debug', async (c: any) => {
    // 从系统设置获取调试模式状态
    const config = await getSystemConfig(c.env.DB);

    if (!config.debug_mode && c.env.cem_debug !== 'true') {
        throw new HTTPException(404, { message: '接口不存在' });
    }

    // 检查管理员权限
    try {
        await jwtAuthMiddleware(c, async () => {
            await adminAuthMiddleware(c, async () => {
                // 权限检查通过，继续处理
            });
        });
    } catch (error) {
        throw new HTTPException(403, { message: '需要管理员权限' });
    }

    return c.json({
        success: true,
        data: {
            message: '调试模式已启用',
            timestamp: new Date().toISOString(),
            environment: {
                debug_mode: config.debug_mode,
                env_debug: c.env.cem_debug === 'true',
                domain: c.env.DOMAIN,
            }
        }
    });
});

// 模拟邮件接收接口（仅在调试模式下启用，且仅管理员可访问）
app.post('/api/debug/simulate-email', async (c: any) => {
    // 从系统设置获取调试模式状态
    const config = await getSystemConfig(c.env.DB);

    if (!config.debug_mode && c.env.cem_debug !== 'true') {
        throw new HTTPException(404, { message: '接口不存在' });
    }

    // 检查管理员权限
    try {
        await jwtAuthMiddleware(c, async () => {
            await adminAuthMiddleware(c, async () => {
                // 权限检查通过，继续处理
            });
        });
    } catch (error) {
        throw new HTTPException(403, { message: '需要管理员权限' });
    }

    try {
        const { to, from, subject, content, content_type } = await c.req.json();

        if (!to || !from) {
            return c.json({
                success: false,
                error: '收件人和发件人不能为空'
            }, 400);
        }

        const emailContent = content || '这是一封测试邮件';
        const contentType = content_type || 'text';

        // 构造模拟邮件对象
        const mockMessage = {
            to,
            from,
            headers: new Map([
                ['Subject', subject || '测试邮件'],
                ['Message-ID', `test-${Date.now()}@debug.local`]
            ]),
            text: () => Promise.resolve(contentType === 'text' ? emailContent : ''),
            html: () => Promise.resolve(contentType === 'html' ? emailContent : ''),
            raw: () => Promise.resolve(`From: ${from}\nTo: ${to}\nSubject: ${subject || '测试邮件'}\n\n${emailContent}`)
        };

        await emailHandler.email(mockMessage, c.env, {});

        return c.json({
            success: true,
            message: '模拟邮件发送成功'
        });

    } catch (error) {
        console.error('模拟邮件发送失败:', error);
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

        // 如果是 SPA 路由（没有文件扩展名），重定向到根路径
        if (!url.pathname.includes('.')) {
            url.pathname = '/';
        }

        const response = await c.env.ASSETS.fetch(url.toString());

        // 如果是HTML文件，注入动态配置
        if (response && response.headers.get('content-type')?.includes('text/html')) {
            const html = await response.text();
            const modifiedHtml = await injectDynamicConfig(html, c.env.DB);

            return new Response(modifiedHtml, {
                status: response.status,
                statusText: response.statusText,
                headers: {
                    ...Object.fromEntries(response.headers.entries()),
                    'Content-Type': 'text/html; charset=utf-8'
                }
            });
        }

        return response;
    }

    // 如果没有 ASSETS 绑定，返回404
    return c.text('前端资源不可用', 404);
});

// favicon.ico 处理（返回空响应避免404）
app.get('/favicon.ico', (c: any) => {
    return new Response(null, {
        status: 204,
        headers: {
            'Cache-Control': 'public, max-age=86400' // 缓存24小时
        }
    });
});

// 静态资源路由已移除，现在通过 ASSETS 绑定处理

/**
 * Workers 主要导出对象
 */
export default {
    /**
     * HTTP 请求处理
     */
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        // 初始化调试模式
        initDebugMode(env);

        // 初始化系统设置
        try {
            await initializeSystemSettings(env.DB);
        } catch (error) {
            console.error('初始化系统设置失败:', error);
        }

        return app.fetch(request, env, ctx);
    },

    /**
     * 邮件处理
     */
    async email(message: any, env: Env, ctx: ExecutionContext): Promise<void> {
        initDebugMode(env);
        await emailHandler.email(message, env, ctx);
    },

    /**
     * 定时任务处理
     */
    async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
        initDebugMode(env);
        await scheduledHandler.scheduled(event, env, ctx);
    }
};
