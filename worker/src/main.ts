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

// 路由模块
import { auth } from './routes/auth';
import { user } from './routes/user';
import { admin } from './routes/admin';
import { system } from './routes/system';
import { adminSecurityRoutes } from './routes/admin-security';
import { mailbox } from './routes/mailbox';

// 处理器模块
import emailHandler from './handlers/email';
import scheduledHandler from './handlers/scheduled';

// 静态资源服务
import { staticAssetService } from './services/static';

import type { Env, ExecutionContext, ScheduledEvent } from './types';

// 创建 Hono 应用
const app = new Hono<{ Bindings: Env }>();

// 全局 CORS 配置
app.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
}));

// 静态资源处理中间件
app.use('*', async (c, next) => {
    // 检查是否为静态文件请求
    if (c.env.ASSETS && !c.req.path.startsWith('/api/')) {
        const url = new URL(c.req.raw.url);

        // 如果是 SPA 路由（没有文件扩展名），重定向到根路径
        if (!url.pathname.includes('.')) {
            url.pathname = '/';
        }

        // 通过 ASSETS 绑定获取静态资源
        return c.env.ASSETS.fetch(url);
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

// 注册路由模块
app.route('/api', auth);           // 认证相关: /api/register, /api/login, /api/logout
app.route('/api/protected', user); // 用户功能: /api/protected/...
app.route('/api/admin', admin);    // 管理员功能: /api/admin/...
app.route('/api/admin/security', adminSecurityRoutes); // 管理员安全功能: /api/admin/security/...
app.route('/api/system', system);  // 系统配置: /api/system/...
app.route('/api/mailbox', mailbox); // 邮箱管理: /api/mailbox/...

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

// 静态资源路由 - 处理所有前端资源
app.get('*', async (c: any) => {
    const path = c.req.path;

    // 如果是API路径，跳过静态资源处理
    if (path.startsWith('/api/')) {
        return c.notFound();
    }

    try {
        const html = await getTemplate();
        return new Response(html, {
            status: 200,
            headers: {
                'Content-Type': 'text/html; charset=utf-8',
                'Cache-Control': 'public, max-age=300' // 缓存5分钟，便于更新
            }
        });
        // 尝试获取静态资源
        const assetResponse = await staticAssetService.getAsset(path, c.env);

        if (assetResponse) {
            return assetResponse;
        }

        // 如果找不到具体资源，返回默认HTML（SPA路由支持）
        const defaultHTML = await staticAssetService.getDefaultHTML(c.env);
        if (defaultHTML) {
            return defaultHTML;
        }

        // 如果连默认HTML都没有，返回404
        return c.text('页面不存在', 404);
    } catch (error) {
        console.error('静态资源处理失败:', error);
        return c.text('服务器错误', 500);
    }
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

// 静态资源路由
app.get('/static/*', async (c: any) => {
    const path = c.req.path.replace('/static/', '');

    // 这里可以从 KV 或其他存储中获取静态资源
    // 目前返回 404，但添加了缓存头
    return new Response('静态资源不存在', {
        status: 404,
        headers: {
            'Cache-Control': 'public, max-age=3600', // 缓存1小时
            'Content-Type': 'text/plain; charset=utf-8'
        }
    });
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
