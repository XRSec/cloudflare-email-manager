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

// 调试接口（仅在调试模式下启用）
app.get('/api/debug', async (c: any) => {
    // 从系统设置获取调试模式状态
    const config = await getSystemConfig(c.env.DB);

    if (!config.debug_mode && c.env.cem_debug !== 'true') {
        throw new HTTPException(404, { message: '接口不存在' });
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

// 模拟邮件接收接口（仅在调试模式下启用）
app.post('/api/debug/simulate-email', async (c: any) => {
    // 从系统设置获取调试模式状态
    const config = await getSystemConfig(c.env.DB);

    if (!config.debug_mode && c.env.cem_debug !== 'true') {
        throw new HTTPException(404, { message: '接口不存在' });
    }

    try {
        const { to, from, subject, text, html } = await c.req.json();

        if (!to || !from) {
            return c.json({
                success: false,
                error: '收件人和发件人不能为空'
            }, 400);
        }

        const textContent = text || '这是一封测试邮件';
        const htmlContent = html || `<p>${textContent}</p>`;

        // 构造模拟邮件对象
        const mockMessage = {
            to,
            from,
            headers: new Map([
                ['Subject', subject || '测试邮件'],
                ['Message-ID', `test-${Date.now()}@debug.local`]
            ]),
            text: () => Promise.resolve(textContent),
            html: () => Promise.resolve(htmlContent),
            raw: () => Promise.resolve(`From: ${from}\nTo: ${to}\nSubject: ${subject || '测试邮件'}\n\n${textContent}`)
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
