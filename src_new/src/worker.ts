/**
 * Cloudflare Workers 入口文件 - Vue 3 版本
 * 这个文件将在构建时被用于生成 Workers 脚本
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { HTTPException } from 'hono/http-exception'

// 导入原有的后端逻辑
// 注意：这些文件需要从原始 src 目录复制或重构
import { auth } from '../../../src/routes/auth'
import { user } from '../../../src/routes/user'
import { admin } from '../../../src/routes/admin'
import { system } from '../../../src/routes/system'
import { adminSecurityRoutes } from '../../../src/routes/admin-security'
import emailHandler from '../../../src/handlers/email'
import scheduledHandler from '../../../src/handlers/scheduled'
import { initDebugMode } from '../../../src/utils/debug'
import { initializeSystemSettings, getSystemConfig } from '../../../src/services/settings'

import type { Env, ExecutionContext, ScheduledEvent } from '../../../src/types'

// 创建 Hono 应用
const app = new Hono<{ Bindings: Env }>()

// 全局 CORS 配置
app.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
}))

// 全局错误处理
app.onError((err: any, c: any) => {
    console.error('全局错误处理:', err)

    if (err instanceof HTTPException) {
        return err.getResponse()
    }

    return c.json({
        success: false,
        error: '服务器内部错误'
    }, 500)
})

// 404 处理
app.notFound((c: any) => {
    // 对于 SPA，所有未匹配的路由都返回 index.html
    if (c.req.path.startsWith('/api/')) {
        return c.json({
            success: false,
            error: '接口不存在'
        }, 404)
    }
    
    // 返回 Vue 应用的 index.html
    return c.html(getIndexHTML())
})

// 注册 API 路由模块
app.route('/api', auth)           // 认证相关: /api/register, /api/login, /api/logout
app.route('/api/protected', user) // 用户功能: /api/protected/...
app.route('/api/admin', admin)    // 管理员功能: /api/admin/...
app.route('/api/admin/security', adminSecurityRoutes) // 管理员安全功能: /api/admin/security/...
app.route('/api/system', system)  // 系统配置: /api/system/...

// 调试接口（仅在调试模式下启用）
app.get('/api/debug', async (c: any) => {
    const config = await getSystemConfig(c.env.DB)

    if (!config.debug_mode && c.env.cem_debug !== 'true') {
        throw new HTTPException(404, { message: '接口不存在' })
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
    })
})

// 模拟邮件接收接口（仅在调试模式下启用）
app.post('/api/debug/simulate-email', async (c: any) => {
    const config = await getSystemConfig(c.env.DB)

    if (!config.debug_mode && c.env.cem_debug !== 'true') {
        throw new HTTPException(404, { message: '接口不存在' })
    }

    try {
        const { to, from, subject, text } = await c.req.json()

        if (!to || !from) {
            return c.json({
                success: false,
                error: '收件人和发件人不能为空'
            }, 400)
        }

        // 构造模拟邮件对象
        const mockMessage = {
            to,
            from,
            headers: new Map([
                ['Subject', subject || '测试邮件'],
                ['Message-ID', `test-${Date.now()}@debug.local`]
            ]),
            text: () => Promise.resolve(text || '这是一封测试邮件'),
            html: () => Promise.resolve(`<p>${text || '这是一封测试邮件'}</p>`),
            raw: () => Promise.resolve(`From: ${from}\nTo: ${to}\nSubject: ${subject || '测试邮件'}\n\n${text || '这是一封测试邮件'}`)
        }

        await emailHandler.email(mockMessage, c.env, {})

        return c.json({
            success: true,
            message: '模拟邮件发送成功'
        })

    } catch (error) {
        console.error('模拟邮件发送失败:', error)
        return c.json({
            success: false,
            error: error instanceof Error ? error.message : '模拟邮件发送失败'
        }, 500)
    }
})

// 主页 - 返回 Vue 应用
app.get('/', async (c: any) => {
    return c.html(getIndexHTML())
})

// favicon.ico 处理
app.get('/favicon.ico', (c: any) => {
    return c.body('', 204)
})

// 静态资源处理 - 对于 SPA，这里可能需要特殊处理
app.get('/assets/*', async (c: any) => {
    // 这里需要根据实际的静态资源处理逻辑来实现
    // 可能需要从 KV 或其他存储中获取静态文件
    return c.text('静态资源不存在', 404)
})

// 获取 Vue 应用的 index.html
function getIndexHTML(): string {
    // 这里应该返回构建后的 Vue 应用的 HTML
    // 在实际部署时，这个内容会被构建工具替换
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="description" content="基于Cloudflare的临时邮箱管理系统 - Vue 3 + TypeScript版本" />
    <title>临时邮箱管理系统</title>
    <!-- 构建时会插入 CSS 和 JS 文件 -->
</head>
<body>
    <div id="app"></div>
    <!-- 构建时会插入 Vue 应用的脚本 -->
</body>
</html>`
}

/**
 * Workers 主要导出对象
 */
export default {
    /**
     * HTTP 请求处理
     */
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        // 初始化调试模式
        initDebugMode(env)

        // 初始化系统设置
        try {
            await initializeSystemSettings(env.DB)
        } catch (error) {
            console.error('初始化系统设置失败:', error)
        }

        return app.fetch(request, env, ctx)
    },

    /**
     * 邮件处理
     */
    async email(message: any, env: Env, ctx: ExecutionContext): Promise<void> {
        initDebugMode(env)
        await emailHandler.email(message, env, ctx)
    },

    /**
     * 定时任务处理
     */
    async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
        initDebugMode(env)
        await scheduledHandler.scheduled(event, env, ctx)
    }
}