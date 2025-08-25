/**
 * 主入口文件 - 简洁的临时邮箱系统
 * 基于Cloudflare Workers + D1 + R2构建
 * 
 * 功能特性：
 * - 邮件接收和存储
 * - 附件支持（最大50MB）
 * - Webhook转发（钉钉、飞书、自定义）
 * - 用户管理和权限控制
 * - 自动清理系统
 * - 安全防护机制
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { jwt } from 'hono/jwt';
import { HTTPException } from 'hono/http-exception';

// 导入各个模块
import { SecurityManager, InputValidator, RequestLogger } from './security';
import { WebhookManager } from './webhook';
import { CleanupManager, CleanupScheduler } from './cleanup';
import { EmailProcessor } from './email-processor';
import { setupApiRoutes } from './api-routes';
import { serveStaticFiles } from './static-handler';

// 环境变量接口
interface Env {
  // Cloudflare 绑定
  DB: D1Database;
  R2: R2Bucket;
  KV: KVNamespace;
  
  // 基础配置
  DOMAIN: string;
  JWT_SECRET: string;
  FRONTEND_URL: string;
  
  // 功能开关
  ALLOW_REGISTRATION: string;
  CLEANUP_DAYS: string;
  MAX_ATTACHMENT_SIZE: string;
  
  // 安全配置
  MAX_REQUESTS_PER_MINUTE: string;
  MAX_LOGIN_ATTEMPTS: string;
  ENABLE_IP_WHITELIST: string;
  IP_WHITELIST?: string;
  
  // Webhook配置
  DINGTALK_SECRET?: string;
  FEISHU_SECRET?: string;
}

// 全局变量类型扩展
interface Variables {
  user?: any;
  requestStartTime: number;
}

// 创建Hono应用
const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// ============= 中间件设置 =============

// CORS中间件
app.use('*', cors({
  origin: (origin) => {
    // 允许同域名和配置的前端URL
    return true; // 在生产环境中应该更严格地检查origin
  },
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// 请求开始时间记录
app.use('*', async (c, next) => {
  c.set('requestStartTime', Date.now());
  await next();
});

// 安全中间件
app.use('/api/*', async (c, next) => {
  const securityManager = new SecurityManager(c.env.KV, {
    maxRequestsPerMinute: parseInt(c.env.MAX_REQUESTS_PER_MINUTE || '60'),
    maxLoginAttempts: parseInt(c.env.MAX_LOGIN_ATTEMPTS || '5'),
    enableIPWhitelist: c.env.ENABLE_IP_WHITELIST === 'true',
    ipWhitelist: c.env.IP_WHITELIST ? c.env.IP_WHITELIST.split(',') : [],
  });
  
  await securityManager.rateLimitMiddleware(c, next);
  await securityManager.ipWhitelistMiddleware(c, next);
});

// JWT认证中间件（仅对受保护的路由）
app.use('/api/protected/*', jwt({
  secret: (c) => c.env.JWT_SECRET,
  cookie: 'auth-token', // 也支持cookie认证
}));

app.use('/api/admin/*', jwt({
  secret: (c) => c.env.JWT_SECRET,
}));

// 管理员权限检查
app.use('/api/admin/*', async (c, next) => {
  const payload = c.get('jwtPayload') as any;
  if (!payload || payload.user_type !== 'admin') {
    throw new HTTPException(403, { message: '需要管理员权限' });
  }
  await next();
});

// 请求日志中间件
app.use('*', async (c, next) => {
  await next();
  
  const logger = new RequestLogger(c.env.KV);
  const startTime = c.get('requestStartTime');
  await logger.logRequest(c, startTime);
});

// ============= 路由设置 =============

// API路由
setupApiRoutes(app);

// 静态文件服务
app.get('*', serveStaticFiles);

// 错误处理
app.onError((err, c) => {
  console.error('应用错误:', err);
  
  if (err instanceof HTTPException) {
    return err.getResponse();
  }
  
  return c.json({
    success: false,
    message: '服务器内部错误',
    error: err.message
  }, 500);
});

// 404处理
app.notFound((c) => {
  if (c.req.path.startsWith('/api/')) {
    return c.json({
      success: false,
      message: 'API端点不存在'
    }, 404);
  }
  
  // 对于非API请求，返回主页
  return c.redirect('/');
});

// ============= Worker事件处理器 =============

export default {
  /**
   * HTTP请求处理
   */
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return app.fetch(request, env, ctx);
  },

  /**
   * 邮件接收处理
   */
  async email(message: ForwardableEmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
    try {
      console.log('收到新邮件:', {
        from: message.from,
        to: message.to,
        subject: message.headers.get('Subject'),
        messageId: message.headers.get('Message-ID')
      });

      const emailProcessor = new EmailProcessor(env.DB, env.R2, env.DOMAIN);
      const webhookManager = new WebhookManager(env.DB);
      
      // 处理邮件
      const result = await emailProcessor.processIncomingEmail(message);
      
      if (result.success && result.emailData) {
        // 发送Webhook通知
        await webhookManager.handleEmailReceived(result.emailData, result.userId!);
        
        console.log('邮件处理完成:', {
          emailId: result.emailData.id,
          userId: result.userId,
          attachmentCount: result.emailData.attachmentCount
        });
      } else {
        console.warn('邮件处理失败:', result.error);
      }

    } catch (error) {
      console.error('邮件处理异常:', error);
      
      // 记录错误但不抛出，避免影响邮件路由
      const securityManager = new SecurityManager(env.KV);
      await securityManager.logSecurityEvent({
        type: 'email_processing_error',
        ip: 'system',
        details: {
          error: error instanceof Error ? error.message : '未知错误',
          from: message.from,
          to: message.to
        }
      });
    }
  },

  /**
   * 定时任务处理
   */
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    try {
      console.log('开始执行定时任务:', event.cron);

      const cleanupManager = new CleanupManager(env.DB, env.R2, {
        emailRetentionDays: parseInt(env.CLEANUP_DAYS || '7'),
      });
      
      const cleanupScheduler = new CleanupScheduler(cleanupManager);
      
      // 检查是否需要执行清理
      if (cleanupScheduler.shouldRunCleanup(event.cron)) {
        const stats = await cleanupScheduler.handleScheduledEvent(event.cron);
        
        console.log('定时清理完成:', stats);
        
        // 如果有错误，记录到安全日志
        if (stats.errors.length > 0) {
          const securityManager = new SecurityManager(env.KV);
          await securityManager.logSecurityEvent({
            type: 'cleanup_errors',
            ip: 'system',
            details: {
              errors: stats.errors,
              stats: stats
            }
          });
        }
      }

    } catch (error) {
      console.error('定时任务执行失败:', error);
      
      // 记录错误
      const securityManager = new SecurityManager(env.KV);
      await securityManager.logSecurityEvent({
        type: 'scheduled_task_error',
        ip: 'system',
        details: {
          error: error instanceof Error ? error.message : '未知错误',
          cron: event.cron
        }
      });
    }
  },

  /**
   * 队列消息处理（可选，用于处理大量邮件）
   */
  async queue(batch: MessageBatch<any>, env: Env, ctx: ExecutionContext): Promise<void> {
    try {
      console.log('处理队列消息:', batch.messages.length);

      // 这里可以实现批量邮件处理逻辑
      for (const message of batch.messages) {
        try {
          // 处理单个消息
          await this.processQueueMessage(message, env);
          
          // 确认消息处理完成
          message.ack();
          
        } catch (error) {
          console.error('队列消息处理失败:', error);
          
          // 重试逻辑
          if (message.attempts < 3) {
            message.retry();
          } else {
            message.ack(); // 放弃重试
          }
        }
      }

    } catch (error) {
      console.error('队列批处理失败:', error);
    }
  },

  /**
   * 处理单个队列消息
   */
  async processQueueMessage(message: Message<any>, env: Env): Promise<void> {
    // 实现具体的消息处理逻辑
    console.log('处理队列消息:', message.id);
  }
};

// ============= 辅助函数 =============

/**
 * 生成随机字符串
 */
export function generateRandomString(length: number = 8): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  return result;
}

/**
 * 验证环境配置
 */
export function validateEnvironment(env: Env): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!env.DOMAIN) {
    errors.push('缺少必需的环境变量: DOMAIN');
  }
  
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) {
    errors.push('JWT_SECRET必须至少32个字符');
  }
  
  if (!env.DB) {
    errors.push('缺少D1数据库绑定');
  }
  
  if (!env.R2) {
    errors.push('缺少R2存储绑定');
  }
  
  if (!env.KV) {
    errors.push('缺少KV存储绑定');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

// 导出类型供其他文件使用
export type { Env, Variables };