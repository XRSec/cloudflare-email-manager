/**
 * 测试邮件处理端点
 * 用于本地测试，模拟邮件接收流程
 */

import { Hono } from 'hono';
import { handleIncomingEmail } from '../handlers/email';
import { debugLog, errorLog } from '../utils/debug';
import type { Env } from '../types';

const testEmailRoutes = new Hono<{ Bindings: Env }>();

/**
 * POST /api/test/process-email
 * 
 * 测试邮件处理流程
 * 
 * Body 参数:
 * - rawEmail: string (base64 编码的 .eml 文件内容)
 * - from: string (发件人邮箱)
 * - to: string (收件人邮箱)
 * 
 * 或者直接传递 .eml 文件内容（text/plain）
 */
testEmailRoutes.post('/process-email', async (c) => {
  try {
    debugLog('[测试] 开始处理测试邮件...');

    let rawEmail: string;
    let fromAddress: string;
    let toAddress: string;

    const contentType = c.req.header('content-type') || '';

    if (contentType.includes('application/json')) {
      // JSON 格式
      const body = await c.req.json();

      if (body.rawEmail) {
        // base64 编码的邮件
        const binaryString = atob(body.rawEmail);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        rawEmail = new TextDecoder('utf-8').decode(bytes);
      } else if (body.emlContent) {
        // 直接的邮件内容
        rawEmail = body.emlContent;
      } else {
        return c.json({
          success: false,
          error: '缺少邮件内容（rawEmail 或 emlContent）'
        }, 400);
      }

      fromAddress = body.from || 'test@example.com';
      toAddress = body.to || 'k@doubi.tech';
    } else {
      // 纯文本格式（.eml 内容）
      rawEmail = await c.req.text();
      fromAddress = 'test@example.com';
      toAddress = 'k@doubi.tech';
    }

    debugLog('[测试] 邮件大小:', rawEmail.length, 'bytes');
    debugLog('[测试] From:', fromAddress);
    debugLog('[测试] To:', toAddress);

    // 模拟 Cloudflare Email Worker 的 message 对象
    const mockMessage = {
      from: fromAddress,
      to: toAddress,
      mailFrom: fromAddress,
      rcptTo: toAddress,

      // 提供原始邮件数据
      raw: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(rawEmail));
          controller.close();
        }
      }),

      // 提供 headers
      headers: new Map<string, string>(),

      // 提供辅助方法
      async text() {
        // 从原始邮件中提取纯文本（简化版）
        const textMatch = rawEmail.match(/Content-Type: text\/plain[\s\S]*?\r?\n\r?\n([\s\S]*?)(?=\r?\n--)/);
        return textMatch ? textMatch[1] : '';
      },

      async html() {
        // 从原始邮件中提取 HTML（简化版）
        const htmlMatch = rawEmail.match(/Content-Type: text\/html[\s\S]*?\r?\n\r?\n([\s\S]*?)(?=\r?\n--)/);
        return htmlMatch ? htmlMatch[1] : '';
      }
    };

    // 调用邮件处理函数
    await handleIncomingEmail(mockMessage, c.env, null);

    debugLog('[测试] 邮件处理完成！');

    return c.json({
      success: true,
      message: '邮件处理成功',
      details: {
        from: fromAddress,
        to: toAddress,
        size: rawEmail.length
      }
    });

  } catch (error) {
    errorLog('[测试] 邮件处理失败:', error);

    return c.json({
      success: false,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    }, 500);
  }
});

/**
 * GET /api/test/process-email-file?filename=xxx.eml
 * 
 * 从根目录读取 .eml 文件并处理
 * 
 * Query 参数:
 * - filename: string (根目录的 .eml 文件名)
 * - from: string (可选，发件人邮箱)
 * - to: string (可选，收件人邮箱)
 */
testEmailRoutes.get('/process-email-file', async (c) => {
  try {
    const filename = c.req.query('filename');

    if (!filename) {
      return c.json({
        success: false,
        error: '缺少 filename 参数'
      }, 400);
    }

    debugLog('[测试] 请求处理文件:', filename);

    return c.json({
      success: false,
      error: '此端点需要通过外部脚本调用，Worker 无法直接读取本地文件系统',
      tip: '请使用 test-process-email.js 脚本'
    }, 400);

  } catch (error) {
    errorLog('[测试] 处理失败:', error);

    return c.json({
      success: false,
      error: error instanceof Error ? error.message : String(error)
    }, 500);
  }
});

/**
 * GET /api/test/info
 * 
 * 获取测试环境信息
 */
testEmailRoutes.get('/info', async (c) => {
  return c.json({
    success: true,
    environment: 'test',
    endpoints: {
      processEmail: 'POST /api/test/process-email',
      processEmailFile: 'GET /api/test/process-email-file?filename=xxx.eml'
    },
    usage: {
      curl: 'curl -X POST http://localhost:8787/api/test/process-email -H "Content-Type: text/plain" --data-binary @email.eml',
      node: 'node test-process-email.js email.eml'
    }
  });
});

export default testEmailRoutes;

