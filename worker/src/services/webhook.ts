/**
 * Webhook 服务
 * 
 * 支持的 Webhook 类型：
 * 1. dingtalk - 钉钉机器人
 *    - 请求方式：POST + JSON
 *    - URL 格式：https://oapi.dingtalk.com/robot/send?access_token=xxx
 *    - 如果设置了加签，需要在 secret 字段填入加签密钥，会自动在 URL 中添加 timestamp 和 sign 参数
 *    - 支持自定义消息模板，变量：{{from}}, {{to}}, {{subject}}, {{content}}, {{received_at}}, {{attachment_count}}
 *    - 支持多种消息类型：text, markdown, link, actionCard 等
 *    - JSON 示例：{"msgtype":"text","text":{"content":"{{subject}}\n{{content}}"}}
 *    - 参考文档：https://open.dingtalk.com/document/group/custom-robot-access
 * 
 * 2. feishu - 飞书机器人
 *    - 自定义消息示例：{"msg_type":"interactive","card":{"header":{"template":"blue","title":{"content":"📧 新邮件通知","tag":"plain_text"}},"elements":[{"tag":"div","fields":[{"is_short":true,"text":{"tag":"lark_md","content":"**发件人：**{{from}}"}},{"is_short":true,"text":{"tag":"lark_md","content":"**收件人：**{{to}}"}},{"is_short":true,"text":{"tag":"lark_md","content":"**主题：**{{subject}}"}},{"is_short":true,"text":{"tag":"lark_md","content":"**附件数：**{{attachment_count}}"}}]},{"tag":"div","text":{"tag":"lark_md","content":"**内容：**\n{{content}}"}}]}}
 * 
 * 3. bark - Bark 推送（iOS 设备）
 *    - 支持两种请求方式：
 *      a) GET 请求：https://api.day.app/{device_key}/{title}/{body}?sound=xxx&url=xxx
 *      b) POST 请求：https://api.day.app/push 或 https://api.day.app/{device_key}，body 为 JSON
 *    - 如果 JSON 自定义消息中包含 device_key，自动使用 POST 方式
 *    - 支持自定义消息模板，变量：{{from}}, {{to}}, {{subject}}, {{content}}, {{received_at}}, {{attachment_count}}
 *    - GET 方式 JSON 示例：{"title":"{{subject}}","body":"{{content}}","sound":"default","group":"邮件通知","badge":1}
 *    - POST 方式 JSON 示例：{"device_key":"xxx","title":"{{subject}}","body":"{{content}}","sound":"default","group":"邮件通知","badge":1}
 * 
 * 4. custom - 自定义 Webhook
 *    - 支持任意格式的 POST 请求
 *    - 支持自定义消息模板
 */

import { signJWT } from '../utils/crypto';
import { retryD1Operation } from '../utils/retry';
import type { Email, ForwardLog } from '../types';
import type { D1Database } from '@cloudflare/workers-types';
import { WEBHOOK_STATUS } from '../shared/constants';

/**
 * 钉钉加签算法
 * 参考：https://open.dingtalk.com/document/robots/custom-robot-access
 */
async function generateDingTalkSign(secret: string, timestamp: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const signString = timestamp + '\n' + secret;
    const dataToSign = encoder.encode(signString);

    const key = await crypto.subtle.importKey(
        'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, dataToSign);
    const uint8Array = new Uint8Array(signature);
    return btoa(String.fromCharCode.apply(null, Array.from(uint8Array)));
}

/**
 * 替换消息模板中的变量（字符串版本）
 * 支持的变量：{{from}}, {{to}}, {{subject}}, {{content}}, {{received_at}}, {{attachment_count}}
 */
function replaceMessageVariables(template: string, email: Email): string {
    let result = template;

    // 替换基础变量
    result = result.replace(/\{\{from\}\}/g, email.from_address || '');
    result = result.replace(/\{\{to\}\}/g, email.to_address || '');
    result = result.replace(/\{\{subject\}\}/g, email.subject || '(无主题)');
    result = result.replace(/\{\{content\}\}/g, email.content || '(无内容)');
    result = result.replace(/\{\{received_at\}\}/g, email.received_at || '');

    // 替换附件数量变量
    const attachmentCount = email.attachment_count || 0;
    result = result.replace(/\{\{attachment_count\}\}/g, attachmentCount.toString());

    return result;
}

/**
 * 在 JSON 对象中递归替换变量
 * 避免先替换字符串再解析 JSON 导致的格式破坏问题
 */
function replaceVariablesInObject(obj: any, email: Email): any {
    if (typeof obj === 'string') {
        // 字符串：直接替换变量
        return replaceMessageVariables(obj, email);
    } else if (Array.isArray(obj)) {
        // 数组：递归处理每个元素
        return obj.map(item => replaceVariablesInObject(item, email));
    } else if (obj !== null && typeof obj === 'object') {
        // 对象：递归处理每个属性
        const result: any = {};
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                result[key] = replaceVariablesInObject(obj[key], email);
            }
        }
        return result;
    } else {
        // 其他类型（数字、布尔等）：直接返回
        return obj;
    }
}

/**
 * 发送 Webhook
 * 只支持飞书、钉钉、Bark，固定消息格式：你有一封来自 xxx 的邮件
 */
export async function sendWebhook(
    url: string,
    email: Email,
    secret?: string,
    type: 'dingtalk' | 'feishu' | 'bark' = 'dingtalk'
): Promise<{ success: boolean; responseCode?: number; errorMessage?: string }> {
    try {
        // 固定消息格式：你有一封来自 xxx 的邮件
        const fromAddress = email.from_address || '未知发件人';
        const message = `你有一封来自 ${fromAddress} 的邮件`;

        let payload: any;
        let headers: Record<string, string> = {
            'User-Agent': 'CloudflareTempEmail/1.0'
        };
        let method: string = 'POST';

        // 根据webhook类型构造不同的消息格式
        switch (type) {
            case 'dingtalk':
                // 钉钉：使用简单文本消息
                payload = {
                    msgtype: 'text',
                    text: {
                        content: message
                    }
                };
                headers['Content-Type'] = 'application/json';

                // 钉钉加签：如果提供了 secret，需要在 URL 中添加 timestamp 和 sign 参数
                if (secret) {
                    const timestamp = Math.floor(Date.now() / 1000).toString();
                    const sign = await generateDingTalkSign(secret, timestamp);
                    const urlObj = new URL(url);
                    urlObj.searchParams.set('timestamp', timestamp);
                    urlObj.searchParams.set('sign', sign);
                    url = urlObj.toString();
                }
                break;
            case 'feishu':
                // 飞书：使用简单文本消息
                payload = {
                    msg_type: 'text',
                    content: {
                        text: message
                    }
                };
                headers['Content-Type'] = 'application/json';
                break;
            case 'bark':
                // Bark：使用 GET 请求
                // URL 格式：https://api.day.app/{device_key}/{title}/{body}?sound=xxx
                const urlMatch = url.match(/^https?:\/\/api\.day\.app\/([^\/\?]+)/);
                if (urlMatch) {
                    const deviceKey = urlMatch[1];
                    const encodedTitle = encodeURIComponent('新邮件通知');
                    const encodedBody = encodeURIComponent(message);
                    url = `https://api.day.app/${deviceKey}/${encodedTitle}/${encodedBody}?sound=default`;
                    method = 'GET';
                    payload = null;
                } else {
                    throw new Error(`Bark URL 格式不正确，应为：https://api.day.app/{device_key}/，当前 URL：${url}`);
                }
                break;
            default:
                throw new Error(`不支持的 webhook 类型: ${type}`);
        }

        const fetchOptions: RequestInit = {
            method,
            headers
        };

        // POST 请求需要 body，GET 请求不需要
        if (method === 'POST' && payload !== null) {
            fetchOptions.body = JSON.stringify(payload);
        }

        const response = await fetch(url, fetchOptions);

        return {
            success: response.ok,
            responseCode: response.status,
            errorMessage: response.ok ? undefined : `HTTP ${response.status}: ${response.statusText}`
        };
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('Webhook', '发送失败:', error);
        return {
            success: false,
            errorMessage: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}

/**
 * 处理邮件转发
 * 只发送默认webhook（从system_settings读取）
 */
export async function handleEmailForwarding(email: Email, userId: number | null, db: D1Database): Promise<void> {
    try {
        // 从系统设置读取默认webhook配置
        const { getSystemSetting } = await import('../services/settings');
        const webhookUrl = await getSystemSetting(db, 'default_webhook_url');
        const webhookSecret = await getSystemSetting(db, 'default_webhook_secret');
        const webhookType = await getSystemSetting(db, 'default_webhook_type') as 'dingtalk' | 'feishu' | 'bark' | undefined;

        // 如果没有配置webhook URL，则不发送
        if (!webhookUrl || !webhookType) {
            const { debugLog } = await import('../utils/debug');
            debugLog('Webhook', '未配置默认webhook，跳过发送');
            return;
        }

        // 验证webhook类型
        if (!['dingtalk', 'feishu', 'bark'].includes(webhookType)) {
            const { errorLog } = await import('../utils/debug');
            errorLog('Webhook', `不支持的webhook类型: ${webhookType}`);
            return;
        }

        const { debugLog } = await import('../utils/debug');
        debugLog('Webhook', `发送默认 webhook (类型: ${webhookType}): ${webhookUrl}`);

        const result = await sendWebhook(
            webhookUrl,
            email,
            webhookSecret || undefined,
            webhookType
        );

        // 记录转发日志
        await logForwardResult(db, email.id, webhookUrl, result);
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('Webhook', '处理邮件转发失败:', error);
    }
}

/**
 * 记录转发日志
 */
async function logForwardResult(
    db: D1Database,
    emailId: string,
    webhookUrl: string,
    result: { success: boolean; responseCode?: number; errorMessage?: string }
): Promise<void> {
    try {
        await retryD1Operation('记录转发日志', async () => {
            return await db.prepare(`
                INSERT INTO forward_logs (
                    email_id, webhook_url, status, response_code, error_message,
                    sent_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            `).bind(
                emailId,
                webhookUrl,
                result.success ? WEBHOOK_STATUS.SUCCESS : WEBHOOK_STATUS.FAILED,
                result.responseCode || null,
                result.errorMessage || null
            ).run();
        });
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('Webhook', '记录转发日志失败:', error);
    }
}


