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
import { createEmail, saveRawEmailToR2, sendEmail } from './email';
import { getSystemConfig } from './settings';
import { bumpChangeSignals } from './changeSignals';
import { KVCacheService } from './kvCache';
import type { Email, Env, ForwardLog, D1Database } from '../types';
import { WEBHOOK_STATUS } from '../shared/constants';

type NotificationChannel = {
    id: number;
    name: string;
    type: 'dingtalk' | 'feishu' | 'bark';
    url: string;
    secret?: string;
    enabled: boolean;
};

type NotificationRoutingRule = {
    id: number;
    enabled: boolean;
    matchMode: 'all' | 'any';
    senderPattern: string;
    recipientPattern: string;
    subjectPattern: string;
    contentPattern: string;
    targetChannelIds: number[];
    isDefault: boolean;
    defaultMode: 'always' | 'unmatched';
};

type IncomingRoutingRule = {
    id: number;
    enabled: boolean;
    matchMode: 'all' | 'any';
    senderPattern: string;
    recipientPattern: string;
    subjectPattern: string;
    contentPattern: string;
    targetEmail: string;
    targetFromAddress: string;
    targetForwardType: 'internal' | 'smtp' | 'cf';
    isDefault: boolean;
    defaultMode: 'always' | 'unmatched';
};

type WebhookDebug = {
    request: {
        url: string;
        method: string;
        headers: Record<string, string>;
        body: string | null;
    };
    response?: {
        status: number;
        statusText: string;
        headers: Record<string, string>;
        body: string;
    };
};

export type WebhookResult = {
    success: boolean;
    responseCode?: number;
    errorMessage?: string;
    debug?: WebhookDebug;
};

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
 * 飞书自定义机器人签名算法
 * stringToSign = timestamp + "\n" + secret
 * sign = base64(hmac_sha256("", stringToSign))
 */
async function generateFeishuSign(secret: string, timestamp: string): Promise<string> {
    const encoder = new TextEncoder();
    const stringToSign = `${timestamp}\n${secret}`;
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(stringToSign),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, new Uint8Array());
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
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

function truncateText(value: string | null | undefined, maxLength = 800): string {
    const text = (value || '').trim();
    if (text.length <= maxLength) {
        return text;
    }
    return `${text.slice(0, maxLength)}...`;
}

function buildFeishuEmailCard(email: Email) {
    const subject = email.subject || '(无主题)';
    const fromAddress = email.from_address || '未知发件人';
    const toAddress = email.to_address || '未知收件人';
    const receivedAt = email.received_at || '-';
    const attachmentCount = email.attachment_count || 0;
    const content = truncateText(email.content || '(无内容)');

    return {
        msg_type: 'interactive',
        card: {
            header: {
                template: 'blue',
                title: {
                    content: `新邮件通知：${subject}`,
                    tag: 'plain_text'
                }
            },
            elements: [
                {
                    tag: 'div',
                    fields: [
                        {
                            is_short: true,
                            text: { tag: 'lark_md', content: `**发件人：** ${fromAddress}` }
                        },
                        {
                            is_short: true,
                            text: { tag: 'lark_md', content: `**收件人：** ${toAddress}` }
                        }
                    ]
                },
                {
                    tag: 'div',
                    fields: [
                        {
                            is_short: true,
                            text: { tag: 'lark_md', content: `**接收时间：** ${receivedAt}` }
                        },
                        {
                            is_short: true,
                            text: { tag: 'lark_md', content: `**附件数：** ${attachmentCount}` }
                        }
                    ]
                },
                {
                    tag: 'div',
                    text: {
                        tag: 'lark_md',
                        content: `**主题：** ${subject}`
                    }
                },
                {
                    tag: 'div',
                    text: {
                        tag: 'lark_md',
                        content: `**内容摘要：**\n${content}`
                    }
                }
            ]
        }
    };
}

function getWebhookBusinessError(type: 'dingtalk' | 'feishu' | 'bark', responseBody: string): string | null {
    if (!responseBody.trim()) {
        return null;
    }

    try {
        const parsed = JSON.parse(responseBody);
        if (type === 'feishu') {
            const code = Number(parsed.code ?? parsed.StatusCode ?? 0);
            if (code !== 0) {
                return responseBody;
            }
        }
        if (type === 'dingtalk') {
            const errcode = Number(parsed.errcode ?? 0);
            if (errcode !== 0) {
                return responseBody;
            }
        }
        if (type === 'bark') {
            const code = Number(parsed.code ?? 200);
            if (code !== 200) {
                return responseBody;
            }
        }
    } catch {
        return null;
    }

    return null;
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
): Promise<WebhookResult> {
    let debugRequest: WebhookDebug['request'] | undefined;
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
                // 飞书：使用结构化消息卡片
                payload = buildFeishuEmailCard(email);
                if (secret) {
                    const timestamp = Math.floor(Date.now() / 1000).toString();
                    payload.timestamp = timestamp;
                    payload.sign = await generateFeishuSign(secret, timestamp);
                }
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

        debugRequest = {
            url,
            method,
            headers,
            body: typeof fetchOptions.body === 'string' ? fetchOptions.body : null
        };

        const response = await fetch(url, fetchOptions);
        const responseBody = await response.text().catch(() => '');
        const responseHeaders: Record<string, string> = {};
        response.headers.forEach((value, key) => {
            responseHeaders[key] = value;
        });
        const businessError = response.ok ? getWebhookBusinessError(type, responseBody) : null;
        const success = response.ok && !businessError;

        return {
            success,
            responseCode: response.status,
            errorMessage: success ? undefined : (businessError || `HTTP ${response.status}: ${response.statusText}`),
            debug: {
                request: debugRequest,
                response: {
                    status: response.status,
                    statusText: response.statusText,
                    headers: responseHeaders,
                    body: responseBody
                }
            }
        };
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('Webhook', '发送失败:', error);
        return {
            success: false,
            errorMessage: error instanceof Error ? error.message : 'Unknown error',
            ...(debugRequest ? { debug: { request: debugRequest } } : {})
        };
    }
}

/**
 * 处理邮件转发
 * 根据 routing_rules 中的通知通道和通知规则发送 webhook
 */
export async function handleEmailForwarding(email: Email, userId: number | null, db: D1Database, env?: Env): Promise<void> {
    try {
        const channels = await loadNotificationChannels(db);

        if (channels.length === 0) {
            const { debugLog } = await import('../utils/debug');
            debugLog('Webhook', '未配置通知通道，跳过发送');
        } else {
            const rules = await loadNotificationRules(db);
            const defaultRule = rules.find((rule) => rule.isDefault && rule.enabled);
            const matchedChannelIds = new Set<number>();

            rules
                .filter((rule) => !rule.isDefault && rule.enabled && matchesRoutingRule(email, rule))
                .flatMap((rule) => rule.targetChannelIds)
                .forEach((channelId) => matchedChannelIds.add(channelId));

            if (defaultRule) {
                const shouldUseDefault = defaultRule.defaultMode === 'always' || matchedChannelIds.size === 0;
                if (shouldUseDefault) {
                    defaultRule.targetChannelIds.forEach((channelId) => matchedChannelIds.add(channelId));
                }
            }

            const targetChannels = channels.filter((channel) => matchedChannelIds.has(channel.id));
            if (targetChannels.length === 0) {
                const { debugLog } = await import('../utils/debug');
                debugLog('Webhook', '没有命中的通知通道，跳过发送');
            } else {
                const { debugLog } = await import('../utils/debug');
                debugLog('Webhook', `发送 ${targetChannels.length} 个通知通道`);

                for (const channel of targetChannels) {
                    const result = await sendWebhook(
                        channel.url,
                        email,
                        channel.secret || undefined,
                        channel.type
                    );
                    await logForwardResult(db, email.id, channel.url, result, env?.KV);
                }
            }
        }

        if (env) {
            await handleIncomingForwarding(email, db, env);
        }
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('Webhook', '处理邮件转发失败:', error);
    }
}

async function loadNotificationRules(db: D1Database): Promise<NotificationRoutingRule[]> {
    const result = await db.prepare(`
        SELECT
            id,
            enabled,
            match_mode,
            sender_pattern,
            recipient_pattern,
            subject_pattern,
            content_pattern,
            target_channel_ids,
            is_default,
            default_mode
        FROM routing_rules
        WHERE category = 'notification'
    `).all();

    return (result.results || []).map((row: any) => ({
        id: Number(row.id),
        enabled: row.enabled === 1,
        matchMode: row.match_mode === 'any' ? 'any' : 'all',
        senderPattern: row.sender_pattern || '',
        recipientPattern: row.recipient_pattern || '',
        subjectPattern: row.subject_pattern || '',
        contentPattern: row.content_pattern || '',
        targetChannelIds: parseChannelIds(row.target_channel_ids),
        isDefault: row.is_default === 1,
        defaultMode: row.default_mode === 'always' ? 'always' : 'unmatched'
    }));
}

async function loadNotificationChannels(db: D1Database): Promise<NotificationChannel[]> {
    const result = await db.prepare(`
        SELECT id, name, enabled, channel_type, channel_url, channel_secret
        FROM routing_rules
        WHERE category = 'channel'
    `).all();

    return (result.results || [])
        .map((row: any) => ({
            id: Number(row.id),
            name: row.name || '',
            enabled: row.enabled === 1,
            type: row.channel_type === 'feishu' || row.channel_type === 'bark' ? row.channel_type : 'dingtalk',
            url: row.channel_url || '',
            secret: row.channel_secret || ''
        }))
        .filter((channel) => channel.enabled && channel.url);
}

function parseChannelIds(value: unknown): number[] {
    if (typeof value !== 'string') return [];

    try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed)
            ? parsed.map((item) => Number(item)).filter((item) => Number.isInteger(item))
            : [];
    } catch {
        return [];
    }
}

function matchesRoutingRule(
    email: Email,
    rule: Pick<IncomingRoutingRule | NotificationRoutingRule, 'matchMode' | 'senderPattern' | 'recipientPattern' | 'subjectPattern' | 'contentPattern'>
): boolean {
    const checks = [
        !rule.senderPattern || (email.from_address || '').toLowerCase().includes(rule.senderPattern.toLowerCase()),
        !rule.recipientPattern || (email.to_address || '').toLowerCase().includes(rule.recipientPattern.toLowerCase()),
        !rule.subjectPattern || (email.subject || '').toLowerCase().includes(rule.subjectPattern.toLowerCase()),
        !rule.contentPattern || (email.content || '').toLowerCase().includes(rule.contentPattern.toLowerCase())
    ];

    return rule.matchMode === 'all' ? checks.every(Boolean) : checks.some(Boolean);
}

async function loadIncomingRules(db: D1Database): Promise<IncomingRoutingRule[]> {
    const result = await db.prepare(`
        SELECT
            id,
            enabled,
            match_mode,
            sender_pattern,
            recipient_pattern,
            subject_pattern,
            content_pattern,
            target_email,
            target_from_address,
            target_forward_type,
            is_default,
            default_mode
        FROM routing_rules
        WHERE category = 'incoming'
    `).all();

    return (result.results || []).map((row: any) => ({
        id: Number(row.id),
        enabled: row.enabled === 1,
        matchMode: row.match_mode === 'any' ? 'any' : 'all',
        senderPattern: row.sender_pattern || '',
        recipientPattern: row.recipient_pattern || '',
        subjectPattern: row.subject_pattern || '',
        contentPattern: row.content_pattern || '',
        targetEmail: row.target_email || '',
        targetFromAddress: row.target_from_address || '',
        targetForwardType: row.target_forward_type === 'smtp' || row.target_forward_type === 'cf' ? row.target_forward_type : 'internal',
        isDefault: row.is_default === 1,
        defaultMode: row.default_mode === 'always' ? 'always' : 'unmatched'
    }));
}

function isSystemForwardedEmail(email: Email): boolean {
    if (!email.headers_json) return false;

    try {
        const headers = JSON.parse(email.headers_json);
        return headers['x-cem-forwarded'] === '1' || headers['X-CEM-Forwarded'] === '1';
    } catch {
        return false;
    }
}

async function handleIncomingForwarding(email: Email, db: D1Database, env: Env): Promise<void> {
    if (isSystemForwardedEmail(email)) {
        const { debugLog } = await import('../utils/debug');
        debugLog('Webhook', '系统转发邮件跳过收件转发，避免循环');
        return;
    }

    const rules = await loadIncomingRules(db);
    const defaultRule = rules.find((rule) => rule.isDefault && rule.enabled);
    const matchedRules = rules.filter((rule) => !rule.isDefault && rule.enabled && rule.targetEmail && matchesRoutingRule(email, rule));
    const targetRules = [...matchedRules];

    if (defaultRule?.targetEmail) {
        const shouldUseDefault = defaultRule.defaultMode === 'always' || targetRules.length === 0;
        if (shouldUseDefault) {
            targetRules.push(defaultRule);
        }
    }

    for (const rule of targetRules) {
        await forwardEmailByRule(email, rule, db, env);
    }
}

async function forwardEmailByRule(email: Email, rule: IncomingRoutingRule, db: D1Database, env: Env): Promise<void> {
    const targetEmail = rule.targetEmail.trim().toLowerCase();
    const targetDomain = targetEmail.split('@').pop() || '';
    const fromAddress = email.from_address || `unknown@${targetDomain}`;
    const targetFromAddress = rule.targetFromAddress.trim();
    const originalReplyTo = email.reply_to || email.from_address || undefined;
    const forwardedBy = 'cloudflare-email-manager';
    const forwardSubject = `Fwd: ${email.subject || '(无主题)'}`;
    const forwardContent = [
        `转发邮件（由系统转发）`,
        ``,
        `转发系统: ${forwardedBy}`,
        `转发规则: ${rule.id}`,
        `原发件人: ${email.from_address || '-'}`,
        `原收件人: ${email.to_address || '-'}`,
        `原主题: ${email.subject || '(无主题)'}`,
        `接收时间: ${email.received_at || '-'}`,
        ``,
        email.content || ''
    ].join('\n');

    try {
        if (rule.targetForwardType === 'internal') {
            const config = await getSystemConfig(db);
            const localDomains = Array.isArray(config.supported_emails) ? config.supported_emails : [];
            if (!localDomains.includes(targetDomain)) {
                throw new Error('站内转发目标域名不在系统配置中');
            }

            const forwardedEmailId = crypto.randomUUID();
            const now = new Date().toISOString();
            const messageId = `<forward-${forwardedEmailId}@${targetDomain}>`;
            const rawEmail = [
                `From: ${fromAddress}`,
                `To: ${targetEmail}`,
                `Subject: ${forwardSubject}`,
                `Date: ${new Date().toUTCString()}`,
                `Message-ID: ${messageId}`,
                `X-CEM-Forwarded: 1`,
                `X-CEM-Forwarded-By: ${forwardedBy}`,
                `X-CEM-Forward-Rule-ID: ${rule.id}`,
                `X-CEM-Original-From: ${email.from_address || ''}`,
                `X-CEM-Original-To: ${email.to_address || ''}`,
                `MIME-Version: 1.0`,
                `Content-Type: text/plain; charset=UTF-8`,
                `Content-Transfer-Encoding: 8bit`,
                ``,
                forwardContent
            ].join('\r\n');

            const forwardedEmail = await createEmail(db, {
                subject: forwardSubject,
                from_address: fromAddress,
                to_address: targetEmail,
                content: forwardContent.slice(0, 1000),
                is_read: 0,
                attachment_count: 0,
                message_id: messageId,
                headers_json: JSON.stringify({
                    from: fromAddress,
                    to: targetEmail,
                    subject: forwardSubject,
                    date: now,
                    'message-id': messageId,
                    'x-cem-forwarded': '1',
                    'x-cem-forwarded-by': forwardedBy,
                    'x-cem-forward-rule-id': String(rule.id),
                    'x-cem-original-from': email.from_address || '',
                    'x-cem-original-to': email.to_address || ''
                }),
                size_bytes: new TextEncoder().encode(rawEmail).byteLength,
                date: now,
                reply_to: email.reply_to || email.from_address,
                cc: null,
                bcc: null,
                content_type: 'text/plain; charset=UTF-8',
                received_at: now
            }, forwardedEmailId);

            if (env.R2) {
                await saveRawEmailToR2(env.R2, rawEmail, messageId, forwardedEmail.id, fromAddress, targetEmail);
            }

            await logForwardResult(db, email.id, `mailto:${targetEmail}`, {
                success: true,
                responseCode: 200
            }, env.KV, { from: fromAddress, to: targetEmail });
            return;
        }

        if (rule.targetForwardType === 'cf' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(targetFromAddress)) {
            throw new Error('CF 转发发件人邮箱格式无效');
        }

        await sendEmail(env, {
            to: targetEmail,
            from: targetFromAddress,
            reply_to: originalReplyTo,
            subject: forwardSubject,
            content: forwardContent,
            content_type: 'text',
            delivery_method: rule.targetForwardType
        });

        await logForwardResult(db, email.id, `mailto:${targetEmail}`, {
            success: true,
            responseCode: 200
        }, env.KV, { from: targetFromAddress, to: targetEmail });
    } catch (error) {
        const message = error instanceof Error ? error.message : '收件转发失败';
        await logForwardResult(db, email.id, `mailto:${targetEmail}`, {
            success: false,
            errorMessage: message
        }, env.KV, { from: targetFromAddress || null, to: targetEmail });
    }
}

/**
 * 记录转发日志
 */
export async function logForwardResult(
    db: D1Database,
    emailId: string,
    webhookUrl: string,
    result: { success: boolean; responseCode?: number; errorMessage?: string },
    kv?: any,
    delivery?: { from?: string | null; to?: string | null }
): Promise<void> {
    try {
        await ensureForwardLogDeliveryColumns(db);
        await retryD1Operation('记录转发日志', async () => {
            return await db.prepare(`
                INSERT INTO forward_logs (
                    email_id, webhook_url, status, response_code, error_message,
                    delivery_from_address, delivery_to_address,
                    sent_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            `).bind(
                emailId,
                webhookUrl,
                result.success ? WEBHOOK_STATUS.SUCCESS : WEBHOOK_STATUS.FAILED,
                result.responseCode || null,
                result.errorMessage || null,
                delivery?.from || null,
                delivery?.to || null
            ).run();
        });
        await bumpChangeSignals(db, ['forward_logs', 'dashboard']);
        if (kv) {
            await new KVCacheService(kv).clearDashboardCache();
        }
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('Webhook', '记录转发日志失败:', error);
    }
}

let forwardLogDeliveryColumnsReady = false;

export async function ensureForwardLogDeliveryColumns(db: D1Database): Promise<void> {
    if (forwardLogDeliveryColumnsReady) {
        return;
    }

    for (const statement of [
        'ALTER TABLE forward_logs ADD COLUMN delivery_from_address TEXT',
        'ALTER TABLE forward_logs ADD COLUMN delivery_to_address TEXT'
    ]) {
        try {
            await db.prepare(statement).run();
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            if (!message.toLowerCase().includes('duplicate column')) {
                throw error;
            }
        }
    }

    forwardLogDeliveryColumnsReady = true;
}
