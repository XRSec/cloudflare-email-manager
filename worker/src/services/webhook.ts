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
import type { Email, User, ForwardRule, ForwardLog } from '../types';
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
 */
export async function sendWebhook(
    url: string,
    data: any,
    secret?: string,
    type: string = 'custom',
    customMessage?: string
): Promise<{ success: boolean; responseCode?: number; errorMessage?: string }> {
    try {
        let payload: any;
        // 默认 headers，Bark 使用 GET 请求时不需要 Content-Type
        let headers: Record<string, string> = {
            'User-Agent': 'CloudflareTempEmail/1.0'
        };

        // 处理自定义消息：先判断是否是 JSON，再替换变量
        let customPayload: any = null;  // JSON 格式的自定义消息（解析后的对象）
        let customText: string = '';     // 文本格式的自定义消息（替换变量后的字符串）

        if (customMessage) {
            // 先尝试解析为 JSON（不替换变量，保持格式完整）
            try {
                const parsedJson = JSON.parse(customMessage);
                // JSON 解析成功：在对象中递归替换变量
                customPayload = replaceVariablesInObject(parsedJson, data);
            } catch {
                // 不是 JSON：当作普通文本，直接替换变量
                customText = replaceMessageVariables(customMessage, data);
            }
        }

        // 根据webhook类型构造不同的消息格式
        switch (type) {
            case 'dingtalk':
                // 钉钉：使用简单文本消息
                if (customPayload) {
                    // 用户提供了 JSON 格式的自定义消息
                    payload = customPayload;
                } else if (customText) {
                    // 用户提供了文本格式的自定义消息
                    payload = {
                        msgtype: 'text',
                        text: {
                            content: customText
                        }
                    };
                } else {
                    // 使用默认格式
                    payload = {
                        msgtype: 'text',
                        text: {
                            content: `新邮件通知\n发件人: ${data.from_address || ''}\n主题: ${data.subject || '(无主题)'}\n内容: ${data.content?.substring(0, 200) || '(无内容)'}...`
                        }
                    };
                }

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
                // 飞书：支持 JSON 格式（卡片消息）和简单文本（富文本格式）
                if (customPayload) {
                    // 用户提供了 JSON 格式的自定义消息（已替换变量）
                    payload = customPayload;
                } else if (customText) {
                    // 用户提供了文本格式的自定义消息，使用富文本格式发送
                    // title 会自动以蓝色显示，内容支持加粗、斜体等样式
                    payload = {
                        msg_type: 'post',
                        content: {
                            post: {
                                zh_cn: {
                                    title: '📧 新邮件通知',  // title 默认蓝色显示
                                    content: [[{ tag: 'text', text: customText }]]
                                }
                            }
                        }
                    };
                } else {
                    // 使用默认的飞书卡片消息格式
                    const emailContent = data.content || '(无内容)';
                    const contentPreview = emailContent.length > 500
                        ? emailContent.substring(0, 500) + '...'
                        : emailContent;

                    // 转义 JSON 特殊字符
                    const escapeJson = (str: string): string => {
                        return str
                            .replace(/\\/g, '\\\\')
                            .replace(/"/g, '\\"')
                            .replace(/\n/g, '\\n')
                            .replace(/\r/g, '\\r')
                            .replace(/\t/g, '\\t');
                    };

                    // 格式化日期时间
                    const formatDateTime = (dateStr: string | null | undefined): string => {
                        if (!dateStr) {
                            const now = new Date();
                            return now.toLocaleString('zh-CN', {
                                year: 'numeric',
                                month: '2-digit',
                                day: '2-digit',
                                hour: '2-digit',
                                minute: '2-digit',
                                second: '2-digit',
                                hour12: false
                            });
                        }
                        try {
                            const date = new Date(dateStr);
                            return date.toLocaleString('zh-CN', {
                                year: 'numeric',
                                month: '2-digit',
                                day: '2-digit',
                                hour: '2-digit',
                                minute: '2-digit',
                                second: '2-digit',
                                hour12: false
                            });
                        } catch {
                            return dateStr;
                        }
                    };

                    const fromAddress = escapeJson(data.from_address || '未知发件人');
                    const toAddress = escapeJson(data.to_address || '未知收件人');
                    const subject = escapeJson(data.subject || '(无主题)');
                    const content = escapeJson(contentPreview);
                    const receivedAt = escapeJson(formatDateTime(data.received_at));
                    const attachmentInfo = data.attachment_count && data.attachment_count > 0
                        ? `有 ${data.attachment_count} 个附件`
                        : '无附件';

                    payload = {
                        msg_type: 'interactive',
                        card: {
                            header: {
                                template: 'blue',
                                title: {
                                    content: '📧 新邮件通知',
                                    tag: 'plain_text'
                                }
                            },
                            elements: [
                                {
                                    tag: 'div',
                                    fields: [
                                        {
                                            is_short: true,
                                            text: {
                                                tag: 'lark_md',
                                                content: `**🕙接收时间：** ${receivedAt}`
                                            }
                                        },
                                        {
                                            is_short: true,
                                            text: {
                                                tag: 'lark_md',
                                                content: `**📎附件信息：** ${attachmentInfo}`
                                            }
                                        }
                                    ]
                                },
                                {
                                    tag: 'div',
                                    fields: [
                                        {
                                            is_short: true,
                                            text: {
                                                tag: 'lark_md',
                                                content: `**📤发件人：** ${fromAddress}`
                                            }
                                        },
                                        {
                                            is_short: true,
                                            text: {
                                                tag: 'lark_md',
                                                content: `**📥收件人：** ${toAddress}`
                                            }
                                        }
                                    ]
                                },
                                {
                                    tag: 'div',
                                    fields: [
                                        {
                                            is_short: false,
                                            text: {
                                                tag: 'lark_md',
                                                content: `**📝主题：** ${subject}`
                                            }
                                        }
                                    ]
                                },
                                {
                                    tag: 'div',
                                    fields: [
                                        {
                                            is_short: false,
                                            text: {
                                                tag: 'lark_md',
                                                content: `**📄内容预览：**\n${content}`
                                            }
                                        }
                                    ]
                                }
                            ]
                        }
                    };
                }
                break;
            case 'bark':
                // Bark 支持两种请求方式：
                // 1. GET 请求：https://api.day.app/{device_key}/{title}/{body}?sound=xxx&url=xxx
                // 2. POST 请求：https://api.day.app/push 或 https://api.day.app/{device_key}，body 为 JSON
                // 如果提供了完整的 JSON payload（包含 device_key），使用 POST；否则使用 GET

                let title: string;
                let body: string;
                let barkParams: Record<string, any> = {};
                let usePost = false; // 是否使用 POST 请求

                if (customText) {
                    // 用户提供了文本格式的自定义消息，需要解析标题和内容
                    const lines = customText.split('\n');
                    title = lines[0] || `新邮件: ${data.subject || '(无主题)'}`;
                    body = lines.slice(1).join('\n') || customText;
                } else {
                    // 使用默认格式
                    title = `新邮件: ${data.subject || '(无主题)'}`;
                    body = `发件人: ${data.from_address || ''}\n收件人: ${data.to_address || ''}\n\n${data.content?.substring(0, 500) || '(无内容)'}`;
                }

                // 如果用户提供了 JSON 格式的自定义消息
                if (customPayload) {
                    // 检查是否包含 device_key，如果包含则使用 POST
                    if (customPayload.device_key) {
                        usePost = true;
                        // 构建 POST 请求的 payload
                        payload = {
                            device_key: customPayload.device_key,
                            title: customPayload.title || title,
                            body: customPayload.body || body,
                            sound: customPayload.sound || 'default',
                            url: customPayload.url || '',
                            icon: customPayload.icon || '',
                            group: customPayload.group || '邮件通知',
                            badge: customPayload.badge || 1
                        };
                        // 如果 URL 是 /push 端点，使用它；否则使用 device_key 构建 URL
                        if (url.includes('/push')) {
                            // 使用 /push 端点
                        } else {
                            // 使用 device_key 构建 URL
                            url = `https://api.day.app/${customPayload.device_key}`;
                        }
                    } else {
                        // 没有 device_key，使用 GET 方式，从 URL 中提取 device_key
                        if (customPayload.title) title = customPayload.title;
                        if (customPayload.body) body = customPayload.body;
                        if (customPayload.sound) barkParams.sound = customPayload.sound;
                        if (customPayload.url) barkParams.url = customPayload.url;
                        if (customPayload.icon) barkParams.icon = customPayload.icon;
                        if (customPayload.group) barkParams.group = customPayload.group;
                        if (customPayload.badge) barkParams.badge = customPayload.badge.toString();
                    }
                } else {
                    // 默认参数（GET 方式）
                    barkParams.group = '邮件通知';
                    barkParams.badge = '1';
                    barkParams.sound = 'default';
                }

                // 如果使用 GET 请求
                if (!usePost) {
                    // 构建 Bark URL
                    // Bark URL 格式：https://api.day.app/{device_key}/{title}/{body}?sound=xxx&url=xxx
                    // 支持多种 URL 格式：
                    // 1. https://api.day.app/{device_key}/
                    // 2. https://api.day.app/{device_key}
                    // 3. https://api.day.app/{device_key}/?sound=xxx
                    const urlMatch = url.match(/^https?:\/\/api\.day\.app\/([^\/\?]+)/);
                    if (urlMatch) {
                        const deviceKey = urlMatch[1];
                        // URL 编码标题和内容
                        const encodedTitle = encodeURIComponent(title);
                        const encodedBody = encodeURIComponent(body);
                        // 构建完整 URL
                        let barkUrl = `https://api.day.app/${deviceKey}/${encodedTitle}/${encodedBody}`;
                        // 添加查询参数
                        const queryParams = new URLSearchParams();
                        Object.entries(barkParams).forEach(([key, value]) => {
                            if (value) {
                                queryParams.append(key, value.toString());
                            }
                        });
                        if (queryParams.toString()) {
                            barkUrl += '?' + queryParams.toString();
                        }
                        url = barkUrl;
                        // Bark 使用 GET 请求，不需要 payload
                        payload = null;
                    } else {
                        // URL 格式不正确，抛出错误提示用户
                        throw new Error(`Bark URL 格式不正确，应为：https://api.day.app/{device_key}/ 或 https://api.day.app/push，当前 URL：${url}`);
                    }
                }
                break;
            default:
                // Custom 类型：如果有自定义消息，使用自定义消息；否则发送原始数据
                if (customPayload) {
                    // 用户提供了 JSON 格式的自定义消息
                    payload = customPayload;
                } else if (customText) {
                    // 用户提供了文本格式的自定义消息
                    payload = { message: customText };
                } else {
                    // 使用原始邮件数据
                    payload = data;
                }
                break;
        }

        // 添加 Content-Type 头（仅用于 POST 请求）
        // Bark 如果使用 POST 也需要 Content-Type
        const isBarkPost = type === 'bark' && payload !== null;
        if (type !== 'bark' || isBarkPost) {
            headers['Content-Type'] = 'application/json';
        }

        // 添加签名验证（仅用于非钉钉、非 Bark 的 webhook）
        // 钉钉的加签已经在上面处理了，Bark 使用 GET 请求不需要签名
        if (secret && type !== 'dingtalk' && type !== 'bark') {
            const timestamp = Math.floor(Date.now() / 1000).toString();
            const signString = timestamp + JSON.stringify(payload);
            const signature = await signJWT(signString, secret);
            headers['X-Timestamp'] = timestamp;
            headers['X-Signature'] = signature;
        }

        // 确定请求方法
        // Bark: 如果 payload 不为 null，使用 POST；否则使用 GET
        // 其他类型：使用 POST
        const method = (type === 'bark' && payload === null) ? 'GET' : 'POST';
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
 * 邮件过滤函数 - 检查邮件是否匹配转发规则
 */
/**
 * 验证邮箱地址格式（必须包含域名）
 */
function isValidEmailFormat(value: string): boolean {
    // 简单的邮箱格式验证：必须包含 @ 符号和域名
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(value);
}

export function matchForwardRule(email: Email, rule: ForwardRule): boolean {
    const isExactMatch = rule.exact_match === 1;

    // 检查发件人过滤器（支持多个条件，用逗号分隔，满足任一条件即可）
    if (rule.sender_filter) {
        const senderEmail = (email.from_address || '').toLowerCase();
        // 将过滤条件按逗号分割，去除空白
        const filters = rule.sender_filter.split(',').map(f => f.trim().toLowerCase()).filter(f => f);

        // 如果启用精确匹配，验证格式并精确匹配
        if (isExactMatch) {
            // 精确匹配：必须携带完整域名，使用 === 匹配
            const matched = filters.some(filter => {
                // 验证过滤条件必须是有效的邮箱格式
                if (!isValidEmailFormat(filter)) {
                    return false;
                }
                return senderEmail === filter;
            });
            if (!matched) {
                return false;
            }
        } else {
            // 包含匹配：使用 includes
            const matched = filters.some(filter => senderEmail.includes(filter));
            if (!matched) {
                return false;
            }
        }
    }

    // 检查收件人过滤器（支持多个条件，用逗号分隔，满足任一条件即可）
    if (rule.recipient_filter) {
        const recipientEmail = (email.to_address || '').toLowerCase();
        // 将过滤条件按逗号分割，去除空白
        const filters = rule.recipient_filter.split(',').map(f => f.trim().toLowerCase()).filter(f => f);

        // 如果启用精确匹配，验证格式并精确匹配
        if (isExactMatch) {
            // 精确匹配：必须携带完整域名，使用 === 匹配
            const matched = filters.some(filter => {
                // 验证过滤条件必须是有效的邮箱格式
                if (!isValidEmailFormat(filter)) {
                    return false;
                }
                return recipientEmail === filter;
            });
            if (!matched) {
                return false;
            }
        } else {
            // 包含匹配：使用 includes
            const matched = filters.some(filter => recipientEmail.includes(filter));
            if (!matched) {
                return false;
            }
        }
    }

    // 检查关键字过滤器
    if (rule.keyword_filter) {
        const keyword = rule.keyword_filter.toLowerCase();
        const subject = (email.subject || '').toLowerCase();
        const content = (email.content || '').toLowerCase();
        if (!subject.includes(keyword) && !content.includes(keyword)) {
            return false;
        }
    }

    return true;
}

/**
 * 处理邮件转发
 */
export async function handleEmailForwarding(email: Email, userId: number | null, db: D1Database): Promise<void> {
    try {
        // 1. 先检查全局转发规则，找出所有匹配的规则
        const rulesResult = await retryD1Operation('查询转发规则', async () => {
            return await db.prepare(`
                SELECT id, rule_name, sender_filter, keyword_filter, recipient_filter, exact_match, skip_default_webhook, enabled
                FROM forward_rules
                WHERE enabled = 1
            `).all();
        });

        const rules = rulesResult.results as unknown as ForwardRule[];

        // 找出所有匹配的规则
        const matchedRules: ForwardRule[] = [];
        for (const rule of rules) {
            if (matchForwardRule(email, rule)) {
                matchedRules.push(rule);
            }
        }

        // 2. 决定是否发送默认 webhook
        // 如果所有匹配的规则都设置了 skip_default_webhook，则不发送默认 webhook
        // 3. 如果未跳过默认推送，且配置了默认 webhook，则发送
        const allSkipDefault = matchedRules.length > 0 && matchedRules.every(rule => rule.skip_default_webhook === 1);

        if (!allSkipDefault) {
            // 确定要查询的用户ID
            let targetUserId = userId;

            // 如果邮件没有关联用户，查找管理员用户作为默认
            if (targetUserId === null) {
                const adminUser = await db.prepare(`
                    SELECT id FROM users WHERE user_type = 1 LIMIT 1
                `).first();
                if (adminUser) {
                    targetUserId = (adminUser as any).id;
                }
            }

            // 使用用户ID查询 webhook 配置
            if (targetUserId !== null) {
                const userWebhook = await db.prepare(`
                    SELECT webhook_url, webhook_secret, webhook_type, webhook_custom_message 
                    FROM users 
                    WHERE id = ?
                `).bind(targetUserId).first();

                if (userWebhook && (userWebhook as any).webhook_url) {
                    const webhook = userWebhook as any;
                    const { debugLog } = await import('../utils/debug');
                    debugLog('Webhook', `发送默认 webhook (用户ID: ${targetUserId}, 类型: ${webhook.webhook_type || 'custom'}): ${webhook.webhook_url}`);
                    const result = await sendWebhook(
                        webhook.webhook_url,
                        email,
                        webhook.webhook_secret || undefined,
                        webhook.webhook_type || 'custom',
                        webhook.webhook_custom_message || undefined
                    );

                    // 记录转发日志（rule_id 为 null 表示默认 webhook）
                    await logForwardResult(db, email.id, null, webhook.webhook_url, result);
                }
            }
        }

        // 4. 处理匹配的规则
        for (const rule of matchedRules) {
            const { debugLog } = await import('../utils/debug');
            debugLog('转发规则', `邮件匹配转发规则: ${rule.rule_name}`);

            // 获取该规则的所有 webhook 配置
            const webhooksResult = await retryD1Operation(`查询规则 ${rule.rule_name} 的 webhook`, async () => {
                return await db.prepare(`
                    SELECT id, webhook_url, webhook_secret, webhook_type, custom_message, enabled
                    FROM forward_rule_webhooks
                    WHERE rule_id = ? AND enabled = 1
                `).bind(rule.id).all();
            });

            const webhooks = webhooksResult.results as any[];

            // 发送到该规则的所有 webhook
            for (const webhook of webhooks) {
                const result = await sendWebhook(
                    webhook.webhook_url,
                    email,
                    webhook.webhook_secret || undefined,
                    webhook.webhook_type || 'custom',
                    webhook.custom_message || undefined
                );

                // 记录转发日志
                await logForwardResult(db, email.id, rule.id, webhook.webhook_url, result);
            }
        }
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('转发规则', '处理邮件转发失败:', error);
    }
}

/**
 * 记录转发日志
 */
async function logForwardResult(
    db: D1Database,
    emailId: string,
    ruleId: number | null,
    webhookUrl: string,
    result: { success: boolean; responseCode?: number; errorMessage?: string }
): Promise<void> {
    try {
        await retryD1Operation('记录转发日志', async () => {
            return await db.prepare(`
                INSERT INTO forward_logs (
                    email_id, rule_id, webhook_url, status, response_code, error_message,
                    sent_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            `).bind(
                emailId,
                ruleId,
                webhookUrl,
                result.success ? WEBHOOK_STATUS.SUCCESS : WEBHOOK_STATUS.FAILED,
                result.responseCode || null,
                result.errorMessage || null
            ).run();
        });
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('转发规则', '记录转发日志失败:', error);
    }
}

/**
 * 获取转发规则列表
 */
export async function getForwardRules(db: D1Database, paginationParams?: { page: number; limit: number }): Promise<ForwardRule[]> {
    const result = await db.prepare(`
        SELECT id, rule_name, sender_filter, keyword_filter, recipient_filter,
               exact_match, skip_default_webhook, enabled,
               created_at, updated_at
        FROM forward_rules
        ORDER BY created_at DESC
    `).all();

    const rules: ForwardRule[] = result.results.map(row => ({
        id: row.id as number,
        rule_name: row.rule_name as string,
        sender_filter: row.sender_filter as string | undefined,
        keyword_filter: row.keyword_filter as string | undefined,
        recipient_filter: row.recipient_filter as string | undefined,
        exact_match: row.exact_match as number | undefined,
        skip_default_webhook: row.skip_default_webhook as number | undefined,
        enabled: row.enabled as number,
        created_at: row.created_at as string | undefined,
        updated_at: row.updated_at as string | undefined,
        webhooks: [] // 初始化为空数组
    }));

    // 为每个规则加载关联的 webhooks
    for (const rule of rules) {
        const webhooksResult = await db.prepare(`
            SELECT id, rule_id, webhook_url, webhook_secret, webhook_type, custom_message, enabled,
                   created_at, updated_at
            FROM forward_rule_webhooks
            WHERE rule_id = ?
            ORDER BY created_at ASC
        `).bind(rule.id).all();

        rule.webhooks = webhooksResult.results.map(wh => ({
            id: wh.id as number,
            rule_id: wh.rule_id as number,
            webhook_url: wh.webhook_url as string,
            webhook_secret: wh.webhook_secret as string | undefined,
            webhook_type: wh.webhook_type as 'dingtalk' | 'feishu' | 'bark' | 'custom',
            custom_message: wh.custom_message as string | undefined,
            enabled: wh.enabled as number,
            created_at: wh.created_at as string | undefined,
            updated_at: wh.updated_at as string | undefined,
        }));
    }

    return rules;
}

/**
 * 获取单个转发规则
 */
export async function getForwardRuleById(db: D1Database, id: number): Promise<ForwardRule | null> {
    const result = await db.prepare(`
        SELECT id, rule_name, sender_filter, keyword_filter, recipient_filter,
               exact_match, skip_default_webhook, enabled,
               created_at, updated_at
        FROM forward_rules
        WHERE id = ?
    `).bind(id).first();

    if (!result) {
        return null;
    }

    // 加载关联的 webhooks
    const webhooksResult = await db.prepare(`
        SELECT id, rule_id, webhook_url, webhook_secret, webhook_type, custom_message, enabled,
               created_at, updated_at
        FROM forward_rule_webhooks
        WHERE rule_id = ?
        ORDER BY created_at ASC
    `).bind(id).all();

    return {
        id: result.id as number,
        rule_name: result.rule_name as string,
        sender_filter: result.sender_filter as string | undefined,
        keyword_filter: result.keyword_filter as string | undefined,
        recipient_filter: result.recipient_filter as string | undefined,
        exact_match: result.exact_match as number | undefined,
        skip_default_webhook: result.skip_default_webhook as number | undefined,
        enabled: result.enabled as number,
        created_at: result.created_at as string | undefined,
        updated_at: result.updated_at as string | undefined,
        webhooks: webhooksResult.results.map(wh => ({
            id: wh.id as number,
            rule_id: wh.rule_id as number,
            webhook_url: wh.webhook_url as string,
            webhook_secret: wh.webhook_secret as string | undefined,
            webhook_type: wh.webhook_type as 'dingtalk' | 'feishu' | 'bark' | 'custom',
            custom_message: wh.custom_message as string | undefined,
            enabled: wh.enabled as number,
            created_at: wh.created_at as string | undefined,
            updated_at: wh.updated_at as string | undefined,
        })),
    };
}

/**
 * 创建转发规则
 */
export async function createForwardRule(
    db: D1Database,
    rule: Omit<ForwardRule, 'id' | 'created_at' | 'updated_at'>
): Promise<ForwardRule> {
    const result = await db.prepare(`
        INSERT INTO forward_rules (
            rule_name, sender_filter, keyword_filter, recipient_filter,
            exact_match, skip_default_webhook, enabled,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).bind(
        rule.rule_name,
        rule.sender_filter || null,
        rule.keyword_filter || null,
        rule.recipient_filter || null,
        rule.exact_match || 0,
        rule.skip_default_webhook || 0,
        rule.enabled
    ).run();

    if (!result.success) {
        throw new Error('Failed to create forward rule');
    }

    const ruleId = result.meta.last_row_id;

    // 如果有 webhooks 配置，创建它们
    if (rule.webhooks && rule.webhooks.length > 0) {
        for (const webhook of rule.webhooks) {
            await db.prepare(`
                INSERT INTO forward_rule_webhooks (
                    rule_id, webhook_url, webhook_secret, webhook_type, custom_message, enabled,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            `).bind(
                ruleId,
                webhook.webhook_url,
                webhook.webhook_secret || null,
                webhook.webhook_type || 'custom',
                webhook.custom_message || null,
                webhook.enabled !== undefined ? webhook.enabled : 1
            ).run();
        }
    }

    // 返回创建的规则（包含 webhooks）
    return await getForwardRuleById(db, ruleId) || (() => {
        throw new Error('Failed to retrieve created rule');
    })();
}

/**
 * 更新转发规则
 */
export async function updateForwardRule(
    db: D1Database,
    id: number,
    updates: Partial<Omit<ForwardRule, 'id' | 'created_at' | 'updated_at'>>
): Promise<void> {
    const setParts: string[] = [];
    const values: any[] = [];

    if (updates.rule_name !== undefined) {
        setParts.push('rule_name = ?');
        values.push(updates.rule_name);
    }

    if (updates.sender_filter !== undefined) {
        setParts.push('sender_filter = ?');
        values.push(updates.sender_filter || null);
    }

    if (updates.keyword_filter !== undefined) {
        setParts.push('keyword_filter = ?');
        values.push(updates.keyword_filter || null);
    }

    if (updates.recipient_filter !== undefined) {
        setParts.push('recipient_filter = ?');
        values.push(updates.recipient_filter || null);
    }

    if (updates.exact_match !== undefined) {
        setParts.push('exact_match = ?');
        values.push(updates.exact_match || 0);
    }

    if (updates.skip_default_webhook !== undefined) {
        setParts.push('skip_default_webhook = ?');
        values.push(updates.skip_default_webhook);
    }

    if (updates.enabled !== undefined) {
        setParts.push('enabled = ?');
        values.push(updates.enabled);
    }

    // 更新规则基本信息
    if (setParts.length > 0) {
        setParts.push('updated_at = CURRENT_TIMESTAMP');
        values.push(id);

        const sql = `UPDATE forward_rules SET ${setParts.join(', ')} WHERE id = ?`;
        const result = await db.prepare(sql).bind(...values).run();

        if (!result.success) {
            throw new Error('Failed to update forward rule');
        }
    }

    // 如果提供了 webhooks，更新它们
    if (updates.webhooks !== undefined) {
        // 先删除所有现有的 webhooks
        await db.prepare(`
            DELETE FROM forward_rule_webhooks WHERE rule_id = ?
        `).bind(id).run();

        // 然后插入新的 webhooks
        if (updates.webhooks.length > 0) {
            for (const webhook of updates.webhooks) {
                await db.prepare(`
                    INSERT INTO forward_rule_webhooks (
                        rule_id, webhook_url, webhook_secret, webhook_type, custom_message, enabled,
                        created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                `).bind(
                    id,
                    webhook.webhook_url,
                    webhook.webhook_secret || null,
                    webhook.webhook_type || 'custom',
                    webhook.custom_message || null,
                    webhook.enabled !== undefined ? webhook.enabled : 1
                ).run();
            }
        }
    }
}

/**
 * 删除转发规则
 */
export async function deleteForwardRule(db: D1Database, id: number): Promise<void> {
    // 由于外键约束，删除规则时会自动删除关联的 webhooks
    const result = await db.prepare(`
        DELETE FROM forward_rules WHERE id = ?
    `).bind(id).run();

    if (!result.success) {
        throw new Error('Failed to delete forward rule');
    }
}

/**
 * 添加转发规则的 Webhook
 */
export async function addForwardRuleWebhook(
    db: D1Database,
    ruleId: number,
    webhook: Omit<import('../types').ForwardRuleWebhook, 'id' | 'rule_id' | 'created_at' | 'updated_at'>
): Promise<import('../types').ForwardRuleWebhook> {
    const result = await db.prepare(`
                    INSERT INTO forward_rule_webhooks (
                        rule_id, webhook_url, webhook_secret, webhook_type, custom_message, enabled,
                        created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                `).bind(
        ruleId,
        webhook.webhook_url,
        webhook.webhook_secret || null,
        webhook.webhook_type || 'custom',
        webhook.custom_message || null,
        webhook.enabled !== undefined ? webhook.enabled : 1
    ).run();

    if (!result.success) {
        throw new Error('Failed to add forward rule webhook');
    }

    const created = await db.prepare(`
        SELECT id, rule_id, webhook_url, webhook_secret, webhook_type, enabled,
               created_at, updated_at
        FROM forward_rule_webhooks
        WHERE id = ?
    `).bind(result.meta.last_row_id).first();

    if (!created) {
        throw new Error('Failed to retrieve created webhook');
    }

    return {
        id: created.id as number,
        rule_id: created.rule_id as number,
        webhook_url: created.webhook_url as string,
        webhook_secret: created.webhook_secret as string | undefined,
        webhook_type: created.webhook_type as 'dingtalk' | 'feishu' | 'bark' | 'custom',
        enabled: created.enabled as number,
        created_at: created.created_at as string | undefined,
        updated_at: created.updated_at as string | undefined,
    };
}

/**
 * 更新转发规则的 Webhook
 */
export async function updateForwardRuleWebhook(
    db: D1Database,
    webhookId: number,
    updates: Partial<Omit<import('../types').ForwardRuleWebhook, 'id' | 'rule_id' | 'created_at' | 'updated_at'>>
): Promise<void> {
    const setParts: string[] = [];
    const values: any[] = [];

    if (updates.webhook_url !== undefined) {
        setParts.push('webhook_url = ?');
        values.push(updates.webhook_url);
    }

    if (updates.webhook_secret !== undefined) {
        setParts.push('webhook_secret = ?');
        values.push(updates.webhook_secret || null);
    }

    if (updates.webhook_type !== undefined) {
        setParts.push('webhook_type = ?');
        values.push(updates.webhook_type);
    }

    if (updates.enabled !== undefined) {
        setParts.push('enabled = ?');
        values.push(updates.enabled);
    }

    if (setParts.length === 0) {
        return;
    }

    setParts.push('updated_at = CURRENT_TIMESTAMP');
    values.push(webhookId);

    const sql = `UPDATE forward_rule_webhooks SET ${setParts.join(', ')} WHERE id = ?`;
    const result = await db.prepare(sql).bind(...values).run();

    if (!result.success) {
        throw new Error('Failed to update forward rule webhook');
    }
}

/**
 * 删除转发规则的 Webhook
 */
export async function deleteForwardRuleWebhook(db: D1Database, webhookId: number): Promise<void> {
    const result = await db.prepare(`
        DELETE FROM forward_rule_webhooks WHERE id = ?
    `).bind(webhookId).run();

    if (!result.success) {
        throw new Error('Failed to delete forward rule webhook');
    }
}

