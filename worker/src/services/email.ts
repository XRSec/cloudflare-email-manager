/**
 * 邮件服务
 */

import type { D1Database, R2Bucket } from '@cloudflare/workers-types';
import type { Email, Attachment, EmailQueryParams, Env } from '../types';
import { getSystemSetting } from './settings';
import { retryR2Operation, retryD1Operation } from '../utils/retry';
import PostalMime from 'postal-mime';

function getAddressDomain(address?: string): string {
    const normalized = (address || '').trim().toLowerCase();
    const match = normalized.match(/@([^>\s]+)>?$/);
    return (match?.[1] || '').replace(/^@+/, '');
}

async function getResendTokenForAddress(db: D1Database, from?: string): Promise<string> {
    const domain = getAddressDomain(from);
    if (!domain) {
        throw new Error('使用 Resend 发信时必须提供有效发件人地址');
    }

    const channel = await db.prepare(`
        SELECT channel_secret
        FROM routing_rules
        WHERE category = 'mail_channel'
          AND channel_type = 'resend'
          AND channel_url = ?
        LIMIT 1
    `).bind(domain).first();
    const token = typeof channel?.channel_secret === 'string' ? channel.channel_secret.trim() : '';
    if (!token) {
        throw new Error(`邮件通道未配置 ${domain} 的 Resend API Key`);
    }

    return token;
}

async function sendViaResend(db: D1Database, emailData: {
    to: string;
    from?: string;
    subject: string;
    content: string;
    content_type: 'text' | 'html';
    reply_to?: string;
}): Promise<{ messageId?: string }> {
    const token = await getResendTokenForAddress(db, emailData.from);
    const isHtml = emailData.content_type === 'html';
    const payload = {
        from: emailData.from,
        to: [emailData.to],
        subject: emailData.subject,
        ...(emailData.reply_to ? { reply_to: emailData.reply_to } : {}),
        ...(isHtml ? { html: emailData.content } : { text: emailData.content })
    };

    const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    });

    const responseText = await response.text();
    let responseBody: any = {};
    try {
        responseBody = responseText ? JSON.parse(responseText) : {};
    } catch {
        responseBody = { message: responseText };
    }

    if (!response.ok) {
        throw new Error(responseBody?.message || responseBody?.error || `Resend 投递失败：${response.status}`);
    }

    return { messageId: responseBody?.id };
}

function removeHiddenHtmlContent(html: string): string {
    return html
        .replace(/<([a-z][\w:-]*)(?=[^>]*\bdata-skip-in-text\s*=\s*["']?true["']?)[^>]*>[\s\S]*?<\/\1>/gi, '')
        .replace(/<([a-z][\w:-]*)(?=[^>]*\bhidden\b)[^>]*>[\s\S]*?<\/\1>/gi, '')
        .replace(/<([a-z][\w:-]*)(?=[^>]*\bstyle\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|max-height\s*:\s*0|max-width\s*:\s*0)[^"']*["'])[^>]*>[\s\S]*?<\/\1>/gi, '');
}

/**
 * 从 HTML 中提取纯文本内容
 *
 * @param html HTML 字符串
 * @returns 提取的纯文本内容（Promise）
 *
 * @description
 * 使用 html-to-text 库将 HTML 转换为纯文本
 * 用于在邮件预览中显示纯文本而不是 HTML 标签
 * 如果 html-to-text 转换失败，会回退到简单的正则表达式方法
 */
export async function extractTextFromHtml(html: string): Promise<string> {
    if (!html) {
        return '';
    }

    const visibleHtml = removeHiddenHtmlContent(html);

    try {
        // 动态导入 html-to-text 库
        const { convert } = await import('html-to-text');

        // 使用 html-to-text 转换 HTML 为纯文本
        const text = convert(visibleHtml, {
            // 保留换行符
            preserveNewlines: true,
            // 长单词换行
            longWordSplit: {
                wrapCharacters: [],
                forceWrapOnLimit: false
            },
            // 选择器选项
            selectors: [
                // 忽略 script 和 style 标签
                { selector: 'script', format: 'skip' },
                { selector: 'style', format: 'skip' },
                { selector: '[data-skip-in-text="true"]', format: 'skip' },
                { selector: '[hidden]', format: 'skip' },
                // 处理链接
                { selector: 'a', options: { ignoreHref: false } },
                // 处理图片（显示 alt 文本）
                { selector: 'img', format: 'image', options: { baseUrl: '' } },
                // 处理列表
                { selector: 'ul', format: 'unorderedList' },
                { selector: 'ol', format: 'orderedList' },
                // 处理表格
                { selector: 'table', format: 'dataTable' }
            ],
            // 最大行宽（0 表示不限制）
            wordwrap: 0
        });

        return text.trim();
    } catch (error) {
        const { debugLog } = await import('../utils/debug');
        debugLog('邮件处理', 'html-to-text 转换失败，使用备用方法:', error);
        // 如果 html-to-text 转换失败，使用简单的备用方法
        return extractTextFromHtmlFallback(visibleHtml);
    }
}

export type ForwardedEmailBody = {
    content: string;
    contentType: 'text' | 'html';
    preview: string;
};

type ForwardedEmailMeta = {
    forwardedBy: string;
    ruleId?: number | string;
};

function escapeHtml(value: string): string {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function extractHtmlBodyContent(html: string): string {
    const bodyMatch = html.match(/<body\b[^>]*>([\s\S]*?)<\/body>/i);
    const styleTags = Array.from(html.matchAll(/<style\b[^>]*>[\s\S]*?<\/style>/gi)).map(match => match[0]).join('\n');
    return `${styleTags}${styleTags ? '\n' : ''}${bodyMatch ? bodyMatch[1] : html}`;
}

function buildForwardHeaderLines(email: Email, meta: ForwardedEmailMeta): string[] {
    return [
        '转发邮件（由系统转发）',
        '',
        `转发系统: ${meta.forwardedBy}`,
        ...(meta.ruleId !== undefined ? [`转发规则: ${meta.ruleId}`] : []),
        `原发件人: ${email.from_address || '-'}`,
        `原收件人: ${email.to_address || '-'}`,
        `原主题: ${email.subject || '(无主题)'}`,
        `接收时间: ${email.received_at || '-'}`
    ];
}

function buildForwardHeaderHtml(email: Email, meta: ForwardedEmailMeta): string {
    const rows = buildForwardHeaderLines(email, meta)
        .filter(line => line)
        .map((line) => {
            const [label, ...rest] = line.split(':');
            if (rest.length === 0) {
                return `<div style="font-weight:600;margin-bottom:8px">${escapeHtml(line)}</div>`;
            }
            return `<div><strong>${escapeHtml(label)}:</strong> ${escapeHtml(rest.join(':').trim())}</div>`;
        })
        .join('');

    return [
        '<div style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.6;color:#333;background:#f6f8fa;border:1px solid #d0d7de;border-radius:6px;padding:12px;margin:0 0 16px">',
        rows,
        '</div>'
    ].join('');
}

export async function buildForwardedEmailBody(email: Email, meta: ForwardedEmailMeta, r2?: R2Bucket | any): Promise<ForwardedEmailBody> {
    const headerLines = buildForwardHeaderLines(email, meta);

    if (r2) {
        const rawEmailBytes = await getRawEmailBytesFromR2(r2, email.id);
        if (!rawEmailBytes) {
            throw new Error(`原始邮件不存在：${email.id}`);
        }

        const parser = new PostalMime();
        const parsedEmail = await parser.parse(rawEmailBytes);

        if (parsedEmail.html && parsedEmail.html.trim()) {
            const previewText = await extractTextFromHtml(parsedEmail.html);
            const originalHtml = extractHtmlBodyContent(parsedEmail.html.trim());
            return {
                content: [
                    '<!doctype html>',
                    '<html>',
                    '<body>',
                    buildForwardHeaderHtml(email, meta),
                    '<div style="margin:0;padding:0">',
                    originalHtml,
                    '</div>',
                    '</body>',
                    '</html>'
                ].join(''),
                contentType: 'html',
                preview: [...headerLines, '', previewText || email.content || ''].join('\n').trim()
            };
        }

        if (parsedEmail.text && parsedEmail.text.trim()) {
            const originalText = parsedEmail.text.trim();
            return {
                content: [...headerLines, '', originalText].join('\n'),
                contentType: 'text',
                preview: [...headerLines, '', originalText].join('\n').trim()
            };
        }

        throw new Error(`原始邮件无可转发正文：${email.id}`);
    }

    const fallbackText = (email.content || '').trim();
    return {
        content: [...headerLines, '', fallbackText].join('\n'),
        contentType: 'text',
        preview: [...headerLines, '', fallbackText].join('\n').trim()
    };
}

/**
 * 备用方法：从 HTML 中提取纯文本内容（当 html-to-text 不可用时使用）
 *
 * @param html HTML 字符串
 * @returns 提取的纯文本内容
 */
function extractTextFromHtmlFallback(html: string): string {
    if (!html) {
        return '';
    }

    // 移除 script 和 style 标签及其内容
    let text = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
    text = text.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '');

    // 将常见的 HTML 实体转换为换行或空格
    text = text.replace(/<br\s*\/?>/gi, '\n');
    text = text.replace(/<\/p>/gi, '\n');
    text = text.replace(/<\/div>/gi, '\n');
    text = text.replace(/<\/li>/gi, '\n');
    text = text.replace(/<li[^>]*>/gi, '• ');

    // 移除所有 HTML 标签
    text = text.replace(/<[^>]+>/g, '');

    // 解码 HTML 实体
    text = text.replace(/&nbsp;/g, ' ');
    text = text.replace(/&amp;/g, '&');
    text = text.replace(/&lt;/g, '<');
    text = text.replace(/&gt;/g, '>');
    text = text.replace(/&quot;/g, '"');
    text = text.replace(/&#39;/g, "'");
    text = text.replace(/&apos;/g, "'");

    // 处理其他常见的 HTML 实体（十进制和十六进制）
    text = text.replace(/&#(\d+);/g, (match, dec) => {
        return String.fromCharCode(parseInt(dec, 10));
    });
    text = text.replace(/&#x([0-9A-Fa-f]+);/g, (match, hex) => {
        return String.fromCharCode(parseInt(hex, 16));
    });

    // 清理多余的空白字符
    text = text.replace(/\n\s*\n\s*\n/g, '\n\n'); // 多个连续换行合并为两个
    text = text.replace(/[ \t]+/g, ' '); // 多个空格合并为一个
    text = text.replace(/^\s+|\s+$/gm, ''); // 移除每行首尾空白

    return text.trim();
}

/**
 * 解码 quoted-printable 编码的文本
 *
 * @param text quoted-printable 编码的文本
 * @returns 解码后的文本
 *
 * @example
 * decodeQuotedPrintable('=E5=B9=B4=E6=9C=88=E6=97=A5') // 返回: '年月日'
 */
export function decodeQuotedPrintable(text: string): string {
    if (!text) return text;

    // 移除软换行（行尾的 = 表示软换行）
    let decoded = text.replace(/=\r?\n/g, '');

    // 解码 =XX 格式的十六进制编码
    decoded = decoded.replace(/=([0-9A-Fa-f]{2})/g, (match, hex) => {
        return String.fromCharCode(parseInt(hex, 16));
    });

    // 处理 = 后面不是十六进制的情况（保持原样）
    return decoded;
}

/**
 * 解码邮件内容（处理多种编码方式）
 *
 * @param content 原始内容
 * @param encoding Content-Transfer-Encoding 值（如 'quoted-printable', 'base64', '8bit', '7bit'）
 * @param charset 字符集（如 'UTF-8', 'GB2312'）
 * @returns 解码后的内容
 */
export function decodeEmailContent(content: string, encoding?: string, charset?: string): string {
    if (!content) return content;

    let decoded = content;

    // 处理 Content-Transfer-Encoding
    if (encoding) {
        const enc = encoding.toLowerCase().trim();
        if (enc === 'quoted-printable') {
            decoded = decodeQuotedPrintable(decoded);
        } else if (enc === 'base64') {
            try {
                // Base64 解码
                const binaryString = atob(decoded.replace(/\s/g, ''));
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                // 使用 TextDecoder 解码为字符串
                const decoder = new TextDecoder(charset || 'utf-8');
                decoded = decoder.decode(bytes);
            } catch (error) {
                // Base64 解码失败时静默处理
            }
        }
        // 8bit 和 7bit 不需要特殊处理
    }

    return decoded;
}

/**
 * 从文件名或 Content-Type 中提取文件扩展名
 * 优先使用文件名中的扩展名（更符合用户期望），如果文件名没有扩展名则从 Content-Type 提取
 *
 * @param contentType Content-Type 字符串，如 "image/png" 或 "image/jpeg"
 * @param filename 文件名，如 "image.jpg" 或 "document.pdf"
 * @returns 文件扩展名（不含点号），如 "png"、"jpg"、"pdf"，如果无法确定则返回 "bin"
 */
export function getFileExtension(contentType: string, filename?: string): string {
    // 优先从文件名提取扩展名（文件名是用户或发送方设置的，更直观）
    if (filename) {
        const lastDot = filename.lastIndexOf('.');
        if (lastDot > 0 && lastDot < filename.length - 1) {
            const ext = filename.substring(lastDot + 1).toLowerCase();
            // 移除可能的引号或其他字符
            const cleanExt = ext.replace(/["']/g, '').trim();
            if (cleanExt && cleanExt.length <= 10) { // 扩展名通常不超过10个字符
                return cleanExt;
            }
        }
    }

    // 如果文件名没有扩展名，从 Content-Type 提取
    if (contentType) {
        const mimeToExt: Record<string, string> = {
            'image/png': 'png',
            'image/jpeg': 'jpg',
            'image/jpg': 'jpg',
            'image/gif': 'gif',
            'image/webp': 'webp',
            'image/svg+xml': 'svg',
            'image/bmp': 'bmp',
            'image/tiff': 'tiff',
            'application/pdf': 'pdf',
            'application/msword': 'doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
            'application/vnd.ms-excel': 'xls',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
            'application/vnd.ms-powerpoint': 'ppt',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
            'application/zip': 'zip',
            'application/x-rar-compressed': 'rar',
            'application/x-7z-compressed': '7z',
            'application/x-tar': 'tar',
            'application/gzip': 'gz',
            'text/plain': 'txt',
            'text/html': 'html',
            'text/css': 'css',
            'text/javascript': 'js',
            'text/json': 'json',
            'text/xml': 'xml',
            'application/json': 'json',
            'application/xml': 'xml',
            'video/mp4': 'mp4',
            'video/mpeg': 'mpeg',
            'video/quicktime': 'mov',
            'audio/mpeg': 'mp3',
            'audio/wav': 'wav',
            'audio/ogg': 'ogg',
        };

        const mimeType = contentType.toLowerCase().split(';')[0].trim();
        if (mimeToExt[mimeType]) {
            return mimeToExt[mimeType];
        }
    }

    // 默认返回 bin
    return 'bin';
}

/**
 * 清理 Message-ID 以便作为文件名使用
 *
 * @param messageId 邮件的 Message-ID（可能包含 < > @ 等特殊字符）
 * @returns 清理后的文件名（只包含字母、数字、连字符、下划线）
 *
 * @example
 * sanitizeMessageIdForFilename('<9BE6F42F-3B72-4E5E-83FB-BDE82155880A@icloud.com>')
 * // 返回: '9BE6F42F-3B72-4E5E-83FB-BDE82155880A_icloud.com'
 */
export function sanitizeMessageIdForFilename(messageId: string): string {
    // 移除 < > 等包裹符号
    let cleaned = messageId.replace(/^<|>$/g, '');
    // 替换特殊字符为下划线
    cleaned = cleaned.replace(/[<>@:;,\s\/\\?*|"]/g, '_');
    // 移除连续的下划线
    cleaned = cleaned.replace(/_+/g, '_');
    // 移除开头和结尾的下划线
    cleaned = cleaned.replace(/^_+|_+$/g, '');
    // 限制长度（避免文件名过长）
    if (cleaned.length > 200) {
        cleaned = cleaned.substring(0, 200);
    }
    return cleaned || 'email'; // 如果清理后为空，使用默认值
}

/**
 * 将 emailId 转换为完整的 R2 key
 * @param emailId 邮件ID
 * @returns 完整的 R2 key，格式：email:{emailId}.eml
 */
export function emailIdToR2Key(emailId: string): string {
    return `email:${emailId}.eml`;
}

/**
 * 从 R2 key 中提取 emailId
 * @param r2Key R2 key，格式：email:{emailId}.eml
 * @returns emailId
 */
export function r2KeyToEmailId(r2Key: string): string {
    // 处理格式：email:{id}.eml 或 email:{id}:meta.json
    if (r2Key.startsWith('email:')) {
        const match = r2Key.match(/^email:([^:\.]+)/);
        return match ? match[1] : r2Key;
    }
    return r2Key; // 如果已经是 emailId 格式，直接返回
}

/**
 * 从原始邮件中提取 headers 对象
 */
export function extractHeadersFromRawEmail(rawEmail: string): Record<string, string> {
    const headers: Record<string, string> = {};
    const lines = rawEmail.split(/\r?\n/);
    let i = 0;

    // 解析邮件头（直到遇到空行）
    while (i < lines.length && lines[i].trim()) {
        const line = lines[i];
        const colonIndex = line.indexOf(':');

        if (colonIndex > 0) {
            const key = line.substring(0, colonIndex).trim().toLowerCase();
            let value = line.substring(colonIndex + 1).trim();

            // 处理多行 header（以空格或制表符开头）
            i++;
            while (i < lines.length && (lines[i].startsWith(' ') || lines[i].startsWith('\t'))) {
                value += ' ' + lines[i].trim();
                i++;
            }

            headers[key] = value;
        } else {
            i++;
        }
    }

    return headers;
}

/**
 * 从 MIME 部分中提取 Content-ID
 * @param mimePart MIME 部分内容（包含头部和正文）
 * @returns Content-ID 值（不包含 < > 符号），如果不存在则返回 null
 */
export function extractContentIdFromMimePart(mimePart: string): string | null {
    // 查找 Content-ID 头部
    const contentIdMatch = mimePart.match(/Content-ID:\s*<?([^>\r\n]+)>?/i);
    if (contentIdMatch) {
        // 移除可能的 < > 符号和空白
        return contentIdMatch[1].trim().replace(/^<|>$/g, '');
    }
    return null;
}

/**
 * 从原始邮件中剔除附件，重新构建不包含附件的邮件
 *
 * @param rawEmail 原始邮件内容（RFC 822/MIME 格式）
 * @returns 剔除附件后的邮件内容
 *
 * @description
 * 此函数会：
 * 1. 解析 MIME multipart 结构
 * 2. 识别并移除所有附件部分（Content-Disposition: attachment）
 * 3. 保留文本、HTML 等正文内容
 * 4. 重新构建邮件，更新 Content-Type 头部
 */
export function removeAttachmentsFromRawEmail(rawEmail: string): string {
    if (!rawEmail) {
        return rawEmail;
    }

    // 分离邮件头和正文
    const headerBodySplit = rawEmail.indexOf('\r\n\r\n');
    if (headerBodySplit === -1) {
        // 如果没有找到空行分隔，可能是单部分邮件，直接返回
        return rawEmail;
    }

    const headersText = rawEmail.substring(0, headerBodySplit);
    const bodyText = rawEmail.substring(headerBodySplit + 4);

    // 提取 Content-Type 头部
    const contentTypeMatch = headersText.match(/Content-Type:\s*([^\r\n]+)/i);
    if (!contentTypeMatch) {
        // 没有 Content-Type，可能是简单邮件，直接返回
        return rawEmail;
    }

    const contentType = contentTypeMatch[1].trim();
    const contentTypeLower = contentType.toLowerCase();

    // 如果不是 multipart，直接返回（没有附件）
    if (!contentTypeLower.includes('multipart')) {
        return rawEmail;
    }

    // 提取 boundary
    const boundaryMatch = contentType.match(/boundary="?([^"\s;]+)"?/i);
    if (!boundaryMatch) {
        // 没有 boundary，无法解析，返回原邮件
        return rawEmail;
    }

    const boundary = boundaryMatch[1];
    const boundaryMarker = `--${boundary}`;
    const boundaryEnd = `${boundaryMarker}--`;

    // 分割邮件部分
    const parts = bodyText.split(boundaryMarker);
    const nonAttachmentParts: string[] = [];

    for (let i = 0; i < parts.length; i++) {
        const part = parts[i].trim();
        if (!part || part === '--') {
            // 跳过空部分或结束标记
            continue;
        }

        // 检查是否是附件
        const isAttachment = part.includes('Content-Disposition: attachment') ||
            part.includes('Content-Disposition:attachment');

        if (!isAttachment) {
            // 保留非附件部分
            nonAttachmentParts.push(part);
        }
    }

    // 如果没有保留任何部分，返回原邮件（避免丢失内容）
    if (nonAttachmentParts.length === 0) {
        return rawEmail;
    }

    // 重新构建邮件
    // 更新 Content-Type 头部
    let newContentType: string;
    if (nonAttachmentParts.length === 1) {
        // 只有一个部分，检查其 Content-Type
        const partContentTypeMatch = nonAttachmentParts[0].match(/Content-Type:\s*([^\r\n]+)/i);
        if (partContentTypeMatch) {
            newContentType = partContentTypeMatch[1].trim();
        } else {
            newContentType = 'text/plain; charset=UTF-8';
        }
    } else {
        // 多个部分，使用 multipart/alternative
        newContentType = `multipart/alternative; boundary="${boundary}"`;
    }

    // 替换 Content-Type 头部
    const newHeadersText = headersText.replace(
        /Content-Type:\s*[^\r\n]+/i,
        `Content-Type: ${newContentType}`
    );

    // 重新构建正文
    let newBodyText = '';
    if (nonAttachmentParts.length === 1) {
        // 单部分：提取正文内容（跳过头部）
        const part = nonAttachmentParts[0];
        const partHeaderBodySplit = part.indexOf('\r\n\r\n');
        if (partHeaderBodySplit !== -1) {
            newBodyText = part.substring(partHeaderBodySplit + 4);
        } else {
            newBodyText = part;
        }
    } else {
        // 多部分：保留 boundary 结构
        for (let i = 0; i < nonAttachmentParts.length; i++) {
            newBodyText += boundaryMarker + '\r\n';
            newBodyText += nonAttachmentParts[i];
            if (i < nonAttachmentParts.length - 1) {
                newBodyText += '\r\n';
            }
        }
        newBodyText += '\r\n' + boundaryEnd;
    }

    // 组合新的邮件
    return newHeadersText + '\r\n\r\n' + newBodyText;
}

/**
 * 将原始邮件内容保存到 R2 存储（完整邮件，包含附件）
 *
 * @param r2 R2存储桶实例
 * @param rawEmail 原始邮件内容（RFC 822/MIME 格式）
 * @param messageId 邮件的 Message-ID
 * @param emailId 邮件数据库ID
 * @param from 发件人邮箱
 * @param to 收件人邮箱
 * @param headers 邮件头信息（可选，如果不提供则从 rawEmail 中提取）
 * @returns emailId（仅返回ID，不返回完整的R2 key，以节省数据库空间）
 *
 * @description
 * 注意：此函数保存完整的原始邮件，包含邮件头、正文和附件。
 *
 * @description
 * Raw邮件格式说明（RFC 822/MIME标准）:
 *
 * 1. 邮件头（Headers）:
 *    - 每行一个头部字段，格式：字段名: 字段值
 *    - 常见字段：From, To, Subject, Date, Message-ID, Content-Type, MIME-Version 等
 *    - 头部和正文之间用空行分隔
 *
 * 2. 邮件正文（Body）:
 *    - 纯文本邮件：直接是文本内容
 *    - HTML邮件：Content-Type: text/html，正文是HTML代码
 *    - 多部分邮件（Multipart）：使用boundary分隔不同部分
 *
 * 3. MIME格式示例:
 *    ```
 *    From: cem@example.com
 *    To: recipient@example.com
 *    Subject: Test Email
 *    Date: Mon, 1 Jan 2024 12:00:00 +0000
 *    Message-ID: <unique-id@example.com>
 *    MIME-Version: 1.0
 *    Content-Type: multipart/alternative; boundary="----=_Part_12345"
 *
 *    ------=_Part_12345
 *    Content-Type: text/plain; charset=UTF-8
 *
 *    This is plain text content.
 *
 *    ------=_Part_12345
 *    Content-Type: text/html; charset=UTF-8
 *
 *    <html><body>This is HTML content.</body></html>
 *
 *    ------=_Part_12345--
 *    ```
 *
 * 4. 附件格式:
 *    - Content-Type: application/octet-stream 或其他MIME类型
 *    - Content-Disposition: attachment; filename="file.txt"
 *    - Content-Transfer-Encoding: base64（二进制内容通常base64编码）
 *
 * 5. 编码:
 *    - 文本内容：通常使用UTF-8编码
 *    - 二进制内容：使用base64编码
 *    - 长行：可能使用quoted-printable编码
 */
export async function saveRawEmailToR2(
    r2: R2Bucket | any, // 使用 any 避免类型兼容性问题
    rawEmail: string,
    messageId: string,
    emailId: string,
    from?: string,
    to?: string,
    headers?: Record<string, string>
): Promise<string> {
    // 使用新的存储格式：email:{id}.eml
    // 格式：email:{emailId}.eml
    const r2Key = `email:${emailId}.eml`;

    // 保存完整的原始邮件（包含附件）
    // 将字符串转换为 ArrayBuffer
    const encoder = new TextEncoder();
    const rawEmailBytes = encoder.encode(rawEmail);

    // 保存到R2，设置正确的Content-Type
    // message/rfc822 是标准的邮件MIME类型
    await r2.put(r2Key, rawEmailBytes, {
        httpMetadata: {
            contentType: 'message/rfc822', // RFC 822 邮件格式
            contentDisposition: `attachment; filename="email_${emailId}.eml"`
        },
        customMetadata: {
            emailId: emailId,
            messageId: messageId,
            savedAt: new Date().toISOString(),
            format: 'RFC822' // 标识邮件格式标准
        }
    });

    // 返回 emailId 而不是完整的 R2 key，以节省数据库空间
    // 注意：.eml 文件是完整的原始邮件（包含邮件头、正文和附件），所有基础数据已从 message.raw 提取并存入数据库
    return emailId;
}

/**
 * 从 R2 读取原始邮件内容（完整邮件，包含附件）
 *
 * @param r2 R2存储桶实例
 * @param emailIdOrR2Key emailId（如：a419ecd4-ad3a-4fa6-b205-408938707a88）或完整的R2 key（向后兼容）
 * @returns 原始邮件内容（完整邮件，包含邮件头、正文和附件），如果不存在则返回null
 *
 * @description
 * 注意：此函数用于读取完整的原始邮件
 * - 数据库字段（message_id、headers_json、date、reply_to 等）已包含所有基础数据，无需从 .eml 读取
 * - .eml 文件是完整的原始邮件（包含邮件头、正文和附件），用于存储邮件完整内容
 * - 只有在需要邮件完整内容（如查看详情、下载原始邮件）时才调用此函数
 */
export async function getRawEmailFromR2(
    r2: R2Bucket | any, // 使用 any 避免类型兼容性问题
    emailIdOrR2Key: string
): Promise<string | null> {
    try {
        // 如果已经是完整的 R2 key，直接使用；否则转换为完整的 R2 key
        const r2Key = emailIdOrR2Key.startsWith('email:')
            ? emailIdOrR2Key
            : emailIdToR2Key(emailIdOrR2Key);

        // 使用重试机制从 R2 读取对象
        const object = await retryR2Operation(`读取 R2 对象 ${r2Key}`, async () => {
            return await r2.get(r2Key);
        });

        if (!object) {
            return null;
        }

        // 将 ArrayBuffer 转换为字符串
        const arrayBuffer = await object.arrayBuffer();
        const decoder = new TextDecoder('utf-8');
        return decoder.decode(arrayBuffer);
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('邮件存储', '从R2读取原始邮件失败:', error);
        return null;
    }
}

/**
 * 从 R2 读取原始邮件字节。
 *
 * 详情解析必须尽量保留原始字节交给 MIME 解析器处理，避免先按 UTF-8
 * 解码再重新编码导致非 UTF-8 邮件正文损坏。
 */
export async function getRawEmailBytesFromR2(
    r2: R2Bucket | any,
    emailIdOrR2Key: string
): Promise<Uint8Array | null> {
    try {
        const r2Key = emailIdOrR2Key.startsWith('email:')
            ? emailIdOrR2Key
            : emailIdToR2Key(emailIdOrR2Key);

        const object = await retryR2Operation(`读取 R2 对象字节 ${r2Key}`, async () => {
            return await r2.get(r2Key);
        });

        if (!object) {
            return null;
        }

        const arrayBuffer = await object.arrayBuffer();
        return new Uint8Array(arrayBuffer);
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('邮件存储', '从R2读取原始邮件字节失败:', error);
        return null;
    }
}

/**
 * 从 R2 读取邮件元数据（meta.json）
 *
 * @param r2 R2存储桶实例
 * @param emailId 邮件ID
 * @returns 元数据对象，如果不存在则返回null
 */
export async function getEmailMetaFromR2(
    r2: R2Bucket | any,
    emailId: string
): Promise<any | null> {
    try {
        const metaKey = `email:${emailId}:meta.json`;
        const object = await r2.get(metaKey);
        if (!object) {
            return null;
        }

        const arrayBuffer = await object.arrayBuffer();
        const decoder = new TextDecoder('utf-8');
        const metaText = decoder.decode(arrayBuffer);
        return JSON.parse(metaText);
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('邮件存储', '从R2读取邮件元数据失败:', error);
        return null;
    }
}

/**
 * 创建邮件记录
 *
 * @param db 数据库实例
 * @param emailData 邮件数据
 * @param providedEmailId 邮件ID（必须提供），使用 crypto.randomUUID() 生成的 UUID
 * @returns 创建的邮件记录
 */
export async function createEmail(
    db: D1Database,
    emailData: Omit<Email, 'id' | 'created_at' | 'updated_at'>,
    providedEmailId?: string
): Promise<Email> {
    // emailId 必须提供（使用 crypto.randomUUID() 生成的 UUID）
    if (!providedEmailId) {
        throw new Error('emailId 必须提供（使用 crypto.randomUUID() 生成的 UUID）');
    }
    const emailId = providedEmailId;

    // 注意：
    // 1. id 使用 crypto.randomUUID() 生成的 UUID，与 messageId（邮件头中的 Message-ID）不同
    // 2. 原始邮件信息（message_id、headers_json 等）从 message.raw 直接提取并存入数据库
    const sql = `
        INSERT INTO emails (
            id, subject, from_address, to_address, content,
            is_read, attachment_count, message_id, headers_json, size_bytes,
            date, reply_to, cc, bcc, content_type,
            folder, resend_email_id, received_at, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `;

    const bound = [
        emailId,
        emailData.subject || null,
        emailData.from_address || null,
        emailData.to_address || null,
        emailData.content || null, // 内容概览/预览
        emailData.is_read || 0,
        emailData.attachment_count || 0, // 附件数量
        emailData.message_id || null,
        emailData.headers_json || null,
        emailData.size_bytes || null,
        emailData.date || null,
        emailData.reply_to || null,
        emailData.cc || null,
        emailData.bcc || null,
        emailData.content_type || null,
        emailData.folder === 'sent' ? 'sent' : 'inbox',
        emailData.resend_email_id || null,
        emailData.received_at || new Date().toISOString()
    ];

    const stmt = db.prepare(sql);

    // 使用重试机制执行 INSERT 操作
    const result = await retryD1Operation('插入邮件记录', async () => {
        return await stmt.bind(...bound).run();
    });

    if (!result.success) {
        const errorMsg = `Failed to create email; success=${result.success}; meta=${JSON.stringify(result.meta)}; error=${JSON.stringify(result.error || 'undefined')}`;
        throw new Error(errorMsg);
    }

    // 使用重试机制获取创建的邮件
    const createdEmail = await retryD1Operation('查询创建的邮件', async () => {
        return await getEmailById(db, emailId);
    });

    if (!createdEmail) {
        throw new Error('Failed to retrieve created email');
    }

    return createdEmail;
}

/**
 * 根据ID获取邮件
 */
export async function getEmailById(db: D1Database, id: string): Promise<Email | null> {
    // 使用重试机制执行 SELECT 操作
    const result = await retryD1Operation(`查询邮件 ${id}`, async () => {
        return await db.prepare(`
            SELECT id, subject, from_address, to_address, content,
                   is_read, attachment_count, message_id, headers_json, size_bytes,
                   date, reply_to, cc, bcc, content_type,
                   folder, resend_email_id, received_at, created_at, updated_at
            FROM emails
            WHERE id = ?
        `).bind(id).first();
    });

    if (!result) {
        return null;
    }

    return {
        id: result.id as string,
        subject: result.subject as string | null,
        from_address: result.from_address as string | null,
        to_address: result.to_address as string | null,
        content: result.content as string | null,
        is_read: result.is_read as number,
        attachment_count: (result.attachment_count as number) || 0,
        message_id: result.message_id as string | null,
        headers_json: result.headers_json as string | null,
        size_bytes: result.size_bytes as number | null,
        date: result.date as string | null,
        reply_to: result.reply_to as string | null,
        cc: result.cc as string | null,
        bcc: result.bcc as string | null,
        content_type: result.content_type as string | null,
        folder: result.folder === 'sent' ? 'sent' : 'inbox',
        resend_email_id: result.resend_email_id as string | null,
        received_at: result.received_at as string,
        created_at: result.created_at as string | undefined,
        updated_at: result.updated_at as string | undefined,
    };
}

/**
 * 获取所有邮件（单管理员模式）
 *
 * 单管理员模式：系统中只有一个管理员用户，所有邮件都不绑定用户ID。
 *
 * @param db 数据库实例
 * @param params 查询参数（分页、搜索等）
 * @returns 邮件列表和总数
 */
export async function getAllEmails(
    db: D1Database,
    params: EmailQueryParams = {}
): Promise<{
    emails: Email[];
    total: number;
    groups: Array<{ value: string; count: number }>;
    hierarchyGroups: Array<{ domain: string; recipient: string; sender: string; count: number }>;
}> {
    try {
        const { debugLog, errorLog } = await import('../utils/debug');
        debugLog('邮件查询', '开始执行，参数:', params);

        const allowedSortFields = new Set([
            'received_at',
            'created_at',
            'subject',
            'from_address',
            'to_address',
            'attachment_count',
            'is_read',
            'size_bytes'
        ]);

        const {
            page = 1,
            limit = 20,
            folder = 'inbox',
            recipient_domain,
            recipient_mailbox,
            sender_mailbox,
            recipient,
            search,
            status,
            sender,
            subject,
            start_date,
            end_date,
            has_attachments,
            sort = 'received_at',
            order = 'desc'
        } = params;

        const offset = (page - 1) * limit;
        const conditions: string[] = [];
        const values: any[] = [];
        const groupConditions: string[] = [];
        const groupValues: any[] = [];
        const normalizedSort = allowedSortFields.has(sort) ? sort : 'received_at';
        const normalizedOrder = order.toLowerCase() === 'asc' ? 'ASC' : 'DESC';
        const normalizedFolder = folder === 'sent' ? 'sent' : 'inbox';
        const mailboxColumn = normalizedFolder === 'sent' ? 'from_address' : 'to_address';
        const recipientDomainExpression = `CASE
            WHEN to_address IS NULL OR TRIM(to_address) = '' OR INSTR(to_address, '@') = 0 THEN '(空域名)'
            ELSE LOWER(SUBSTR(to_address, INSTR(to_address, '@') + 1))
        END`;
        const senderExpression = `COALESCE(NULLIF(TRIM(from_address), ''), '(空地址)')`;
        const mailboxExpression = `COALESCE(NULLIF(TRIM(${mailboxColumn}), ''), '(空地址)')`;
        const addCondition = (condition: string, conditionValues: any[] = [], options: { group?: boolean } = {}) => {
            conditions.push(condition);
            values.push(...conditionValues);
            if (options.group !== false) {
                groupConditions.push(condition);
                groupValues.push(...conditionValues);
            }
        };

        // 构建查询条件
        addCondition('folder = ?', [normalizedFolder]);

        if (recipient_domain) {
            addCondition(`${recipientDomainExpression} = ?`, [recipient_domain], { group: false });
        }

        if (recipient_mailbox) {
            addCondition('to_address = ?', [recipient_mailbox], { group: false });
        }

        if (sender_mailbox) {
            addCondition(`${senderExpression} = ?`, [sender_mailbox], { group: false });
        }

        if (search) {
            const searchPattern = `%${search}%`;
            addCondition(
                '(subject LIKE ? OR content LIKE ? OR from_address LIKE ? OR to_address LIKE ?)',
                [searchPattern, searchPattern, searchPattern, searchPattern]
            );
        }

        if (status === 'read') {
            addCondition('is_read = 1');
        } else if (status === 'unread') {
            addCondition('is_read = 0');
        }

        if (sender) {
            addCondition('from_address LIKE ?', [`%${sender}%`]);
        }

        if (recipient) {
            addCondition('to_address LIKE ?', [`%${recipient}%`]);
        }

        if (subject) {
            addCondition('subject LIKE ?', [`%${subject}%`]);
        }

        if (start_date) {
            addCondition('received_at >= ?', [start_date]);
        }

        if (end_date) {
            addCondition('received_at <= ?', [end_date]);
        }

        if (has_attachments !== undefined) {
            // 使用 attachment_count > 0 来判断是否有附件
            if (has_attachments) {
                addCondition('attachment_count > 0');
            } else {
                addCondition('attachment_count = 0');
            }
        }

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
        const orderClause = `ORDER BY ${normalizedSort} ${normalizedOrder}`;

        // 获取邮件列表（从 message.raw 提取的信息）
        const emailsResult = await db.prepare(`
            SELECT 
                e.id, e.subject, e.from_address, e.to_address, 
                e.content, e.is_read, e.attachment_count,
                e.message_id, e.headers_json, e.size_bytes,
                e.date, e.reply_to, e.cc, e.bcc, e.content_type,
                e.folder, e.resend_email_id, e.received_at, e.created_at, e.updated_at
            FROM emails e
            ${whereClause}
            ${orderClause}
            LIMIT ? OFFSET ?
        `).bind(...values, limit, offset).all();

        debugLog('邮件查询', '查询结果:', emailsResult.results.length, '封邮件');

        // 获取总数
        const countResult = await db.prepare(`
            SELECT COUNT(*) as total
            FROM emails
            ${whereClause}
        `).bind(...values).first();

        const groupWhereClause = groupConditions.length > 0 ? `WHERE ${groupConditions.join(' AND ')}` : '';
        const groupsResult = await db.prepare(`
            SELECT ${mailboxExpression} as value, COUNT(*) as count
            FROM emails
            ${groupWhereClause}
            GROUP BY ${mailboxExpression}
            ORDER BY count DESC, value ASC
        `).bind(...groupValues).all();

        const hierarchyGroupsResult = await db.prepare(`
            SELECT
                ${recipientDomainExpression} as domain,
                ${mailboxExpression} as recipient,
                ${senderExpression} as sender,
                COUNT(*) as count
            FROM emails
            ${groupWhereClause}
            GROUP BY ${recipientDomainExpression}, ${mailboxExpression}, ${senderExpression}
            ORDER BY domain ASC, recipient ASC, count DESC, sender ASC
        `).bind(...groupValues).all();

        debugLog('邮件查询', '总数查询结果:', countResult?.total);

        const emails = emailsResult.results.map(result => ({
            id: result.id as string,
            subject: result.subject as string | null,
            from_address: result.from_address as string | null,
            to_address: result.to_address as string | null,
            content: result.content as string | null,
            is_read: result.is_read as number,
            attachment_count: (result.attachment_count as number) || 0,
            message_id: result.message_id as string | null,
            headers_json: result.headers_json as string | null,
            size_bytes: result.size_bytes as number | null,
            date: result.date as string | null,
            reply_to: result.reply_to as string | null,
            cc: result.cc as string | null,
            bcc: result.bcc as string | null,
            content_type: result.content_type as string | null,
            folder: (result.folder === 'sent' ? 'sent' : 'inbox') as 'inbox' | 'sent',
            resend_email_id: result.resend_email_id as string | null,
            received_at: result.received_at as string,
            created_at: result.created_at as string | undefined,
            updated_at: result.updated_at as string | undefined,
        }));

        debugLog('邮件查询', '返回结果:', { emails: emails.length, total: countResult?.total || 0 });

        return {
            emails,
            total: countResult?.total as number || 0,
            groups: (groupsResult.results || []).map((row: any) => ({
                value: String(row.value || '(空地址)'),
                count: Number(row.count || 0)
            })),
            hierarchyGroups: (hierarchyGroupsResult.results || []).map((row: any) => ({
                domain: String(row.domain || '(空域名)'),
                recipient: String(row.recipient || '(空地址)'),
                sender: String(row.sender || '(空地址)'),
                count: Number(row.count || 0)
            }))
        };
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('邮件查询', '执行失败:', error);
        throw error;
    }
}

/**
 * 删除邮件
 */
/**
 * 更新邮件已读状态
 *
 * @param db 数据库实例
 * @param emailId 邮件ID
 * @param isRead 是否已读（true=已读, false=未读）
 * @returns 更新后的邮件记录
 */
export async function updateEmailReadStatus(
    db: D1Database,
    emailId: string,
    isRead: boolean
): Promise<Email | null> {
    const result = await db.prepare(`
        UPDATE emails
        SET is_read = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `).bind(isRead ? 1 : 0, emailId).run();

    if (!result.success) {
        throw new Error('Failed to update email read status');
    }

    return await getEmailById(db, emailId);
}

/**
 * 批量更新邮件已读状态
 *
 * @param db 数据库实例
 * @param emailIds 邮件ID数组
 * @param isRead 是否已读（true=已读, false=未读）
 * @returns 更新的邮件数量
 */
export async function batchUpdateEmailReadStatus(
    db: D1Database,
    emailIds: string[],
    isRead: boolean
): Promise<number> {
    if (emailIds.length === 0) {
        return 0;
    }

    // 使用 IN 子句批量更新
    const placeholders = emailIds.map(() => '?').join(',');
    const result = await db.prepare(`
        UPDATE emails
        SET is_read = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id IN (${placeholders})
    `).bind(isRead ? 1 : 0, ...emailIds).run();

    if (!result.success) {
        throw new Error('Failed to batch update email read status');
    }

    return result.meta.changes || 0;
}

/**
 * 批量删除邮件
 *
 * @param db 数据库实例
 * @param r2 R2存储桶实例
 * @param emailIds 邮件ID数组
 * @returns 删除结果
 */
export async function batchDeleteEmails(
    db: D1Database,
    r2: R2Bucket | any,
    emailIds: string[]
): Promise<{ deletedEmails: number; deletedFiles: number; deletedAttachments: number }> {
    let deletedEmails = 0;
    let deletedFiles = 0;

    for (const emailId of emailIds) {
        try {
            const result = await deleteEmail(db, r2, emailId);
            deletedEmails++;
            deletedFiles += result.deletedFiles;
        } catch (error) {
            const { errorLog } = await import('../utils/debug');
            errorLog('邮件删除', `删除邮件失败: ${emailId}`, error);
        }
    }

    // 返回兼容的格式（附件相关字段始终为 0）
    return { deletedEmails, deletedFiles, deletedAttachments: 0 };
}

/**
 * 删除邮件（包括数据库记录和 R2 文件）
 *
 * @param db 数据库实例
 * @param r2 R2存储桶实例
 * @param emailId 邮件ID
 * @returns 删除结果，包含删除的文件数量
 *
 * @description
 * 注意：不再删除附件，因为不再单独保存附件
 */
export async function deleteEmail(
    db: D1Database,
    r2: R2Bucket | any,
    emailId: string
): Promise<{ deletedFiles: number; deletedAttachments: number }> {
    let deletedFiles = 0;

    // 先获取邮件信息
    const email = await getEmailById(db, emailId);
    if (!email) {
        throw new Error('邮件不存在');
    }

    // 删除 R2 中的精简版 .eml 文件
    try {
        const emlKey = emailIdToR2Key(email.id);
        await r2.delete(emlKey);
        deletedFiles++;
        const { debugLog } = await import('../utils/debug');
        debugLog('邮件删除', `删除 R2 文件: ${emlKey}`);
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('邮件删除', `删除 .eml 文件失败: ${email.id}`, error);
    }

    // 删除 R2 中的所有附件（attachments/{emailId}/）
    try {
        const attachmentsPrefix = `attachments/${email.id}/`;
        const attachmentsList = await r2.list({ prefix: attachmentsPrefix });

        if (attachmentsList.objects && attachmentsList.objects.length > 0) {
            for (const obj of attachmentsList.objects) {
                await r2.delete(obj.key);
                deletedFiles++;
            }
            const { debugLog } = await import('../utils/debug');
            debugLog('附件删除', `删除了 ${attachmentsList.objects.length} 个附件文件（包含内嵌图片）`);
        }
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('附件删除', `删除附件文件失败: ${email.id}`, error);
    }

    // 删除数据库中的邮件记录
    const result = await db.prepare(`
        DELETE FROM emails WHERE id = ?
    `).bind(emailId).run();

    if (!result.success) {
        throw new Error('Failed to delete email from database');
    }

    // 返回兼容的格式（附件相关字段始终为 0）
    return { deletedFiles, deletedAttachments: 0 };
}

/**
 * 获取邮件附件列表
 */
export async function getEmailAttachments(db: D1Database, emailId: string): Promise<Attachment[]> {
    // 调试：打印查询参数
    const { debugLog } = await import('../utils/debug');
    debugLog('附件查询', '查询附件，emailId:', emailId, '类型:', typeof emailId);

    const result = await db.prepare(`
        SELECT id, email_id, filename, content_type, size_bytes, r2_key, content_id,
               deleted_at, created_at, updated_at
        FROM attachments
        WHERE email_id = ?
        ORDER BY created_at
    `).bind(emailId).all();

    debugLog('附件查询', '查询结果数量:', result.results.length);

    return result.results.map(row => ({
        id: row.id as string,
        email_id: row.email_id as string,
        filename: row.filename as string,
        content_type: row.content_type as string,
        size_bytes: row.size_bytes as number,
        r2_key: row.r2_key as string,
        content_id: row.content_id as string | null | undefined,
        deleted_at: row.deleted_at as string | null | undefined,
        created_at: row.created_at as string | undefined,
        updated_at: row.updated_at as string | undefined,
    }));
}

/**
 * 创建附件记录
 * @param db 数据库实例
 * @param attachmentData 附件数据（不包含 id 和 created_at、updated_at）
 */
export async function createAttachment(
    db: D1Database,
    attachmentData: Omit<Attachment, 'id' | 'created_at' | 'updated_at'>
): Promise<Attachment> {
    // 生成 UUID 作为附件 ID
    const attachmentId = crypto.randomUUID();

    const result = await db.prepare(`
        INSERT INTO attachments (
            id, email_id, filename, content_type, size_bytes, r2_key, content_id,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).bind(
        attachmentId,
        attachmentData.email_id,
        attachmentData.filename,
        attachmentData.content_type,
        attachmentData.size_bytes,
        attachmentData.r2_key,
        attachmentData.content_id || null
    ).run();

    if (!result.success) {
        throw new Error('Failed to create attachment');
    }

    const createdAttachment = await db.prepare(`
        SELECT id, email_id, filename, content_type, size_bytes, r2_key, content_id,
               created_at, updated_at
        FROM attachments
        WHERE id = ?
    `).bind(attachmentId).first();

    if (!createdAttachment) {
        throw new Error('Failed to retrieve created attachment');
    }

    return {
        id: createdAttachment.id as string,
        email_id: createdAttachment.email_id as string,
        filename: createdAttachment.filename as string,
        content_type: createdAttachment.content_type as string,
        size_bytes: createdAttachment.size_bytes as number,
        r2_key: createdAttachment.r2_key as string,
        content_id: createdAttachment.content_id as string | null | undefined,
        created_at: createdAttachment.created_at as string | undefined,
        updated_at: createdAttachment.updated_at as string | undefined,
    };
}

/**
 * 将一封邮件的附件复制到另一封邮件。
 *
 * 站内转发不会经过 SMTP/MIME 重新投递，必须复制 R2 对象和附件表记录，
 * 否则新邮件只会有正文摘要，前端附件列表为空。
 */
export async function copyEmailAttachments(
    db: D1Database,
    r2: R2Bucket | any,
    sourceEmailId: string,
    targetEmailId: string
): Promise<number> {
    const attachments = (await getEmailAttachments(db, sourceEmailId))
        .filter(attachment => !attachment.deleted_at);

    let copiedCount = 0;
    const usedKeys = new Set<string>();

    for (let i = 0; i < attachments.length; i++) {
        const attachment = attachments[i];
        const sourcePrefix = `attachments/${sourceEmailId}/`;
        if (!attachment.r2_key.startsWith(sourcePrefix)) {
            throw new Error(`附件存储路径无效：${attachment.r2_key}`);
        }

        const sourceObject = await retryR2Operation(`读取待转发附件 ${attachment.r2_key}`, async () => {
            return await r2.get(attachment.r2_key);
        });

        if (!sourceObject) {
            throw new Error(`待转发附件不存在：${attachment.filename}`);
        }

        const targetR2Key = attachment.r2_key.replace(sourcePrefix, `attachments/${targetEmailId}/`);
        if (usedKeys.has(targetR2Key)) {
            throw new Error(`转发附件目标路径重复：${targetR2Key}`);
        }
        usedKeys.add(targetR2Key);

        const content = await sourceObject.arrayBuffer();
        await retryR2Operation(`复制转发附件 ${attachment.filename}`, async () => {
            return await r2.put(targetR2Key, content, {
                httpMetadata: {
                    contentType: attachment.content_type || 'application/octet-stream',
                    contentDisposition: attachment.content_id
                        ? 'inline'
                        : `attachment; filename="${encodeURIComponent(attachment.filename)}"`,
                    cacheControl: 'public, max-age=31536000'
                },
                customMetadata: {
                    emailId: targetEmailId,
                    sourceEmailId,
                    sourceAttachmentId: attachment.id,
                    filename: attachment.filename,
                    contentId: attachment.content_id || '',
                    copiedAt: new Date().toISOString()
                }
            });
        });

        await createAttachment(db, {
            email_id: targetEmailId,
            filename: attachment.filename,
            content_type: attachment.content_type || 'application/octet-stream',
            size_bytes: attachment.size_bytes || content.byteLength,
            r2_key: targetR2Key,
            content_id: attachment.content_id || null,
            deleted_at: null
        });

        copiedCount++;
    }

    return copiedCount;
}

/**
 * 将 HTML 内容中的 cid: 引用替换为附件 URL
 * @param htmlContent HTML 内容
 * @param attachments 附件列表
 * @param emailId 邮件ID
 * @returns 替换后的 HTML 内容
 */
export function replaceCidReferencesInHtml(
    htmlContent: string,
    attachments: Attachment[],
    emailId: string
): string {
    if (!htmlContent || !attachments || attachments.length === 0) {
        return htmlContent;
    }

    // 创建 Content-ID 到附件的映射
    const cidMap = new Map<string, Attachment>();
    for (const attachment of attachments) {
        if (attachment.content_id) {
            // 支持多种格式：带 < > 或不带
            const cid = attachment.content_id.replace(/^<|>$/g, '');
            cidMap.set(cid.toLowerCase(), attachment);
        }
    }

    if (cidMap.size === 0) {
        return htmlContent;
    }

    // 替换所有 cid: 引用
    // 匹配格式：cid:xxx 或 cid:xxx@xxx 等
    return htmlContent.replace(/cid:([^\s"'>]+)/gi, (match, cidValue) => {
        // 移除可能的 < > 符号
        const normalizedCid = cidValue.replace(/^<|>$/g, '').toLowerCase();
        const attachment = cidMap.get(normalizedCid);

        if (attachment && attachment.id) {
            // 替换为附件 URL
            const attachmentUrl = `/api/emails/${emailId}/attachments/${attachment.id}`;
            return attachmentUrl;
        }

        // 如果没有找到匹配的附件，保持原样
        return match;
    });
}

/**
 * 根据ID获取附件
 */
export async function getAttachmentById(db: D1Database, id: string): Promise<Attachment | null> {
    // 使用重试机制执行 SELECT 操作
    const result = await retryD1Operation(`查询附件 ${id}`, async () => {
        return await db.prepare(`
            SELECT id, email_id, filename, content_type, size_bytes, r2_key, content_id,
                   deleted_at, created_at, updated_at
            FROM attachments
            WHERE id = ?
        `).bind(id).first();
    });

    if (!result) {
        return null;
    }

    return {
        id: result.id as string,
        email_id: result.email_id as string,
        filename: result.filename as string,
        content_type: result.content_type as string,
        size_bytes: result.size_bytes as number,
        r2_key: result.r2_key as string,
        content_id: result.content_id as string | null | undefined,
        deleted_at: result.deleted_at as string | null | undefined,
        created_at: result.created_at as string | undefined,
        updated_at: result.updated_at as string | undefined,
    };
}

/**
 * MIME 邮件解析 - 提取附件
 *
 * @param rawEmail 原始邮件内容
 * @param env 环境变量
 * @param emailId 邮件ID（用于生成附件文件名）
 * @returns 附件数据数组
 */
export async function parseEmailAttachments(rawEmail: string, env: Env, emailId: string): Promise<Omit<Attachment, 'id' | 'email_id' | 'created_at' | 'updated_at'>[]> {
    const attachments: Omit<Attachment, 'id' | 'email_id' | 'created_at' | 'updated_at'>[] = [];

    try {
        // 查找boundary
        const boundaryMatch = rawEmail.match(/boundary="?([^"\s;]+)"?/i);
        if (!boundaryMatch) {
            return attachments;
        }

        const boundary = boundaryMatch[1];
        const parts = rawEmail.split(`--${boundary}`);

        let attachmentIndex = 1; // 附件序号，从1开始

        for (const part of parts) {
            // 跳过非附件部分
            if (!part.includes('Content-Disposition: attachment') &&
                !part.includes('Content-Disposition: inline')) {
                continue;
            }

            // 提取文件名
            const filenameMatch = part.match(/filename[*]?="?([^";\r\n]+)"?/i);
            if (!filenameMatch) continue;

            const filename = filenameMatch[1];

            // 提取Content-Type
            const contentTypeMatch = part.match(/Content-Type:\s*([^;\r\n]+)/i);
            const contentType = contentTypeMatch ? contentTypeMatch[1].trim() : 'application/octet-stream';

            // 提取 Content-ID（用于内嵌图片）
            const contentId = extractContentIdFromMimePart(part);

            // 从 Content-Type 或文件名中提取文件扩展名
            const fileExtension = getFileExtension(contentType, filename);

            // 提取编码方式
            const encodingMatch = part.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i);
            const encoding = encodingMatch ? encodingMatch[1].trim().toLowerCase() : '';

            // 提取内容
            const contentStartIndex = part.indexOf('\r\n\r\n');
            if (contentStartIndex === -1) continue;

            let content = part.substring(contentStartIndex + 4);
            content = content.replace(/\r\n$/, ''); // 移除末尾换行

            // 解码内容
            let decodedContent: ArrayBuffer;
            try {
                if (encoding === 'base64') {
                    // Base64解码
                    const binaryString = atob(content.replace(/\s/g, ''));
                    const bytes = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    decodedContent = bytes.buffer;
                } else {
                    // 其他编码方式，暂时按原文处理
                    const encoder = new TextEncoder();
                    decodedContent = encoder.encode(content).buffer;
                }
            } catch (error) {
                const { debugLog } = await import('../utils/debug');
                debugLog('附件处理', '解码附件内容失败:', filename, error);
                continue;
            }

            // 检查文件大小
            const maxSizeSetting = await getSystemSetting(env.DB, 'max_attachment_size');
            if (!maxSizeSetting) {
                throw new Error('附件大小限制未配置');
            }
            const maxSize = parseInt(maxSizeSetting);
            if (decodedContent.byteLength > maxSize) {
                const { debugLog } = await import('../utils/debug');
                debugLog('附件处理', `附件过大，跳过: ${filename} (${decodedContent.byteLength} bytes)`);
                continue;
            }

            // 生成 R2 key：格式为 attachments/{emailId}-{序号}.{扩展名}
            // 注意：R2 key 使用序号便于管理，但数据库 id 使用 UUID
            const r2Key = `attachments/${emailId}-${attachmentIndex}.${fileExtension}`;
            attachmentIndex++;

            // 存储到 R2
            try {
                await env.R2.put(r2Key, decodedContent, {
                    httpMetadata: {
                        contentType: contentType,
                        contentDisposition: `attachment; filename="${filename}"`
                    }
                });

                attachments.push({
                    filename: filename,
                    content_type: contentType,
                    size_bytes: decodedContent.byteLength,
                    r2_key: r2Key,
                    content_id: contentId
                });
            } catch (error) {
                const { errorLog } = await import('../utils/debug');
                errorLog('附件存储', `存储附件到R2失败: ${filename}`, error);
                continue;
            }
        }
    } catch (error) {
        const { errorLog } = await import('../utils/debug');
        errorLog('邮件解析', 'MIME解析失败:', error);
    }

    return attachments;
}

/**
 * 清理过期附件
 *
 * @param env 环境变量
 * @returns 删除结果
 */
export async function cleanupExpiredAttachments(env: Env): Promise<{
    deletedEmails: number;
    deletedAttachments: number;
    deletedEmailFiles: number;
    deletedAttachmentFiles: number;
}> {
    const attachmentRetentionDaysSetting = await getSystemSetting(env.DB, 'attachment_retention_days');
    if (!attachmentRetentionDaysSetting) {
        const { errorLog } = await import('../utils/debug');
        errorLog('附件清理', '附件保留天数未配置，跳过附件清理');
        return { deletedEmails: 0, deletedAttachments: 0, deletedEmailFiles: 0, deletedAttachmentFiles: 0 };
    }

    const attachmentRetentionDays = parseInt(attachmentRetentionDaysSetting);
    if (!Number.isFinite(attachmentRetentionDays) || attachmentRetentionDays <= 0) {
        const { errorLog } = await import('../utils/debug');
        errorLog('附件清理', `附件保留天数无效: ${attachmentRetentionDaysSetting}`);
        return { deletedEmails: 0, deletedAttachments: 0, deletedEmailFiles: 0, deletedAttachmentFiles: 0 };
    }

    let deletedAttachments = 0;
    let deletedAttachmentFiles = 0;
    const affectedEmailIds = new Set<string>();

    const attachmentsToDelete = await env.DB.prepare(`
        SELECT id, email_id, r2_key
        FROM attachments
        WHERE deleted_at IS NULL
          AND created_at < datetime('now', ?)
    `).bind(`-${attachmentRetentionDays} days`).all();

    for (const row of attachmentsToDelete.results) {
        const attachmentId = row.id as string;
        const emailId = row.email_id as string;
        const r2Key = row.r2_key as string;

        try {
            try {
                await env.R2.delete(r2Key);
                deletedAttachmentFiles++;
            } catch (error) {
                const { errorLog } = await import('../utils/debug');
                errorLog('附件清理', `删除附件文件失败: ${r2Key}`, error);
                continue;
            }

            const result = await env.DB.prepare(`
                UPDATE attachments
                SET deleted_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `).bind(attachmentId).run();

            if (result.success) {
                deletedAttachments++;
                affectedEmailIds.add(emailId);
            }
        } catch (error) {
            const { errorLog } = await import('../utils/debug');
            errorLog('附件清理', `删除附件记录失败: ${attachmentId}`, error);
        }
    }

    for (const emailId of affectedEmailIds) {
        await env.DB.prepare(`
            UPDATE emails
            SET attachment_count = (
                SELECT COUNT(*)
                FROM attachments
                WHERE email_id = ?
                  AND deleted_at IS NULL
            )
            WHERE id = ?
        `).bind(emailId, emailId).run();
    }

    const { infoLog } = await import('../utils/debug');
    infoLog('附件清理', `清理完成: 删除了 ${deletedAttachments} 条附件记录、${deletedAttachmentFiles} 个附件文件`);

    return { deletedEmails: 0, deletedAttachments, deletedEmailFiles: 0, deletedAttachmentFiles };
}

export const cleanupOldEmails = cleanupExpiredAttachments;

/**
 * 发送邮件
 */
export async function sendEmail(
    env: Env,
    emailData: {
        to: string;
        from?: string;
        subject: string;
        content: string;
        content_type: 'text' | 'html';
        delivery_method?: 'cf' | 'internal' | 'resend';
        reply_to?: string;
    }
): Promise<{ messageId?: string }> {
    const { debugLog } = await import('../utils/debug');
    const deliveryMethod = emailData.delivery_method || 'cf';

    debugLog('邮件发送', '发送邮件:', {
        to: emailData.to,
        from: emailData.from || '(由发送服务决定)',
        reply_to: emailData.reply_to || '',
        subject: emailData.subject,
        content_type: emailData.content_type,
        delivery_method: deliveryMethod
    });

    if (deliveryMethod === 'resend') {
        return await sendViaResend(env.DB, emailData);
    }

    if (deliveryMethod !== 'cf') {
        throw new Error(`${deliveryMethod} 邮件发送功能尚未实现`);
    }

    if (!env.EMAIL) {
        throw new Error('Cloudflare Email Service 未配置：缺少 EMAIL send_email 绑定');
    }

    if (!emailData.from) {
        throw new Error('使用 Cloudflare Email Service 发信时必须提供发件人地址');
    }

    return await env.EMAIL.send({
        to: emailData.to,
        from: emailData.from,
        ...(emailData.reply_to ? { replyTo: emailData.reply_to } : {}),
        subject: emailData.subject,
        ...(emailData.content_type === 'html'
            ? { html: emailData.content }
            : { text: emailData.content })
    });
}
