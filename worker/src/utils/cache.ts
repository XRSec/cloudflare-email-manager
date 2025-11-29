/**
 * R2 文件缓存工具
 * 提供 HTTP 缓存机制，避免重复请求
 */

import type { Context } from 'hono';
import type { R2ObjectBody } from '@cloudflare/workers-types';

/**
 * 生成 ETag
 * @param identifier 唯一标识符（如文件 ID、路径等）
 * @param lastModified 最后修改时间
 */
export function generateETag(identifier: string, lastModified?: string): string {
    const content = lastModified ? `${identifier}-${lastModified}` : identifier;
    return `"${hashString(content)}"`;
}

/**
 * 简单的字符串哈希函数
 */
function hashString(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
}

/**
 * 检查缓存是否有效
 * @param c Hono Context
 * @param etag 资源的 ETag
 * @param lastModified 资源的最后修改时间
 * @returns 如果缓存有效返回 true
 */
export function isCacheValid(c: Context, etag: string, lastModified?: Date): boolean {
    // 检查 If-None-Match (ETag)
    const ifNoneMatch = c.req.header('If-None-Match');
    if (ifNoneMatch) {
        // 支持多个 ETag，用逗号分隔
        const etags = ifNoneMatch.split(',').map(e => e.trim());
        if (etags.includes(etag) || etags.includes('*')) {
            return true;
        }
    }

    // 检查 If-Modified-Since
    if (lastModified) {
        const ifModifiedSince = c.req.header('If-Modified-Since');
        if (ifModifiedSince) {
            try {
                const ifModifiedSinceDate = new Date(ifModifiedSince);
                // 如果资源未修改（修改时间 <= If-Modified-Since）
                if (lastModified.getTime() <= ifModifiedSinceDate.getTime()) {
                    return true;
                }
            } catch (e) {
                // 忽略无效的日期格式
            }
        }
    }

    return false;
}

/**
 * 创建带缓存头的响应
 * @param body 响应体
 * @param options 选项
 */
export function createCachedResponse(
    body: ReadableStream | ArrayBuffer | string | null,
    options: {
        contentType: string;
        contentDisposition?: string;
        contentLength?: number;
        etag: string;
        lastModified?: Date;
        maxAge?: number; // 缓存时间（秒），默认 1 年
        immutable?: boolean; // 是否为不可变资源
    }
): Response {
    const {
        contentType,
        contentDisposition,
        contentLength,
        etag,
        lastModified,
        maxAge = 31536000, // 默认 1 年
        immutable = false
    } = options;

    const headers: Record<string, string> = {
        'Content-Type': contentType,
        'ETag': etag,
        'Cache-Control': immutable
            ? `public, max-age=${maxAge}, immutable`
            : `public, max-age=${maxAge}`
    };

    if (contentDisposition) {
        headers['Content-Disposition'] = contentDisposition;
    }

    if (contentLength !== undefined) {
        headers['Content-Length'] = contentLength.toString();
    }

    if (lastModified) {
        headers['Last-Modified'] = lastModified.toUTCString();
    }

    // 添加 Vary 头，确保根据认证状态正确缓存
    headers['Vary'] = 'Authorization';

    return new Response(body, {
        status: 200,
        headers
    });
}

/**
 * 创建 304 Not Modified 响应
 * @param etag ETag 值
 * @param lastModified 最后修改时间
 */
export function createNotModifiedResponse(etag: string, lastModified?: Date): Response {
    const headers: Record<string, string> = {
        'ETag': etag,
        'Cache-Control': 'public, max-age=31536000'
    };

    if (lastModified) {
        headers['Last-Modified'] = lastModified.toUTCString();
    }

    return new Response(null, {
        status: 304,
        headers
    });
}

/**
 * 处理 R2 对象的缓存响应
 * @param c Hono Context
 * @param r2Object R2 对象
 * @param options 选项
 */
export function handleR2ObjectCache(
    c: Context,
    r2Object: any, // 使用 any 避免类型冲突
    options: {
        contentType: string;
        contentDisposition?: string;
        identifier: string; // 唯一标识符（用于生成 ETag）
        immutable?: boolean;
        body?: ReadableStream; // 可选的自定义 body（用于 tee 后的 stream）
    }
): Response {
    const { contentType, contentDisposition, identifier, immutable = true, body } = options;

    // R2 对象的 uploaded 时间作为 lastModified
    const lastModified = r2Object.uploaded ? new Date(r2Object.uploaded) : undefined;

    // 生成 ETag（使用 R2 的 etag 或自己生成）
    const etag = r2Object.etag
        ? `"${r2Object.etag}"`
        : generateETag(identifier, lastModified?.toISOString());

    // 检查缓存是否有效
    if (isCacheValid(c, etag, lastModified)) {
        return createNotModifiedResponse(etag, lastModified);
    }

    // 返回带缓存头的完整响应，使用自定义 body 或原始 body
    return createCachedResponse((body || r2Object.body) as any, {
        contentType,
        contentDisposition,
        contentLength: r2Object.size,
        etag,
        lastModified,
        immutable
    });
}

/**
 * 处理文本内容的缓存响应
 * @param c Hono Context
 * @param content 文本内容
 * @param options 选项
 */
export function handleTextContentCache(
    c: Context,
    content: string,
    options: {
        contentType: string;
        contentDisposition?: string;
        identifier: string; // 唯一标识符
        lastModified?: Date;
        immutable?: boolean;
    }
): Response {
    const { contentType, contentDisposition, identifier, lastModified, immutable = true } = options;

    // 生成 ETag
    const etag = generateETag(identifier, lastModified?.toISOString());

    // 检查缓存是否有效
    if (isCacheValid(c, etag, lastModified)) {
        return createNotModifiedResponse(etag, lastModified);
    }

    // 返回带缓存头的完整响应
    const encoder = new TextEncoder();
    const contentBytes = encoder.encode(content);

    return createCachedResponse(contentBytes.buffer, {
        contentType,
        contentDisposition,
        contentLength: contentBytes.length,
        etag,
        lastModified,
        immutable
    });
}
