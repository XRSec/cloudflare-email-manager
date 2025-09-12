/**
 * 静态资源服务模块
 * 处理前端静态文件的加载和缓存
 */

import type { Env } from '../types';

/**
 * 静态资源缓存接口
 */
interface StaticAsset {
    content: string | ArrayBuffer;
    contentType: string;
    lastModified: Date;
    etag: string;
}

/**
 * 静态资源服务类
 */
export class StaticAssetService {
    private cache = new Map<string, StaticAsset>();
    private cacheTimeout = 5 * 60 * 1000; // 5分钟缓存

    /**
     * 获取静态资源
     */
    async getAsset(path: string, env: Env): Promise<Response | null> {
        try {
            // 清理路径，防止路径遍历攻击
            const cleanPath = this.sanitizePath(path);
            
            // 检查缓存
            const cached = this.cache.get(cleanPath);
            if (cached && this.isCacheValid(cached)) {
                return this.createResponse(cached);
            }

            // 从ASSETS绑定获取资源
            if (env.ASSETS) {
                const asset = await env.ASSETS.fetch(new Request(`https://example.com${cleanPath}`));
                
                if (asset.ok) {
                    const content = await asset.arrayBuffer();
                    const contentType = asset.headers.get('content-type') || this.getContentType(cleanPath);
                    const lastModified = new Date(asset.headers.get('last-modified') || Date.now());
                    const etag = asset.headers.get('etag') || this.generateETag(content);

                    const staticAsset: StaticAsset = {
                        content,
                        contentType,
                        lastModified,
                        etag
                    };

                    // 缓存资源
                    this.cache.set(cleanPath, staticAsset);

                    return this.createResponse(staticAsset);
                }
            }

            return null;
        } catch (error) {
            console.error('获取静态资源失败:', error);
            return null;
        }
    }

    /**
     * 获取默认的HTML文件（SPA路由支持）
     */
    async getDefaultHTML(env: Env): Promise<Response | null> {
        // 尝试获取 index.html
        const indexResponse = await this.getAsset('/index.html', env);
        if (indexResponse) {
            return indexResponse;
        }

        // 如果index.html不存在，返回基本的HTML结构
        const fallbackHTML = this.getFallbackHTML();
        return new Response(fallbackHTML, {
            headers: {
                'Content-Type': 'text/html; charset=utf-8',
                'Cache-Control': 'no-cache'
            }
        });
    }

    /**
     * 清理路径，防止路径遍历攻击
     */
    private sanitizePath(path: string): string {
        // 移除查询参数和hash
        const cleanPath = path.split('?')[0].split('#')[0];
        
        // 确保路径以 / 开头
        const normalizedPath = cleanPath.startsWith('/') ? cleanPath : `/${cleanPath}`;
        
        // 防止路径遍历
        if (normalizedPath.includes('..') || normalizedPath.includes('//')) {
            return '/index.html';
        }

        // 如果是根路径，返回index.html
        if (normalizedPath === '/') {
            return '/index.html';
        }

        return normalizedPath;
    }

    /**
     * 检查缓存是否有效
     */
    private isCacheValid(asset: StaticAsset): boolean {
        return Date.now() - asset.lastModified.getTime() < this.cacheTimeout;
    }

    /**
     * 根据文件扩展名获取Content-Type
     */
    private getContentType(path: string): string {
        const ext = path.split('.').pop()?.toLowerCase();
        
        const mimeTypes: Record<string, string> = {
            'html': 'text/html; charset=utf-8',
            'htm': 'text/html; charset=utf-8',
            'css': 'text/css',
            'js': 'application/javascript',
            'json': 'application/json',
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'svg': 'image/svg+xml',
            'ico': 'image/x-icon',
            'woff': 'font/woff',
            'woff2': 'font/woff2',
            'ttf': 'font/ttf',
            'eot': 'application/vnd.ms-fontobject'
        };

        return mimeTypes[ext || ''] || 'application/octet-stream';
    }

    /**
     * 生成ETag
     */
    private generateETag(content: ArrayBuffer): string {
        // 简单的ETag生成，实际项目中可以使用更复杂的算法
        return `"${content.byteLength}-${Date.now()}"`;
    }

    /**
     * 创建HTTP响应
     */
    private createResponse(asset: StaticAsset): Response {
        const headers = new Headers({
            'Content-Type': asset.contentType,
            'ETag': asset.etag,
            'Last-Modified': asset.lastModified.toUTCString(),
            'Cache-Control': 'public, max-age=3600' // 1小时缓存
        });

        return new Response(asset.content, {
            headers,
            status: 200
        });
    }

    /**
     * 获取回退HTML（当静态资源不可用时）
     */
    private getFallbackHTML(): string {
        return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>临时邮箱管理系统</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 10px;
            padding: 40px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #2980b9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 临时邮箱管理系统</h1>
        <p>系统正在启动中，请稍候...</p>
        <p>如果页面长时间无响应，请刷新页面重试。</p>
        <button class="btn" onclick="window.location.reload()">刷新页面</button>
    </div>
    <script>
        // 自动刷新页面
        setTimeout(() => {
            window.location.reload();
        }, 3000);
    </script>
</body>
</html>`;
    }

    /**
     * 清理过期缓存
     */
    clearExpiredCache(): void {
        const now = Date.now();
        for (const [path, asset] of this.cache.entries()) {
            if (now - asset.lastModified.getTime() >= this.cacheTimeout) {
                this.cache.delete(path);
            }
        }
    }

    /**
     * 清空所有缓存
     */
    clearCache(): void {
        this.cache.clear();
    }
}

// 导出单例实例
export const staticAssetService = new StaticAssetService();