/**
 * 模板工具 - 提供前端HTML模板
 * 
 * 使用预编译的 HTML 模板，保持代码和模板分离
 */

import { getTemplate as getCompiledTemplate } from '../templates/compiled';

/**
 * 获取完整的HTML模板
 */
export async function getTemplate(): Promise<string> {
    try {
        // 返回编译后的 HTML 模板
        return getCompiledTemplate();
    } catch (error) {
        console.error('获取模板失败:', error);
        // 返回错误页面
        return getErrorTemplate();
    }
}

/**
 * 错误模板
 */
function getErrorTemplate(): string {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>临时邮箱管理系统 - 错误</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .error {
            background: white;
            border-radius: 10px;
            padding: 40px;
            max-width: 500px;
            margin: 100px auto;
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
        }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            margin-top: 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #5a67d8;
        }
    </style>
</head>
<body>
    <div class="error">
        <h1>⚠️ 系统错误</h1>
        <p>模板加载失败，请刷新页面重试。</p>
        <p>如果问题持续存在，请联系管理员。</p>
        <a href="/" class="btn">刷新页面</a>
    </div>
</body>
</html>`;
}