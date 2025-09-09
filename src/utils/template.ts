/**
 * 模板加载器
 * 使用模块化的 HTML、CSS、JavaScript
 */

import { getHTMLTemplate } from '../templates/html-template';

/**
 * 获取完整的HTML模板
 * 所有内容都已模块化
 */
export async function getTemplate(): Promise<string> {
    try {
        // 返回模块化的 HTML 模板
        return await getHTMLTemplate();
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
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .error-container {
            background: white;
            border-radius: 10px;
            padding: 40px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        h1 {
            color: #e74c3c;
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
    <div class="error-container">
        <h1>⚠️ 系统错误</h1>
        <p>抱歉，系统遇到了一些问题。</p>
        <p>请稍后再试，或联系管理员。</p>
        <a href="/" class="btn">刷新页面</a>
    </div>
</body>
</html>`;
}