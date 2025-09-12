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

