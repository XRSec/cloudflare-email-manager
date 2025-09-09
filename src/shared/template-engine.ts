/**
 * 模板引擎
 * 安全的HTML模板生成系统
 */

import { escapeHtml } from './utils';

/**
 * 模板变量接口
 */
export interface TemplateVariables {
    [key: string]: any;
}

/**
 * 模板选项
 */
export interface TemplateOptions {
    escapeHtml?: boolean;
    allowUnsafe?: boolean;
}

/**
 * 模板引擎类
 */
export class TemplateEngine {
    private static instance: TemplateEngine;
    
    private constructor() {}
    
    public static getInstance(): TemplateEngine {
        if (!TemplateEngine.instance) {
            TemplateEngine.instance = new TemplateEngine();
        }
        return TemplateEngine.instance;
    }
    
    /**
     * 渲染模板
     * @param template 模板字符串
     * @param variables 变量对象
     * @param options 选项
     */
    public render(
        template: string, 
        variables: TemplateVariables = {}, 
        options: TemplateOptions = {}
    ): string {
        const { escapeHtml: shouldEscape = true, allowUnsafe = false } = options;
        
        // 替换变量
        let result = template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
            const value = variables[key];
            if (value === undefined || value === null) {
                return '';
            }
            
            const stringValue = String(value);
            return shouldEscape ? escapeHtml(stringValue) : stringValue;
        });
        
        // 处理条件语句 {{#if condition}}...{{/if}}
        result = this.processConditionals(result, variables, shouldEscape);
        
        // 处理循环语句 {{#each array}}...{{/each}}
        result = this.processLoops(result, variables, shouldEscape);
        
        // 处理注释 {{!-- comment --}}
        result = result.replace(/\{\{!--[\s\S]*?--\}\}/g, '');
        
        return result;
    }
    
    /**
     * 处理条件语句
     */
    private processConditionals(
        template: string, 
        variables: TemplateVariables, 
        shouldEscape: boolean
    ): string {
        return template.replace(/\{\{#if\s+(\w+)\}\}([\s\S]*?)\{\{\/if\}\}/g, (match, key, content) => {
            const value = variables[key];
            if (this.isTruthy(value)) {
                return this.render(content, variables, { escapeHtml: shouldEscape, allowUnsafe: true });
            }
            return '';
        });
    }
    
    /**
     * 处理循环语句
     */
    private processLoops(
        template: string, 
        variables: TemplateVariables, 
        shouldEscape: boolean
    ): string {
        return template.replace(/\{\{#each\s+(\w+)\}\}([\s\S]*?)\{\{\/each\}\}/g, (match, key, content) => {
            const array = variables[key];
            if (!Array.isArray(array)) {
                return '';
            }
            
            return array.map((item, index) => {
                const itemVariables = {
                    ...variables,
                    [key]: item,
                    '@index': index,
                    '@first': index === 0,
                    '@last': index === array.length - 1
                };
                return this.render(content, itemVariables, { escapeHtml: shouldEscape, allowUnsafe: true });
            }).join('');
        });
    }
    
    /**
     * 检查值是否为真
     */
    private isTruthy(value: any): boolean {
        if (value === null || value === undefined) return false;
        if (typeof value === 'boolean') return value;
        if (typeof value === 'number') return value !== 0;
        if (typeof value === 'string') return value.length > 0;
        if (Array.isArray(value)) return value.length > 0;
        if (typeof value === 'object') return Object.keys(value).length > 0;
        return Boolean(value);
    }
    
    /**
     * 创建模板函数（缓存优化）
     */
    public createTemplate(template: string): (variables: TemplateVariables, options?: TemplateOptions) => string {
        return (variables: TemplateVariables, options?: TemplateOptions) => {
            return this.render(template, variables, options);
        };
    }
}

/**
 * 全局模板引擎实例
 */
export const templateEngine = TemplateEngine.getInstance();

/**
 * 便捷的模板渲染函数
 */
export function renderTemplate(
    template: string, 
    variables: TemplateVariables = {}, 
    options: TemplateOptions = {}
): string {
    return templateEngine.render(template, variables, options);
}

/**
 * 创建模板函数
 */
export function createTemplate(template: string) {
    return templateEngine.createTemplate(template);
}

/**
 * 预定义的模板片段
 */
export const TemplateFragments = {
    /**
     * 加载状态
     */
    loading: '<div class="loading">加载中...</div>',
    
    /**
     * 空状态
     */
    empty: (message: string = '暂无数据') => 
        `<div class="empty-state">
            <div class="empty-icon">📭</div>
            <div class="empty-message">${escapeHtml(message)}</div>
        </div>`,
    
    /**
     * 错误状态
     */
    error: (message: string = '加载失败') => 
        `<div class="error-state">
            <div class="error-icon">❌</div>
            <div class="error-message">${escapeHtml(message)}</div>
        </div>`,
    
    /**
     * 按钮
     */
    button: (text: string, className: string = 'btn', onclick?: string) => 
        `<button class="${className}"${onclick ? ` onclick="${onclick}"` : ''}>${escapeHtml(text)}</button>`,
    
    /**
     * 输入框
     */
    input: (name: string, placeholder: string = '', type: string = 'text', value?: string) => 
        `<input type="${type}" name="${name}" placeholder="${escapeHtml(placeholder)}"${value ? ` value="${escapeHtml(value)}"` : ''} class="form-control">`,
    
    /**
     * 选择框
     */
    select: (name: string, options: Array<{value: string, text: string}>, selected?: string) => {
        const optionsHtml = options.map(option => 
            `<option value="${escapeHtml(option.value)}"${selected === option.value ? ' selected' : ''}>${escapeHtml(option.text)}</option>`
        ).join('');
        return `<select name="${name}" class="form-control">${optionsHtml}</select>`;
    },
    
    /**
     * 模态框
     */
    modal: (id: string, title: string, content: string, footer?: string) => 
        `<div id="${id}" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>${escapeHtml(title)}</h3>
                    <span class="close" onclick="closeModal('${id}')">&times;</span>
                </div>
                <div class="modal-body">${content}</div>
                ${footer ? `<div class="modal-footer">${footer}</div>` : ''}
            </div>
        </div>`,
    
    /**
     * 分页
     */
    pagination: (currentPage: number, totalPages: number, onPageChange: string) => {
        if (totalPages <= 1) return '';
        
        let pagination = '<div class="pagination">';
        
        // 上一页
        if (currentPage > 1) {
            pagination += `<button onclick="${onPageChange}(${currentPage - 1})" class="btn btn-sm">上一页</button>`;
        }
        
        // 页码
        const startPage = Math.max(1, currentPage - 2);
        const endPage = Math.min(totalPages, currentPage + 2);
        
        for (let i = startPage; i <= endPage; i++) {
            const activeClass = i === currentPage ? ' active' : '';
            pagination += `<button onclick="${onPageChange}(${i})" class="btn btn-sm${activeClass}">${i}</button>`;
        }
        
        // 下一页
        if (currentPage < totalPages) {
            pagination += `<button onclick="${onPageChange}(${currentPage + 1})" class="btn btn-sm">下一页</button>`;
        }
        
        pagination += '</div>';
        return pagination;
    }
};
