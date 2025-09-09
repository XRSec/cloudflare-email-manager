/**
 * HTML模板片段
 * 使用模板引擎的安全HTML生成
 */

import { renderTemplate, createTemplate, TemplateFragments } from './template-engine';
import { escapeHtml } from './utils';
import { FRONTEND_ROUTES, USER_TYPES } from './constants';

/**
 * 基础HTML结构模板
 */
export const BaseTemplates = {
    /**
     * HTML头部
     */
    head: createTemplate(`
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="临时邮箱管理系统 - 安全、快速、便捷">
        <title>{{title}}</title>
        {{styles}}
    `),

    /**
     * 侧边栏
     */
    sidebar: createTemplate(`
        <div id="sidebar" class="sidebar {{#if hidden}}hidden{{/if}}">
            <div class="sidebar-header">
                <h3>{{title}}</h3>
                <p id="sidebarUserInfo">{{userInfo}}</p>
            </div>
            <div class="sidebar-menu">
                {{#each menuItems}}
                <div class="sidebar-item {{#if active}}active{{/if}} {{#if hidden}}hidden{{/if}}" 
                     onclick="{{onclick}}">{{icon}} {{text}}</div>
                {{/each}}
            </div>
        </div>
    `),

    /**
     * 主内容区域
     */
    mainContent: createTemplate(`
        <div class="main-content {{#if sidebarOpen}}sidebar-open{{/if}}">
            <div class="content-header">
                <button id="sidebarToggle" class="btn btn-secondary">☰</button>
                <h1>{{title}}</h1>
                <div class="user-info">
                    <span id="userEmail">{{userEmail}}</span>
                    <span id="userType">({{userType}})</span>
                </div>
            </div>
            <div class="content-body">
                {{content}}
            </div>
        </div>
    `),

    /**
     * 卡片容器
     */
    card: createTemplate(`
        <div class="card {{className}}">
            <div class="card-header">
                <h2>{{title}}</h2>
                <div class="card-actions">
                    {{actions}}
                </div>
            </div>
            <div class="card-body">
                {{content}}
            </div>
        </div>
    `),

    /**
     * 表单
     */
    form: createTemplate(`
        <form id="{{formId}}" class="form {{#if className}}{{className}}{{/if}}" {{#if method}}method="{{method}}"{{/if}} {{#if action}}action="{{action}}"{{/if}}>
            {{#each fields}}
            <div class="form-group">
                <label for="{{id}}">{{label}}</label>
                {{#if type}}
                <input type="{{type}}" id="{{id}}" name="{{name}}" 
                       placeholder="{{placeholder}}" 
                       value="{{value}}"
                       {{#if required}}required{{/if}}
                       {{#if disabled}}disabled{{/if}}
                       class="form-control">
                {{/if}}
                {{#if textarea}}
                <textarea id="{{id}}" name="{{name}}" 
                          placeholder="{{placeholder}}"
                          {{#if required}}required{{/if}}
                          {{#if disabled}}disabled{{/if}}
                          class="form-control">{{value}}</textarea>
                {{/if}}
                {{#if select}}
                <select id="{{id}}" name="{{name}}" 
                        {{#if required}}required{{/if}}
                        {{#if disabled}}disabled{{/if}}
                        class="form-control">
                    {{#each options}}
                    <option value="{{value}}" {{#if selected}}selected{{/if}}>{{text}}</option>
                    {{/each}}
                </select>
                {{/if}}
                {{#if helpText}}
                <small class="form-text">{{helpText}}</small>
                {{/if}}
            </div>
            {{/each}}
            <div class="form-actions">
                {{actions}}
            </div>
        </form>
    `)
};

/**
 * 邮件相关模板
 */
export const EmailTemplates = {
    /**
     * 邮件列表项
     */
    emailItem: createTemplate(`
        <div class="email-item" data-email-id="{{id}}">
            <div class="email-header" onclick="{{toggleFunction}}({{id}})">
                <div class="email-sender">{{senderEmail}}</div>
                <div class="email-time">{{receivedAt}}</div>
                <div class="email-toggle">{{#if expanded}}▼{{else}}▶{{/if}}</div>
            </div>
            <div class="email-subject">{{subject}}</div>
            <div class="email-preview">{{preview}}</div>
            {{#if hasAttachments}}
            <div class="email-attachments">📎 有附件</div>
            {{/if}}
            <div class="email-details {{#if expanded}}expanded{{/if}}">
                <div class="email-detail-row">
                    <span class="detail-label">收件人:</span>
                    <span class="detail-value">{{recipientEmail}}</span>
                </div>
                <div class="email-detail-row">
                    <span class="detail-label">消息ID:</span>
                    <span class="detail-value">{{messageId}}</span>
                </div>
                <div class="email-detail-row">
                    <span class="detail-label">接收时间:</span>
                    <span class="detail-value">{{receivedAt}}</span>
                </div>
                <div class="email-detail-row">
                    <span class="detail-label">创建时间:</span>
                    <span class="detail-value">{{createdAt}}</span>
                </div>
                {{#if htmlContent}}
                <div class="email-detail-row">
                    <span class="detail-label">HTML内容预览:</span>
                    <div class="html-content">{{htmlContent}}</div>
                </div>
                {{/if}}
                <div class="email-actions">
                    <button class="btn btn-primary btn-sm" onclick="{{viewFunction}}({{id}})">查看详情</button>
                    <button class="btn btn-secondary btn-sm" onclick="{{copyFunction}}({{id}})">复制ID</button>
                </div>
            </div>
        </div>
    `),

    /**
     * 邮件详情模态框
     */
    emailDetailModal: createTemplate(`
        <div id="emailDetailModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>邮件详情</h3>
                    <span class="close" onclick="closeModal('emailDetailModal')">&times;</span>
                </div>
                <div class="modal-body">
                    <div class="email-detail-content">
                        <div class="detail-section">
                            <h4>基本信息</h4>
                            <div class="detail-grid">
                                <div class="detail-item">
                                    <label>发件人:</label>
                                    <span>{{senderEmail}}</span>
                                </div>
                                <div class="detail-item">
                                    <label>收件人:</label>
                                    <span>{{recipientEmail}}</span>
                                </div>
                                <div class="detail-item">
                                    <label>主题:</label>
                                    <span>{{subject}}</span>
                                </div>
                                <div class="detail-item">
                                    <label>接收时间:</label>
                                    <span>{{receivedAt}}</span>
                                </div>
                            </div>
                        </div>
                        {{#if textContent}}
                        <div class="detail-section">
                            <h4>文本内容</h4>
                            <div class="email-text-content">{{textContent}}</div>
                        </div>
                        {{/if}}
                        {{#if htmlContent}}
                        <div class="detail-section">
                            <h4>HTML内容</h4>
                            <div class="email-html-content">{{htmlContent}}</div>
                        </div>
                        {{/if}}
                        {{#if attachments}}
                        <div class="detail-section">
                            <h4>附件</h4>
                            <div class="attachments-list">
                                {{#each attachments}}
                                <div class="attachment-item">
                                    <span class="attachment-name">{{filename}}</span>
                                    <span class="attachment-size">{{size}}</span>
                                    <button class="btn btn-sm" onclick="{{downloadFunction}}({{id}}, {{attachmentId}})">下载</button>
                                </div>
                                {{/each}}
                            </div>
                        </div>
                        {{/if}}
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="closeModal('emailDetailModal')">关闭</button>
                    <button class="btn btn-danger" onclick="{{deleteFunction}}({{id}})">删除邮件</button>
                </div>
            </div>
        </div>
    `)
};

/**
 * 用户管理模板
 */
export const UserTemplates = {
    /**
     * 用户列表项
     */
    userItem: createTemplate(`
        <div class="user-item" data-user-id="{{id}}">
            <div class="user-info">
                <div class="user-email">{{email}}</div>
                <div class="user-type">{{userType}}</div>
                <div class="user-created">{{createdAt}}</div>
            </div>
            <div class="user-actions">
                <button class="btn btn-sm btn-primary" onclick="{{viewFunction}}({{id}})">查看</button>
                <button class="btn btn-sm btn-warning" onclick="{{editFunction}}({{id}})">编辑</button>
                <button class="btn btn-sm btn-danger" onclick="{{deleteFunction}}({{id}})">删除</button>
            </div>
        </div>
    `),

    /**
     * 用户详情模态框
     */
    userDetailModal: createTemplate(`
        <div id="userDetailModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>用户详情</h3>
                    <span class="close" onclick="closeModal('userDetailModal')">&times;</span>
                </div>
                <div class="modal-body">
                    <div class="user-detail-content">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <label>邮箱:</label>
                                <span>{{email}}</span>
                            </div>
                            <div class="detail-item">
                                <label>用户类型:</label>
                                <span>{{userType}}</span>
                            </div>
                            <div class="detail-item">
                                <label>创建时间:</label>
                                <span>{{createdAt}}</span>
                            </div>
                            <div class="detail-item">
                                <label>最后登录:</label>
                                <span>{{lastLogin}}</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="closeModal('userDetailModal')">关闭</button>
                    <button class="btn btn-warning" onclick="{{editFunction}}({{id}})">编辑用户</button>
                </div>
            </div>
        </div>
    `)
};

/**
 * 调试模板
 */
export const DebugTemplates = {
    /**
     * 调试信息面板
     */
    debugPanel: createTemplate(`
        <div class="debug-panel">
            <h3>调试信息</h3>
            <div class="debug-info">
                <div class="debug-item">
                    <label>系统状态:</label>
                    <span class="status-{{status}}">{{statusText}}</span>
                </div>
                <div class="debug-item">
                    <label>当前用户:</label>
                    <span>{{currentUser}}</span>
                </div>
                <div class="debug-item">
                    <label>调试模式:</label>
                    <span class="status-{{debugMode}}">{{debugModeText}}</span>
                </div>
                <div class="debug-item">
                    <label>最后更新:</label>
                    <span>{{lastUpdate}}</span>
                </div>
            </div>
            <div class="debug-actions">
                <button class="btn btn-primary" onclick="{{refreshFunction}}()">刷新调试信息</button>
                <button class="btn btn-secondary" onclick="{{simulateFunction}}()">模拟邮件</button>
            </div>
        </div>
    `),

    /**
     * 模拟邮件表单
     */
    simulateEmailForm: createTemplate(`
        <div class="simulate-form">
            <h4>模拟邮件发送</h4>
            <form id="{{formId}}">
                <div class="form-group">
                    <label for="simFrom">发件人:</label>
                    <input type="email" id="simFrom" name="from" required class="form-control" placeholder="{{fromEmail}}" value="{{fromEmail}}">
                </div>
                <div class="form-group">
                    <label for="simTo">收件人:</label>
                    <input type="email" id="simTo" name="to" required class="form-control" placeholder="{{toEmail}}" value="{{toEmail}}">
                </div>
                <div class="form-group">
                    <label for="simSubject">主题:</label>
                    <input type="text" id="simSubject" name="subject" required class="form-control" placeholder="{{subject}}" value="{{subject}}">
                </div>
                <div class="form-group">
                    <label for="simText">文本内容:</label>
                    <textarea id="simText" name="text" class="form-control" rows="4" placeholder="{{textContent}}" >{{textContent}}</textarea>
                </div>
                <div class="form-group">
                    <label for="simHtml">HTML内容:</label>
                    <textarea id="simHtml" name="html" class="form-control" rows="4" placeholder="{{htmlContent}}" >{{htmlContent}}</textarea>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">发送模拟邮件</button>
                    <button type="button" class="btn btn-secondary" onclick="closeModal('simulateEmailModal')">取消</button>
                </div>
            </form>
        </div>
    `)
};

/**
 * 消息通知模板
 */
export const MessageTemplates = {
    /**
     * 成功消息
     */
    success: (message: string) =>
        `<div class="message success">
            <span class="message-icon">✅</span>
            <span class="message-text">${escapeHtml(message)}</span>
        </div>`,

    /**
     * 错误消息
     */
    error: (message: string) =>
        `<div class="message error">
            <span class="message-icon">❌</span>
            <span class="message-text">${escapeHtml(message)}</span>
        </div>`,

    /**
     * 警告消息
     */
    warning: (message: string) =>
        `<div class="message warning">
            <span class="message-icon">⚠️</span>
            <span class="message-text">${escapeHtml(message)}</span>
        </div>`,

    /**
     * 信息消息
     */
    info: (message: string) =>
        `<div class="message info">
            <span class="message-icon">ℹ️</span>
            <span class="message-text">${escapeHtml(message)}</span>
        </div>`
};

/**
 * 工具函数
 */
export const TemplateHelpers = {
    /**
     * 生成侧边栏菜单项
     */
    generateSidebarMenuItems: (userType: string, debugMode: boolean) => {
        const items: Array<{
            icon: string;
            text: string;
            onclick: string;
            active?: boolean;
            hidden?: boolean;
            className?: string;
            id?: string;
        }> = [
            { icon: '📧', text: '我的邮件', onclick: `showSection('${FRONTEND_ROUTES.EMAILS}')`, active: true },
            { icon: '⚙️', text: '账户设置', onclick: `showSection('${FRONTEND_ROUTES.SETTINGS}')` }
        ];

        if (debugMode) {
            items.push({ icon: '🐛', text: '调试模式', onclick: `showSection('${FRONTEND_ROUTES.DEBUG}')` });
        }

        if (userType === USER_TYPES.ADMIN) {
            items.push(
                { icon: '👥', text: '用户管理', onclick: `showSection('${FRONTEND_ROUTES.ADMIN_USERS}')` },
                { icon: '🔄', text: '转发规则', onclick: `showSection('${FRONTEND_ROUTES.ADMIN_RULES}')` },
                { icon: '📨', text: '全部邮件', onclick: `showSection('${FRONTEND_ROUTES.ADMIN_EMAILS}')` },
                { icon: '🛠️', text: '系统设置', onclick: `showSection('${FRONTEND_ROUTES.ADMIN_SETTINGS}')` }
            );
        }

        items.push({ icon: '🚪', text: '退出登录', onclick: 'logout()', className: 'logout-item' });

        return items;
    },

    /**
     * 生成表单字段
     */
    generateFormFields: (fields: Array<{
        id: string;
        name: string;
        label: string;
        type?: string;
        placeholder?: string;
        value?: string;
        required?: boolean;
        disabled?: boolean;
        helpText?: string;
    }>) => {
        return fields.map(field => ({
            ...field,
            type: field.type || 'text'
        }));
    }
};
