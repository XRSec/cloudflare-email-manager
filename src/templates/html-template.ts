/**
 * HTML 模板模块
 * 主要的 HTML 结构 - 包含 HTML、CSS、JavaScript 的完整前端文件
 */

import { getStyleTag } from '../static/styles';
import { AppConfig } from '../static/app-config';
import { getJavaScript } from '../static/app';
import { 
    BaseTemplates, 
    EmailTemplates, 
    UserTemplates, 
    DebugTemplates, 
    MessageTemplates,
    TemplateHelpers 
} from '../shared/html-templates';
import { renderTemplate, createTemplate } from '../shared/template-engine';
import { escapeHtml, formatDate, truncateText } from '../shared/utils';
import { FRONTEND_ROUTES, USER_TYPES, STORAGE_KEYS } from '../shared/constants';

/**
 * 获取 HTML 头部
 */
function getHTMLHead(): string {
    return `
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="临时邮箱管理系统 - 安全、快速、便捷">
    <title>临时邮箱管理系统</title>
    ${getStyleTag()}
    `;
}

/**
 * 获取侧边栏
 */
function getSidebar(): string {
    return `
    <div id="sidebar" class="sidebar hidden">
        <div class="sidebar-header">
            <h3>邮箱管理</h3>
            <p id="sidebarUserInfo">用户面板</p>
        </div>
        <div class="sidebar-menu">
            <div class="sidebar-item active" onclick="showSection('${FRONTEND_ROUTES.EMAILS}')">📧 我的邮件</div>
            <div class="sidebar-item" onclick="showSection('${FRONTEND_ROUTES.MAILBOXES}')">📮 我的邮箱</div>
            <div class="sidebar-item" onclick="showSection('${FRONTEND_ROUTES.MAILBOX_APPLICATIONS}')">📝 邮箱申请</div>
            <div class="sidebar-item" onclick="showSection('${FRONTEND_ROUTES.SETTINGS}')">⚙️ 账户设置</div>
            <div id="debugMenuItem" class="sidebar-item hidden" onclick="showSection('${FRONTEND_ROUTES.DEBUG}')">🐛 调试模式</div>
            <div id="adminMenuItems" class="hidden">
                <div class="sidebar-item" onclick="showSection('${FRONTEND_ROUTES.ADMIN_USERS}')">👥 用户管理</div>
                <div class="sidebar-item" onclick="showSection('${FRONTEND_ROUTES.ADMIN_RULES}')">🔄 转发规则</div>
                <div class="sidebar-item" onclick="showSection('${FRONTEND_ROUTES.ADMIN_EMAILS}')">📨 全部邮件</div>
                <div class="sidebar-item" onclick="showSection('${FRONTEND_ROUTES.ADMIN_MAILBOXES}')">📮 邮箱管理</div>
                <div class="sidebar-item" onclick="showSection('${FRONTEND_ROUTES.ADMIN_MAILBOX_APPLICATIONS}')">📋 申请审核</div>
                <div class="sidebar-item" onclick="showSection('${FRONTEND_ROUTES.ADMIN_SETTINGS}')">🛠️ 系统设置</div>
            </div>
            <div class="sidebar-item" onclick="logout()" style="margin-top: 20px; color: #dc3545;">🚪 退出登录</div>
        </div>
    </div>
    `;
}

/**
 * 获取通用邮件列表组件
 */
function getEmailListSection(
    sectionId: string, 
    title: string, 
    listId: string, 
    paginationId: string,
    managerName: string = 'EmailManager'
): string {
    return BaseTemplates.card({
        title: title,
        className: 'email-section',
        actions: `
            <div class="email-controls">
                <button class="btn btn-secondary btn-sm" onclick="${managerName}.expandAllEmails()">📖 展开全部</button>
                <button class="btn btn-secondary btn-sm" onclick="${managerName}.collapseAllEmails()">📕 收起全部</button>
            </div>
        `,
        content: `
            <div class="search-box">
                <input type="text" class="search-input" placeholder="搜索邮件..." id="${sectionId}Search">
                <span class="search-icon">🔍</span>
            </div>
            <div id="${listId}" class="loading">加载中</div>
            <div id="${paginationId}"></div>
        `
    }, { escapeHtml: false });
}

/**
 * 获取登录界面
 */
function getLoginSection(): string {
    return `
    <div id="loginSection" class="card">
        <div class="header">
            <h1>临时邮箱管理系统</h1>
            <p>现代化的邮件管理解决方案</p>
        </div>
        
        <div class="tabs">
            <button class="tab active" data-tab="login" onclick="switchTab('login')">登录</button>
            <button class="tab" data-tab="register" onclick="switchTab('register')" style="display:none">注册</button>
        </div>

        <div id="loginForm" class="tab-content active">
            <div class="form-group">
                <label class="form-label">邮箱前缀</label>
                <input type="text" id="loginPrefix" class="form-control" placeholder="请输入邮箱前缀">
            </div>
            <div class="form-group">
                <label class="form-label">邮箱密码</label>
                <input type="password" id="loginPassword" class="form-control" placeholder="请输入邮箱密码">
            </div>
            <button class="btn btn-primary" onclick="login()">登录</button>
        </div>

        <div id="registerForm" class="tab-content">
            <div class="form-group">
                <label class="form-label">设置密码</label>
                <input type="password" id="registerPassword" class="form-control" placeholder="设置邮箱密码（至少6位）">
            </div>
            <button class="btn btn-primary" onclick="register()">注册</button>
            <p style="margin-top: 15px; color: #6c757d; font-size: 0.9rem;">
                注册成功后将为您分配一个随机邮箱前缀
            </p>
        </div>
    </div>
    `;
}

/**
 * 获取主界面
 */
function getMainSection(): string {
    return `
    <div id="mainSection" class="main-content hidden">
        <!-- 顶部栏 -->
        <div class="top-bar">
            <div>
                <button class="btn btn-secondary btn-sm" onclick="toggleSidebar()">☰ 菜单</button>
                <button class="btn btn-success btn-sm" onclick="refreshConfig()">🔄 刷新配置</button>
            </div>
            <div class="user-info">
                <div class="user-avatar" id="userAvatar">U</div>
                <div>
                    <div id="userEmail"></div>
                    <div id="userType" style="font-size: 0.8rem; color: #6c757d;"></div>
                </div>
            </div>
        </div>

        <!-- 邮件列表 -->
        <div id="emailsSection" class="card hidden">
            ${getEmailListSection('emails', '我的邮件', 'emailList', 'emailPagination', 'EmailManager')}
        </div>

        <!-- 我的邮箱 -->
        <div id="mailboxesSection" class="card hidden">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>📮 我的邮箱</h2>
                <button class="btn btn-primary" onclick="showApplyMailboxModal()">申请新邮箱</button>
            </div>
            <div id="mailboxesList">
                <div class="loading">加载中...</div>
            </div>
        </div>

        <!-- 邮箱申请 -->
        <div id="mailboxApplicationsSection" class="card hidden">
            <h2>📝 邮箱申请记录</h2>
            <div id="applicationsList">
                <div class="loading">加载中...</div>
            </div>
        </div>

        <!-- 用户设置 -->
        <div id="settingsSection" class="card hidden">
            <h2>账户设置</h2>
            <form id="settingsForm">
                <div class="form-group">
                    <label class="form-label">新密码（留空表示不修改）</label>
                    <input type="password" id="newPassword" class="form-control" placeholder="输入新密码">
                </div>
                <div class="form-group">
                    <label class="form-label">Webhook URL</label>
                    <input type="url" id="webhookUrl" class="form-control" placeholder="https://example.com/webhook">
                </div>
                <div class="form-group">
                    <label class="form-label">Webhook 密钥</label>
                    <input type="text" id="webhookSecret" class="form-control" placeholder="用于签名验证">
                </div>
                <button type="button" class="btn btn-primary" onclick="updateSettings()">保存设置</button>
            </form>
        </div>

        <!-- 管理员：用户管理 -->
        <div id="adminUsersSection" class="card hidden">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h2>用户管理</h2>
                <button class="btn btn-primary btn-sm" onclick="showCreateUserModal()">+ 创建用户</button>
            </div>
            <div id="usersList" class="loading">加载中</div>
        </div>

        <!-- 管理员：转发规则 -->
        <div id="adminRulesSection" class="card hidden">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h2>转发规则</h2>
                <button class="btn btn-primary btn-sm" onclick="showCreateRuleModal()">+ 创建规则</button>
            </div>
            <div id="rulesList" class="loading">加载中</div>
        </div>

        <!-- 管理员：全部邮件 -->
        <div id="adminEmailsSection" class="card hidden">
            ${getEmailListSection('adminEmails', '全部邮件管理', 'adminEmailsList', 'adminEmailsPagination', 'AdminManager')}
        </div>

        <!-- 管理员：邮箱管理 -->
        <div id="adminMailboxesSection" class="card hidden">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>📮 邮箱管理</h2>
                <button class="btn btn-primary" onclick="showCreateMailboxModal()">创建邮箱</button>
            </div>
            <div id="adminMailboxesList">
                <div class="loading">加载中...</div>
            </div>
        </div>

        <!-- 管理员：申请审核 -->
        <div id="adminMailboxApplicationsSection" class="card hidden">
            <h2>📋 邮箱申请审核</h2>
            <div id="adminApplicationsList">
                <div class="loading">加载中...</div>
            </div>
        </div>

        <!-- 管理员：系统设置 -->
        <div id="adminSettingsSection" class="card hidden">
            <h2>系统设置</h2>
            <div id="systemSettingsForm" class="loading">加载中</div>
        </div>

        <!-- 调试信息 -->
        <div id="debugSection" class="card hidden">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>🐛 调试模式</h2>
                <span class="badge" style="background-color: #dc3545; color: white;">仅调试模式可用</span>
            </div>
            
            ${DebugTemplates.simulateEmailForm({
                formId: 'simulateEmailForm',
                fromEmail: 'sender@test.com',
                toEmail: 'user@example.com',
                subject: '测试邮件主题',
                textContent: '这是一封测试邮件的纯文本内容...',
                htmlContent: '<p>这是一封<strong>测试邮件</strong>的HTML内容...</p>'
            }, { escapeHtml: false })}
            
            ${DebugTemplates.debugPanel({
                status: 'loading',
                statusText: '检测中...',
                currentUser: '加载中...',
                debugMode: 'loading',
                debugModeText: '检测中...',
                lastUpdate: '刚刚',
                refreshFunction: 'refreshDebugInfo',
                simulateFunction: 'simulateEmailReceive'
            }, { escapeHtml: false })}
        </div>
    </div>
    `;
}

/**
 * 获取邮件列表渲染函数（供前端JavaScript使用）
 */
function getEmailListRenderer(): string {
    return `
    // 通用邮件列表渲染函数
    function renderEmailList(emails, listId, managerName = 'EmailManager') {
        const emailList = document.getElementById(listId);
        if (!emailList) return;

        if (emails.length === 0) {
            emailList.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 40px;">暂无邮件</p>';
            return;
        }

        const emailsHtml = emails.map(email => {
            const emailId = email.id;
            const isExpanded = window[managerName].expandedEmails && window[managerName].expandedEmails.has(emailId);
            
            return '<div class="email-item" data-email-id="' + emailId + '">' +
                '<div class="email-header" onclick="' + managerName + '.toggleEmailExpansion(' + emailId + ')">' +
                    '<div class="email-sender">' + escapeHtml(email.sender_email) + '</div>' +
                    '<div class="email-time">' + formatDate(email.received_at) + '</div>' +
                    '<div class="email-toggle">' + (isExpanded ? '▼' : '▶') + '</div>' +
                '</div>' +
                '<div class="email-subject">' + escapeHtml(email.subject || '(无主题)') + '</div>' +
                '<div class="email-preview">' + escapeHtml(truncateText(email.text_content || '(无内容)', 100)) + '</div>' +
                (email.has_attachments ? '<div class="email-attachments">📎 有附件</div>' : '') +
                '<div class="email-details' + (isExpanded ? ' expanded' : '') + '">' +
                    '<div class="email-detail-row">' +
                        '<span class="detail-label">收件人:</span>' +
                        '<span class="detail-value">' + escapeHtml(email.recipient_email) + '</span>' +
                    '</div>' +
                    '<div class="email-detail-row">' +
                        '<span class="detail-label">消息ID:</span>' +
                        '<span class="detail-value">' + escapeHtml(email.message_id || 'N/A') + '</span>' +
                    '</div>' +
                    '<div class="email-detail-row">' +
                        '<span class="detail-label">接收时间:</span>' +
                        '<span class="detail-value">' + formatDate(email.received_at) + '</span>' +
                    '</div>' +
                    '<div class="email-detail-row">' +
                        '<span class="detail-label">创建时间:</span>' +
                        '<span class="detail-value">' + formatDate(email.created_at) + '</span>' +
                    '</div>' +
                    (email.html_content ? 
                        '<div class="email-detail-row">' +
                            '<span class="detail-label">HTML内容预览:</span>' +
                            '<div class="html-content">' + escapeHtml(truncateText(email.html_content, 200)) + '</div>' +
                        '</div>' : '') +
                    '<div class="email-actions">' +
                        '<button class="btn btn-primary btn-sm" onclick="' + managerName + '.showEmailDetail(' + emailId + ')">查看详情</button>' +
                        '<button class="btn btn-secondary btn-sm" onclick="' + managerName + '.copyEmailId(' + emailId + ')">复制ID</button>' +
                    '</div>' +
                '</div>' +
            '</div>';
        }).join('');

        emailList.innerHTML = emailsHtml;
    }

    // 工具函数
    function escapeHtml(text) {
        if (typeof text !== 'string') return '';
        const map = {
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
            '/': '&#x2F;', '\`': '&#x60;', '=': '&#x3D;'
        };
        return text.replace(/[&<>"'\`=\/]/g, function(s) { return map[s] || s; });
    }

    function formatDate(dateString) {
        if (!dateString) return '';
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) return '';
            return date.toLocaleString('zh-CN', {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        } catch (error) {
            return '';
        }
    }

    function truncateText(text, maxLength) {
        if (typeof maxLength === 'undefined') maxLength = 100;
        if (!text || text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }
    `;
}

/**
 * 获取模态框
 */
function getModals(): string {
    return `
    <!-- 创建用户模态框 -->
    <div id="createUserModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>创建新用户</h3>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">用户名</label>
                    <input type="text" id="createUserPrefix" class="form-control" placeholder="用户名（只允许英文、数字、下划线、连字符）">
                </div>
                <div class="form-group">
                    <label class="form-label">密码</label>
                    <input type="password" id="createUserPassword" class="form-control" placeholder="设置密码">
                </div>
                <div class="form-group">
                    <label class="form-label">用户类型</label>
                    <select id="createUserType" class="form-control">
                        <option value="user">普通用户</option>
                        <option value="admin">管理员</option>
                    </select>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('createUserModal')">取消</button>
                <button class="btn btn-primary" onclick="createUser()">创建</button>
            </div>
        </div>
    </div>

    <!-- 创建规则模态框 -->
    <div id="createRuleModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>创建转发规则</h3>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">规则名称</label>
                    <input type="text" id="ruleName" class="form-control" placeholder="规则名称">
                </div>
                <div class="form-group">
                    <label class="form-label">发件人过滤</label>
                    <input type="text" id="ruleSender" class="form-control" placeholder="例如: @example.com">
                </div>
                <div class="form-group">
                    <label class="form-label">关键字过滤</label>
                    <input type="text" id="ruleKeyword" class="form-control" placeholder="邮件内容关键字">
                </div>
                <div class="form-group">
                    <label class="form-label">Webhook URL</label>
                    <input type="url" id="ruleWebhook" class="form-control" placeholder="https://example.com/webhook">
                </div>
                <div class="form-group">
                    <label class="form-label">Webhook 类型</label>
                    <select id="ruleWebhookType" class="form-control">
                        <option value="custom">自定义</option>
                        <option value="dingtalk">钉钉</option>
                        <option value="feishu">飞书</option>
                    </select>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('createRuleModal')">取消</button>
                <button class="btn btn-primary" onclick="createRule()">创建</button>
            </div>
        </div>
    </div>

    <!-- 申请邮箱模态框 -->
    <div id="applyMailboxModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>申请新邮箱</h3>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">邮箱地址</label>
                    <input type="email" id="applyEmailAddress" class="form-control" placeholder="example@domain.com">
                </div>
                <div class="form-group">
                    <label class="form-label">申请理由（可选）</label>
                    <textarea id="applyReason" class="form-control" rows="3" placeholder="请简述申请此邮箱的理由..."></textarea>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('applyMailboxModal')">取消</button>
                <button class="btn btn-primary" onclick="submitMailboxApplication()">提交申请</button>
            </div>
        </div>
    </div>

    <!-- 创建邮箱模态框（管理员） -->
    <div id="createMailboxModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>创建邮箱</h3>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">用户ID</label>
                    <input type="number" id="createMailboxUserId" class="form-control" placeholder="输入用户ID">
                </div>
                <div class="form-group">
                    <label class="form-label">邮箱地址</label>
                    <input type="email" id="createMailboxAddress" class="form-control" placeholder="example@domain.com">
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('createMailboxModal')">取消</button>
                <button class="btn btn-primary" onclick="createMailbox()">创建</button>
            </div>
        </div>
    </div>

    <!-- 处理申请模态框（管理员） -->
    <div id="processApplicationModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>处理申请</h3>
            </div>
            <div class="modal-body">
                <div id="applicationDetails"></div>
                <div class="form-group">
                    <label class="form-label">管理员备注（可选）</label>
                    <textarea id="adminComment" class="form-control" rows="3" placeholder="处理说明..."></textarea>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('processApplicationModal')">取消</button>
                <button class="btn btn-danger" onclick="processApplication('reject')">拒绝</button>
                <button class="btn btn-success" onclick="processApplication('approve')">批准</button>
            </div>
        </div>
    </div>
    `;
}

/**
 * 获取完整的 HTML 模板
 */
export async function getHTMLTemplate(): Promise<string> {
    const version = new Date().getTime(); // 用于缓存控制
    
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    ${getHTMLHead()}
</head>
<body>
    ${getSidebar()}
    
    <div class="container">
        ${getLoginSection()}
        ${getMainSection()}
    </div>
    
    ${getModals()}
    
    <script data-version="${version}">
        // 通用邮件列表渲染函数和工具函数
        ${getEmailListRenderer()}
        
        // 配置管理器
        ${AppConfig}
        
        // 主应用逻辑
        ${await getJavaScript()}
        
        // 初始化应用
        document.addEventListener('DOMContentLoaded', async function() {
            console.log('应用初始化...');
            
            // 初始化配置
            await ConfigManager.init();
            
            // 检查登录状态
            const token = localStorage.getItem('${STORAGE_KEYS.AUTH_TOKEN}') || localStorage.getItem('token'); // 兼容旧版本
            if (token) {
                // 验证 token 并显示主界面
                // 等待 AuthManager 初始化完成后再检查认证
                if (window.AuthManager) {
                    await window.AuthManager.checkAuth();
                } else {
                    // 如果 AuthManager 还未初始化，等待一下再尝试
                    setTimeout(async () => {
                        if (window.AuthManager) {
                            await window.AuthManager.checkAuth();
                        }
                    }, 100);
                }
            } else {
                // 没有 token，确保侧边栏隐藏
                const sidebar = document.getElementById('sidebar');
                if (sidebar) {
                    sidebar.classList.add('hidden');
                }
            }
        });
    </script>
</body>
</html>`;
}