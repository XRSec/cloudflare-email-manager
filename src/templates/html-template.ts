/**
 * HTML 模板模块
 * 主要的 HTML 结构
 */

import { getStyleTag } from '../static/styles';
import { AppConfig } from '../static/app-config';
import { getJavaScript } from '../static/app';

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
            <div class="sidebar-item active" onclick="showSection('emails')">📧 我的邮件</div>
            <div class="sidebar-item" onclick="showSection('settings')">⚙️ 账户设置</div>
            <div id="debugMenuItem" class="sidebar-item hidden" onclick="showSection('debug')">🐛 调试模式</div>
            <div id="adminMenuItems" class="hidden">
                <div class="sidebar-item" onclick="showSection('admin-users')">👥 用户管理</div>
                <div class="sidebar-item" onclick="showSection('admin-rules')">🔄 转发规则</div>
                <div class="sidebar-item" onclick="showSection('admin-emails')">📨 全部邮件</div>
                <div class="sidebar-item" onclick="showSection('admin-settings')">🛠️ 系统设置</div>
            </div>
            <div class="sidebar-item" onclick="logout()" style="margin-top: 20px; color: #dc3545;">🚪 退出登录</div>
        </div>
    </div>
    `;
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
        <div id="emailsSection" class="card">
            <h2>我的邮件</h2>
            <div class="search-box">
                <input type="text" class="search-input" placeholder="搜索邮件..." id="emailSearch">
                <span class="search-icon">🔍</span>
            </div>
            <div id="emailList" class="loading">加载中</div>
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
            <h2>全部邮件管理</h2>
            <div id="adminEmailsList" class="loading">加载中</div>
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
            
            <div class="card" style="background-color: #fff3cd; border: 1px solid #ffeaa7; margin-bottom: 20px;">
                <h3 style="color: #856404;">📧 模拟邮件接收</h3>
                <p style="color: #856404; margin-bottom: 15px;">在调试模式下，您可以模拟接收邮件来测试系统功能。</p>
                
                <form id="simulateEmailForm" style="margin-bottom: 0;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                        <div class="form-group">
                            <label for="simFromEmail" class="form-label">发件人邮箱</label>
                            <input type="email" id="simFromEmail" class="form-control" placeholder="sender@example.com" required>
                        </div>
                        <div class="form-group">
                            <label for="simToEmail" class="form-label">收件人邮箱</label>
                            <input type="email" id="simToEmail" class="form-control" placeholder="user@your-domain.com" required>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="simSubject" class="form-label">邮件主题</label>
                        <input type="text" id="simSubject" class="form-control" placeholder="测试邮件主题" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="simTextContent" class="form-label">纯文本内容</label>
                        <textarea id="simTextContent" class="form-control" rows="4" placeholder="这是一封测试邮件的纯文本内容..."></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label for="simHtmlContent" class="form-label">HTML内容（可选）</label>
                        <textarea id="simHtmlContent" class="form-control" rows="4" placeholder="<p>这是一封<strong>测试邮件</strong>的HTML内容...</p>"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <button type="button" class="btn btn-primary" onclick="simulateEmailReceive()">
                            📨 模拟接收邮件
                        </button>
                        <button type="button" class="btn btn-secondary" onclick="clearSimulateForm()">
                            🗑️ 清空表单
                        </button>
                    </div>
                </form>
            </div>
            
            <div class="card" style="background-color: #d1ecf1; border: 1px solid #bee5eb;">
                <h3 style="color: #0c5460;">📊 调试信息</h3>
                <div id="debugInfo">
                    <p style="color: #0c5460;">调试模式状态: <span id="debugModeStatus">检测中...</span></p>
                    <p style="color: #0c5460;">当前用户: <span id="debugCurrentUser">加载中...</span></p>
                    <p style="color: #0c5460;">系统配置: <span id="debugSystemConfig">加载中...</span></p>
                    <p style="color: #0c5460;">最近模拟邮件: <span id="lastSimulatedEmail">无</span></p>
                </div>
                
                <div class="form-group" style="margin-top: 15px;">
                    <button type="button" class="btn btn-info btn-sm" onclick="refreshDebugInfo()">
                        🔄 刷新调试信息
                    </button>
                    <button type="button" class="btn btn-warning btn-sm" onclick="clearDebugLogs()">
                        🗑️ 清空调试日志
                    </button>
                </div>
            </div>
        </div>
    </div>
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
                    <label class="form-label">邮箱前缀</label>
                    <input type="text" id="createUserPrefix" class="form-control" placeholder="用户邮箱前缀">
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
            const token = localStorage.getItem('cem_persist_token') || localStorage.getItem('token'); // 兼容旧版本
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