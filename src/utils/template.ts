/**
 * 模板工具 - 生成前端HTML
 */

import { getStyles } from '../static/styles';
import { getJavaScript } from '../static/app';

/**
 * 获取完整的HTML模板
 */
export async function getTemplate(): Promise<string> {
    const styles = await getStyles();
    const javascript = await getJavaScript();
    
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>临时邮箱管理系统</title>
    <style>
        ${styles}
    </style>
</head>
<body>
    <!-- 侧边栏 -->
    <div id="sidebar" class="sidebar">
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

    <div class="container">
        <div class="header">
            <h1>临时邮箱管理系统</h1>
            <p>现代化的邮件管理解决方案</p>
        </div>

        <!-- 登录注册界面 -->
        <div id="loginSection" class="card">
            <div class="tabs">
                <button class="tab active" onclick="switchTab('login')">登录</button>
                <button id="registerTab" class="tab" onclick="switchTab('register')">注册</button> 
            </div>

            <div id="loginForm" class="tab-content active">
                <div class="form-group">
                    <label for="loginPrefix">邮箱前缀</label>
                    <input type="text" id="loginPrefix" class="form-control" placeholder="请输入邮箱前缀">
                </div>
                <div class="form-group">
                    <label for="loginPassword">邮箱密码</label>
                    <input type="password" id="loginPassword" class="form-control" placeholder="请输入邮箱密码">
                </div>
                <button class="btn btn-primary" onclick="login()">登录</button>
            </div>

            <div id="registerForm" class="tab-content">
                <div class="form-group">
                    <label for="registerPassword">邮箱密码</label>
                    <input type="password" id="registerPassword" class="form-control" placeholder="设置邮箱密码（至少6位）">
                </div>
                <button class="btn btn-primary" onclick="register()">注册</button>
                <p style="margin-top: 15px; color: #6c757d; font-size: 0.9rem;">
                    注册成功后将为您分配一个随机邮箱前缀
                </p>
            </div>
        </div>

        <!-- 主界面 -->
        <div id="mainSection" class="main-content hidden">
            <!-- 顶部栏 -->
            <div class="top-bar">
                <div>
                    <button class="btn btn-secondary btn-sm" onclick="toggleSidebar()">☰ 菜单</button>
                </div>
                <div class="user-info" onclick="showSection('settings')" style="cursor: pointer; transition: all 0.3s ease;" onmouseover="this.style.backgroundColor='#f8f9fa'" onmouseout="this.style.backgroundColor='transparent'">
                    <div class="user-avatar" id="userAvatar">U</div>
                    <div>
                        <div id="userEmail" style="font-weight: 600;"></div>
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
                <div id="emailList">加载中...</div>
                <div id="emailPagination" style="margin-top: 20px; text-align: center;"></div>
            </div>

            <!-- 用户设置 -->
            <div id="settingsSection" class="card hidden">
                <h2>账户设置</h2>
                <form id="settingsForm">
                    <div class="form-group">
                        <label for="settingsPassword">新密码（留空表示不修改）</label>
                        <input type="password" id="settingsPassword" class="form-control" placeholder="输入新密码">
                    </div>
                    <div class="form-group">
                        <label for="settingsWebhookUrl">Webhook URL</label>
                        <input type="url" id="settingsWebhookUrl" class="form-control" placeholder="https://example.com/webhook">
                    </div>
                    <div class="form-group">
                        <label for="settingsWebhookSecret">Webhook 签名密钥</label>
                        <input type="text" id="settingsWebhookSecret" class="form-control" placeholder="用于验证webhook的密钥">
                    </div>
                    <button type="button" class="btn btn-primary" onclick="updateSettings()">保存设置</button>
                    <button type="button" class="btn btn-secondary" onclick="refreshData()" style="margin-left: 10px;">🔄 刷新数据</button>
                </form>
            </div>

            <!-- 管理员：用户管理 -->
            <div id="adminUsersSection" class="card hidden">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2>用户管理</h2>
                    <button class="btn btn-success btn-sm" onclick="showCreateUserModal()">➕ 创建用户</button>
                </div>
                <div class="search-box">
                    <input type="text" class="search-input" placeholder="搜索用户..." id="userSearch">
                    <span class="search-icon">🔍</span>
                </div>
                <div id="usersList">加载中...</div>
            </div>

            <!-- 管理员：转发规则 -->
            <div id="adminRulesSection" class="card hidden">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2>转发规则管理</h2>
                    <button class="btn btn-success btn-sm" onclick="showCreateRuleModal()">➕ 创建规则</button>
                </div>
                <div id="rulesList">加载中...</div>
            </div>

            <!-- 管理员：全部邮件 -->
            <div id="adminEmailsSection" class="card hidden">
                <h2>全部邮件管理</h2>
                <div class="form-row">
                    <div class="form-col">
                        <input type="text" class="form-control" placeholder="搜索内容..." id="adminEmailSearch">
                    </div>
                    <div class="form-col">
                        <input type="text" class="form-control" placeholder="发件人..." id="adminSenderSearch">
                    </div>
                    <div class="form-col">
                        <select class="form-control" id="adminAttachmentFilter">
                            <option value="">全部邮件</option>
                            <option value="true">有附件</option>
                            <option value="false">无附件</option>
                        </select>
                    </div>
                </div>
                <div id="adminEmailsList">加载中...</div>
            </div>

            <!-- 管理员：系统设置 -->
            <div id="adminSettingsSection" class="card hidden">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2>🛠️ 系统设置</h2>
                    <button class="btn btn-secondary btn-sm" onclick="loadSystemSettings()">🔄 重新加载</button>
                </div>
                <div id="systemSettingsForm">加载中...</div>
            </div>

            <!-- 调试模式 -->
            <div id="debugSection" class="card hidden">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2>🐛 调试模式</h2>
                    <span class="badge" style="background-color: #dc3545; color: white;">仅调试模式可用</span>
                </div>
                
                <div class="card" style="background-color: #fff3cd; border: 1px solid #ffeaa7; margin-bottom: 20px;">
                    <h3 style="color: #856404;">📧 模拟邮件接收</h3>
                    <p style="color: #856404; margin-bottom: 15px;">在调试模式下，您可以模拟接收邮件来测试系统功能。</p>
                    
                    <form id="simulateEmailForm" style="margin-bottom: 0;">
                        <div class="form-row">
                            <div class="form-col">
                                <div class="form-group">
                                    <label for="simFromEmail">发件人邮箱</label>
                                    <input type="email" id="simFromEmail" class="form-control" placeholder="sender@example.com" required>
                                </div>
                            </div>
                            <div class="form-col">
                                <div class="form-group">
                                    <label for="simToEmail">收件人邮箱</label>
                                    <input type="email" id="simToEmail" class="form-control" placeholder="user@your-domain.com" required>
                                </div>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label for="simSubject">邮件主题</label>
                            <input type="text" id="simSubject" class="form-control" placeholder="测试邮件主题" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="simTextContent">纯文本内容</label>
                            <textarea id="simTextContent" class="form-control" rows="4" placeholder="这是一封测试邮件的纯文本内容..."></textarea>
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
                        <p style="color: #0c5460;">最近模拟邮件: <span id="lastSimulatedEmail">无</span></p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- 模态框：创建用户 -->
    <div id="createUserModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">创建用户</h3>
                <button class="close-btn" onclick="closeModal('createUserModal')">&times;</button>
            </div>
            <form id="createUserForm">
                <div class="form-group">
                    <label for="newUserPassword">密码</label>
                    <input type="password" id="newUserPassword" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="newUserType">用户类型</label>
                    <select id="newUserType" class="form-control">
                        <option value="user">普通用户</option>
                        <option value="admin">管理员</option>
                    </select>
                </div>
                <button type="button" class="btn btn-primary" onclick="createUser()">创建用户</button>
            </form>
        </div>
    </div>

    <!-- 模态框：创建转发规则 -->
    <div id="createRuleModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">创建转发规则</h3>
                <button class="close-btn" onclick="closeModal('createRuleModal')">&times;</button>
            </div>
            <form id="createRuleForm">
                <div class="form-group">
                    <label for="newRuleName">规则名称</label>
                    <input type="text" id="newRuleName" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="newRuleWebhookUrl">Webhook URL</label>
                    <input type="url" id="newRuleWebhookUrl" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="newRuleWebhookType">Webhook 类型</label>
                    <select id="newRuleWebhookType" class="form-control">
                        <option value="custom">自定义</option>
                        <option value="dingtalk">钉钉</option>
                        <option value="feishu">飞书</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="newRuleSenderFilter">发件人过滤器（可选）</label>
                    <input type="text" id="newRuleSenderFilter" class="form-control" placeholder="例：@gmail.com">
                </div>
                <div class="form-group">
                    <label for="newRuleKeywordFilter">关键字过滤器（可选）</label>
                    <input type="text" id="newRuleKeywordFilter" class="form-control" placeholder="例：重要">
                </div>
                <div class="form-group">
                    <label for="newRuleWebhookSecret">Webhook 签名密钥（可选）</label>
                    <input type="text" id="newRuleWebhookSecret" class="form-control">
                </div>
                <button type="button" class="btn btn-primary" onclick="createRule()">创建规则</button>
            </form>
        </div>
    </div>

    <!-- 邮件详情模态框 -->
    <div id="emailDetailModal" class="modal">
        <div class="modal-content large">
            <div class="modal-header">
                <h3 class="modal-title">邮件详情</h3>
                <button class="close-btn" onclick="closeModal('emailDetailModal')">&times;</button>
            </div>
            <div id="emailDetailContent">
                <p>加载中...</p>
            </div>
        </div>
    </div>

    <script>
        ${javascript}
    </script>
</body>
</html>`;
}