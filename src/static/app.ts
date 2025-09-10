/**
 * 前端应用JavaScript代码生成器
 */

export async function getJavaScript(): Promise<string> {
    return `
// =============================================================================
// 临时邮箱管理系统 - 前端应用
// =============================================================================

// API相关模块
const API = {
    baseURL: '',
    token: null,

    // 发起请求的通用方法
    async request(endpoint, options = {}) {
        const url = this.baseURL + endpoint;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };

        // 添加认证头
        if (this.token) {
            defaultOptions.headers['Authorization'] = 'Bearer ' + this.token;
        }

        const finalOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers,
            },
        };

        try {
            const response = await fetch(url, finalOptions);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'HTTP ' + response.status);
            }

            return data;
        } catch (error) {
            console.error('API请求失败:', error);
            throw error;
        }
    },

    // GET 请求
    async get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    },

    // POST 请求
    async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: data ? JSON.stringify(data) : undefined,
        });
    },

    // PUT 请求
    async put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: data ? JSON.stringify(data) : undefined,
        });
    },

    // DELETE 请求
    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    },

    // 设置认证令牌
    setToken(token) {
        this.token = token;
        if (token) {
            localStorage.setItem('cem_persist_auth_token', token);
            // 清理旧的 token 键
            localStorage.removeItem('auth_token');
        } else {
            localStorage.removeItem('cem_persist_auth_token');
            localStorage.removeItem('auth_token'); // 同时清理旧的键
        }
    },

    // 从存储中恢复令牌
    restoreToken() {
        const token = localStorage.getItem('cem_persist_auth_token') || localStorage.getItem('auth_token'); // 兼容旧版本
        if (token) {
            this.token = token;
        }
    }
};

// 状态管理模块
const State = {
    currentUser: null,
    systemConfig: null,
    currentSection: 'emails',
    sidebarOpen: true, // 默认打开侧边栏

    // 设置当前用户
    setCurrentUser(user) {
        this.currentUser = user;
        this.updateUserUI();
    },

    // 设置系统配置
    setSystemConfig(config) {
        this.systemConfig = config;
        this.updateConfigUI();
    },

    // 更新用户界面
    updateUserUI() {
        if (!this.currentUser) {
            console.log('updateUserUI: 没有当前用户');
            return;
        }

        console.log('updateUserUI: 当前用户', this.currentUser);

        const userEmail = document.getElementById('userEmail');
        const userType = document.getElementById('userType');
        const userAvatar = document.getElementById('userAvatar');
        const sidebarUserInfo = document.getElementById('sidebarUserInfo');

        const domain = this.systemConfig?.domains?.[0] || 'domain.com';

        if (userEmail) {
            userEmail.textContent = this.currentUser.email_prefix + '@' + domain;
        }

        if (userType) {
            userType.textContent = this.currentUser.user_type === 'admin' ? '管理员' : '普通用户';
        }

        if (userAvatar) {
            userAvatar.textContent = this.currentUser.email_prefix.charAt(0).toUpperCase();
        }

        if (sidebarUserInfo) {
            sidebarUserInfo.textContent = this.currentUser.email_prefix + ' (' +
                (this.currentUser.user_type === 'admin' ? '管理员' : '用户') + ')';
        }

        // 显示/隐藏管理员菜单
        const adminMenuItems = document.getElementById('adminMenuItems');
        console.log('管理员菜单元素:', adminMenuItems, '用户类型:', this.currentUser.user_type);
        
        if (adminMenuItems) {
            if (this.currentUser.user_type === 'admin') {
                adminMenuItems.classList.remove('hidden');
                console.log('已显示管理员菜单');
            } else {
                adminMenuItems.classList.add('hidden');
                console.log('已隐藏管理员菜单');
            }
        }
    },

    // 更新配置界面
    updateConfigUI() {
        if (!this.systemConfig) return;

        // 显示/隐藏注册按钮
        const registerTab = document.getElementById('registerTab');
        if (registerTab) {
            if (this.systemConfig.allow_registration) {
                registerTab.style.display = 'block';
            } else {
                registerTab.style.display = 'none';
            }
        }

        // 显示/隐藏调试菜单
        const debugMenuItem = document.getElementById('debugMenuItem');
        if (debugMenuItem) {
            if (this.systemConfig.debug_mode) {
                debugMenuItem.classList.remove('hidden');
            } else {
                debugMenuItem.classList.add('hidden');
            }
        }
    }
};

// UI工具模块
const UI = {
    // 显示消息
    showMessage(message, type = 'info') {
        // 创建消息元素
        const messageEl = document.createElement('div');
        messageEl.className = 'message message-' + type;
        messageEl.textContent = message;

        // 添加样式
        Object.assign(messageEl.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            padding: '12px 20px',
            borderRadius: '8px',
            color: 'white',
            fontWeight: '600',
            zIndex: '3000',
            opacity: '0',
            transform: 'translateY(-20px)',
            transition: 'all 0.3s ease',
            maxWidth: '400px',
            boxShadow: '0 4px 20px rgba(0,0,0,0.2)'
        });

        // 设置背景色
        switch (type) {
            case 'success':
                messageEl.style.background = 'linear-gradient(135deg, #28a745, #20c997)';
                break;
            case 'error':
                messageEl.style.background = 'linear-gradient(135deg, #dc3545, #e83e8c)';
                break;
            default:
                messageEl.style.background = 'linear-gradient(135deg, #667eea, #764ba2)';
                break;
        }

        // 添加到页面
        document.body.appendChild(messageEl);

        // 显示动画
        setTimeout(() => {
            messageEl.style.opacity = '1';
            messageEl.style.transform = 'translateY(0)';
        }, 100);

        // 自动消失
        setTimeout(() => {
            messageEl.style.opacity = '0';
            messageEl.style.transform = 'translateY(-20px)';
            setTimeout(() => {
                if (document.body.contains(messageEl)) {
                    document.body.removeChild(messageEl);
                }
            }, 300);
        }, 3000);
    },

    // 显示加载状态
    showLoading(element, text = '加载中...') {
        element.innerHTML = '<div class="loading">' + text + '</div>';
    },

    // 显示模态框
    showModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('show');
            modal.style.display = 'flex';
        }
    },

    // 隐藏模态框
    hideModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('show');
            modal.style.display = 'none';
        }
    },

    // 切换侧边栏
    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        const mainContent = document.querySelector('.main-content');

        if (sidebar && mainContent) {
            State.sidebarOpen = !State.sidebarOpen;

            if (State.sidebarOpen) {
                sidebar.classList.add('open');
                mainContent.classList.add('sidebar-open');
            } else {
                sidebar.classList.remove('open');
                mainContent.classList.remove('sidebar-open');
            }
        }
    },

    // 确保侧边栏打开
    openSidebar() {
        const sidebar = document.getElementById('sidebar');
        const mainContent = document.querySelector('.main-content');

        if (sidebar && mainContent) {
            // 显示侧边栏（移除 hidden 类）
            sidebar.classList.remove('hidden');
            
            if (!State.sidebarOpen) {
                State.sidebarOpen = true;
                sidebar.classList.add('open');
                mainContent.classList.add('sidebar-open');
            }
        }
    },

    // 确保侧边栏关闭
    closeSidebar() {
        const sidebar = document.getElementById('sidebar');
        const mainContent = document.querySelector('.main-content');

        if (sidebar && mainContent) {
            // 隐藏侧边栏（添加 hidden 类）
            sidebar.classList.add('hidden');
            
            if (State.sidebarOpen) {
                State.sidebarOpen = false;
                sidebar.classList.remove('open');
                mainContent.classList.remove('sidebar-open');
            }
        }
    },

    // 显示页面部分
    showSection(sectionName) {
        // ID 映射
        const sectionIdMap = {
            'emails': 'emailsSection',
            'settings': 'settingsSection',
            'admin-users': 'adminUsersSection',
            'admin-rules': 'adminRulesSection',
            'admin-emails': 'adminEmailsSection',
            'admin-settings': 'adminSettingsSection'
        };

        const targetSectionId = sectionIdMap[sectionName] || (sectionName + 'Section');

        // 隐藏所有部分
        const sections = document.querySelectorAll('.card');
        sections.forEach(section => {
            if (section.id && section.id.includes('Section')) {
                section.classList.add('hidden');
            }
        });

        // 显示指定部分
        const targetSection = document.getElementById(targetSectionId);
        if (targetSection) {
            targetSection.classList.remove('hidden');
        }

        // 更新侧边栏激活状态
        const sidebarItems = document.querySelectorAll('.sidebar-item');
        sidebarItems.forEach(item => {
            item.classList.remove('active');
        });

        // 找到对应的菜单项并激活
        const menuItem = document.querySelector('[onclick="showSection(\\''+sectionName+'\\')"]');
        if (menuItem) {
            menuItem.classList.add('active');
        }

        // 设置当前状态
        State.currentSection = sectionName;

        // 加载对应数据
        this.loadSectionData(sectionName);

        // 在移动端关闭侧边栏
        if (window.innerWidth <= 768 && State.sidebarOpen) {
            this.toggleSidebar();
        }
    },

    // 加载部分数据
    async loadSectionData(sectionName) {
        switch (sectionName) {
            case 'emails':
                await EmailManager.loadEmails();
                break;
            case 'settings':
                await UserManager.loadSettings();
                break;
            case 'admin-users':
                if (State.currentUser?.user_type === 'admin') {
                    await AdminManager.loadUsers();
                }
                break;
            case 'admin-rules':
                if (State.currentUser?.user_type === 'admin') {
                    await AdminManager.loadForwardRules();
                }
                break;
            case 'admin-emails':
                if (State.currentUser?.user_type === 'admin') {
                    await AdminManager.loadAllEmails();
                }
                break;
            case 'admin-settings':
                if (State.currentUser?.user_type === 'admin') {
                    await AdminManager.loadSystemSettings();
                }
                break;
            case 'debug':
                if (State.systemConfig?.debug_mode) {
                    await DebugManager.loadDebugInfo();
                }
                break;
        }
    }
};

// 认证管理模块
const AuthManager = {
    // 登录
    async login() {
        const prefixInput = document.getElementById('loginPrefix');
        const passwordInput = document.getElementById('loginPassword');

        if (!prefixInput?.value || !passwordInput?.value) {
            UI.showMessage('请填写邮箱前缀和密码', 'error');
            return;
        }

        try {
            const response = await API.post('/api/login', {
                email_prefix: prefixInput.value.trim(),
                email_password: passwordInput.value
            });

            if (response.success) {
                API.setToken(response.data.token);
                State.setCurrentUser(response.data.user);

                // 显示主界面
                document.getElementById('loginSection')?.classList.add('hidden');
                document.getElementById('mainSection')?.classList.remove('hidden');

                UI.showMessage('登录成功', 'success');

                // 加载系统配置
                await this.loadSystemConfig();

                // 默认打开侧边栏并显示邮件列表
                UI.openSidebar();
                UI.showSection('emails');
            }
        } catch (error) {
            UI.showMessage(error.message || '登录失败', 'error');
        }
    },

    // 注册
    async register() {
        const passwordInput = document.getElementById('registerPassword');

        if (!passwordInput?.value) {
            UI.showMessage('请填写密码', 'error');
            return;
        }

        if (passwordInput.value.length < 6) {
            UI.showMessage('密码长度至少为6位', 'error');
            return;
        }

        try {
            const response = await API.post('/api/register', {
                email_password: passwordInput.value
            });

            if (response.success) {
                UI.showMessage('注册成功！您的邮箱前缀是：' + response.data.email_prefix, 'success');

                // 自动填入登录表单
                const loginPrefixInput = document.getElementById('loginPrefix');
                if (loginPrefixInput) {
                    loginPrefixInput.value = response.data.email_prefix;
                }

                // 切换到登录标签
                this.switchTab('login');
            }
        } catch (error) {
            UI.showMessage(error.message || '注册失败', 'error');
        }
    },

    // 登出
    async logout() {
        try {
            await API.post('/api/logout');
        } catch (error) {
            console.warn('登出请求失败:', error);
        }

        // 清除本地状态
        API.setToken(null);
        State.setCurrentUser(null);

        // 关闭侧边栏
        UI.closeSidebar();

        // 显示登录界面
        document.getElementById('mainSection')?.classList.add('hidden');
        document.getElementById('loginSection')?.classList.remove('hidden');

        UI.showMessage('已退出登录', 'info');
    },

    // 检查登录状态
    async checkAuth() {
        API.restoreToken();

        if (!API.token) {
            return false;
        }

        try {
            const response = await API.get('/api/protected/me');
            if (response.success) {
                State.setCurrentUser(response.data);
                await this.loadSystemConfig();
                return true;
            }
        } catch (error) {
            console.warn('认证检查失败:', error);
            API.setToken(null);
        }

        return false;
    },

    // 加载系统配置
    async loadSystemConfig() {
        try {
            const response = await API.get('/api/system/config');
            if (response.success) {
                State.setSystemConfig(response.data.config);
            }
        } catch (error) {
            console.warn('加载系统配置失败:', error);
        }
    },

    // 切换标签
    switchTab(tabName) {
        // 隐藏所有标签内容
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });

        // 移除所有标签的激活状态
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
        });

        // 显示指定标签内容
        const targetContent = document.getElementById(tabName + 'Form');
        if (targetContent) {
            targetContent.classList.add('active');
        }

        // 激活对应标签
        const targetTab = document.querySelector('[onclick="switchTab(\\''+tabName+'\\')"]');
        if (targetTab) {
            targetTab.classList.add('active');
        }
    }
};

// 邮件管理模块
const EmailManager = {
    currentPage: 1,
    pageSize: 20,

    // 加载邮件列表
    async loadEmails(page = 1) {
        this.currentPage = page;
        const emailList = document.getElementById('emailList');

        if (!emailList) return;

        UI.showLoading(emailList);

        try {
            const response = await API.get('/api/protected/emails?page=' + page + '&limit=' + this.pageSize);

            if (response.success) {
                this.renderEmailList(response.data.emails);
                this.renderPagination(response.data.total, response.data.page, response.data.limit);
            }
        } catch (error) {
            emailList.innerHTML = '<p>加载邮件失败: ' + (error.message || '未知错误') + '</p>';
        }
    },

    // 渲染邮件列表
    renderEmailList(emails) {
        const emailList = document.getElementById('emailList');
        if (!emailList) return;

        if (emails.length === 0) {
            emailList.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 40px;">暂无邮件</p>';
            return;
        }

        const emailsHtml = emails.map(email =>
            '<div class="email-item" onclick="EmailManager.showEmailDetail(' + email.id + ')">' +
                '<div class="email-header">' +
                    '<div class="email-sender">' + this.escapeHtml(email.sender_email) + '</div>' +
                    '<div class="email-time">' + this.formatDate(email.received_at) + '</div>' +
                '</div>' +
                '<div class="email-subject">' + this.escapeHtml(email.subject || '(无主题)') + '</div>' +
                '<div class="email-preview">' + this.escapeHtml((email.text_content || '(无内容)').substring(0, 100)) +
                    (email.text_content && email.text_content.length > 100 ? '...' : '') + '</div>' +
                (email.has_attachments ? '<div class="email-attachments">📎 有附件</div>' : '') +
            '</div>'
        ).join('');

        emailList.innerHTML = emailsHtml;
    },

    // 渲染分页
    renderPagination(total, currentPage, pageSize) {
        const pagination = document.getElementById('emailPagination');
        if (!pagination) return;

        const totalPages = Math.ceil(total / pageSize);

        if (totalPages <= 1) {
            pagination.innerHTML = '';
            return;
        }

        let paginationHtml = '<div class="pagination">';

        // 上一页
        paginationHtml += '<button ' + (currentPage <= 1 ? 'disabled' : '') +
            ' onclick="EmailManager.loadEmails(' + (currentPage - 1) + ')">上一页</button>';

        // 页码
        for (let i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
            paginationHtml += '<button class="' + (i === currentPage ? 'active' : '') +
                '" onclick="EmailManager.loadEmails(' + i + ')">' + i + '</button>';
        }

        // 下一页
        paginationHtml += '<button ' + (currentPage >= totalPages ? 'disabled' : '') +
            ' onclick="EmailManager.loadEmails(' + (currentPage + 1) + ')">下一页</button>';

        paginationHtml += '</div>';

        // 添加信息
        paginationHtml += '<div class="pagination-info">共 ' + total + ' 封邮件，第 ' +
            currentPage + ' 页，共 ' + totalPages + ' 页</div>';

        pagination.innerHTML = paginationHtml;
    },

    // 显示邮件详情
    async showEmailDetail(emailId) {
        try {
            const response = await API.get('/api/protected/emails/' + emailId);

            if (response.success) {
                const email = response.data;
                const modalContent = document.getElementById('emailDetailContent');

                if (modalContent) {
                    let attachmentsHtml = '';
                    if (email.attachments && email.attachments.length > 0) {
                        attachmentsHtml = '<div style="margin-bottom: 20px;">' +
                            '<strong>附件:</strong>' +
                            '<div style="margin-top: 10px;">' +
                            email.attachments.map(att =>
                                '<div style="display: flex; justify-content: space-between; align-items: center; padding: 8px; background: #f8f9fa; border-radius: 4px; margin-bottom: 5px;">' +
                                    '<span>📎 ' + this.escapeHtml(att.filename) + ' (' + this.formatFileSize(att.size_bytes) + ')</span>' +
                                    '<button class="btn btn-primary btn-sm" onclick="EmailManager.downloadAttachment(' + att.id + ')">下载</button>' +
                                '</div>'
                            ).join('') +
                            '</div>' +
                        '</div>';
                    }

                    modalContent.innerHTML =
                        '<div style="margin-bottom: 20px;">' +
                            '<div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px;">' +
                                '<div>' +
                                    '<strong>发件人:</strong> ' + this.escapeHtml(email.sender_email) + '<br>' +
                                    '<strong>收件人:</strong> ' + this.escapeHtml(email.recipient_email) + '<br>' +
                                    '<strong>主题:</strong> ' + this.escapeHtml(email.subject || '(无主题)') + '<br>' +
                                    '<strong>时间:</strong> ' + this.formatDate(email.received_at) +
                                '</div>' +
                                '<button class="btn btn-danger btn-sm" onclick="EmailManager.deleteEmail(' + email.id + ')">删除邮件</button>' +
                            '</div>' +
                        '</div>' +
                        attachmentsHtml +
                        '<div style="border-top: 1px solid #e9ecef; padding-top: 20px;">' +
                            '<strong>邮件内容:</strong>' +
                            '<div style="margin-top: 10px; padding: 15px; background: #f8f9fa; border-radius: 8px; max-height: 400px; overflow-y: auto;">' +
                                (email.html_content ? email.html_content :
                                    '<pre style="white-space: pre-wrap; margin: 0;">' + this.escapeHtml(email.text_content || '(无内容)') + '</pre>') +
                            '</div>' +
                        '</div>';
                }

                UI.showModal('emailDetailModal');
            }
        } catch (error) {
            UI.showMessage(error.message || '获取邮件详情失败', 'error');
        }
    },

    // 删除邮件
    async deleteEmail(emailId) {
        if (!confirm('确定要删除这封邮件吗？')) {
            return;
        }

        try {
            const response = await API.delete('/api/protected/emails/' + emailId);

            if (response.success) {
                UI.showMessage('邮件删除成功', 'success');
                UI.hideModal('emailDetailModal');
                await this.loadEmails(this.currentPage);
            }
        } catch (error) {
            UI.showMessage(error.message || '删除邮件失败', 'error');
        }
    },

    // 下载附件
    async downloadAttachment(attachmentId) {
        try {
            const headers = {};
            if (API.token) {
                headers['Authorization'] = 'Bearer ' + API.token;
            }

            const response = await fetch('/api/protected/attachments/' + attachmentId + '/download', {
                headers: headers
            });

            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }

            const blob = await response.blob();
            const contentDisposition = response.headers.get('content-disposition');
            const filename = contentDisposition ?
                contentDisposition.split('filename=')[1]?.replace(/"/g, '') :
                'attachment_' + attachmentId;

            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);

            UI.showMessage('附件下载开始', 'success');
        } catch (error) {
            UI.showMessage(error.message || '下载附件失败', 'error');
        }
    },

    // HTML转义
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    // 格式化日期
    formatDate(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diffTime = Math.abs(now.getTime() - date.getTime());
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

        if (diffDays === 1) {
            return '今天 ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
        } else if (diffDays === 2) {
            return '昨天 ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
        } else if (diffDays <= 7) {
            return (diffDays - 1) + '天前';
        } else {
            return date.toLocaleDateString('zh-CN') + ' ' +
                date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
        }
    },

    // 格式化文件大小
    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
};

// 用户管理模块
const UserManager = {
    // 加载用户设置
    async loadSettings() {
        try {
            const response = await API.get('/api/protected/settings');

            if (response.success) {
                const settings = response.data;

                // 填充表单
                const webhookUrlInput = document.getElementById('settingsWebhookUrl');
                const webhookSecretInput = document.getElementById('settingsWebhookSecret');

                if (webhookUrlInput) {
                    webhookUrlInput.value = settings.webhook_url || '';
                }

                if (webhookSecretInput) {
                    webhookSecretInput.placeholder = settings.webhook_secret ? '***已设置***' : '用于验证webhook的密钥';
                    webhookSecretInput.value = '';
                }
            }
        } catch (error) {
            UI.showMessage(error.message || '加载设置失败', 'error');
        }
    },

    // 更新设置
    async updateSettings() {
        const passwordInput = document.getElementById('settingsPassword');
        const webhookUrlInput = document.getElementById('settingsWebhookUrl');
        const webhookSecretInput = document.getElementById('settingsWebhookSecret');

        const updates = {};

        if (passwordInput?.value.trim()) {
            if (passwordInput.value.length < 6) {
                UI.showMessage('密码长度至少为6位', 'error');
                return;
            }
            updates.email_password = passwordInput.value;
        }

        if (webhookUrlInput?.value.trim()) {
            updates.webhook_url = webhookUrlInput.value.trim();
        } else {
            updates.webhook_url = '';
        }

        if (webhookSecretInput?.value.trim()) {
            updates.webhook_secret = webhookSecretInput.value.trim();
        } else if (webhookSecretInput?.value === '') {
            updates.webhook_secret = '';
        }

        if (Object.keys(updates).length === 0) {
            UI.showMessage('没有需要更新的内容', 'error');
            return;
        }

        try {
            const response = await API.put('/api/protected/settings', updates);

            if (response.success) {
                UI.showMessage('设置更新成功', 'success');

                // 清空密码字段
                if (passwordInput) {
                    passwordInput.value = '';
                }

                // 重新加载设置
                await this.loadSettings();
            }
        } catch (error) {
            UI.showMessage(error.message || '更新设置失败', 'error');
        }
    }
};

// 管理员管理模块
const AdminManager = {
    // 加载用户列表
    async loadUsers() {
        const usersList = document.getElementById('usersList');
        if (!usersList) return;

        UI.showLoading(usersList);

        try {
            const response = await API.get('/api/admin/users');
            if (response.success) {
                this.renderUsersList(response.data.users);
            }
        } catch (error) {
            usersList.innerHTML = '<p>加载用户列表失败: ' + (error.message || '未知错误') + '</p>';
        }
    },

    // 渲染用户列表
    renderUsersList(users) {
        const usersList = document.getElementById('usersList');
        if (!usersList) return;

        if (users.length === 0) {
            usersList.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 40px;">暂无用户</p>';
            return;
        }

        const usersHtml = '<div class="table-responsive"><table class="table">' +
            '<thead><tr><th>用户前缀</th><th>用户类型</th><th>Webhook</th><th>创建时间</th><th>操作</th></tr></thead>' +
            '<tbody>' +
            users.map(user =>
                '<tr>' +
                    '<td>' + this.escapeHtml(user.email_prefix) + '</td>' +
                    '<td><span class="badge ' + (user.user_type === 'admin' ? 'badge-admin' : 'badge-user') + '">' +
                        (user.user_type === 'admin' ? '管理员' : '用户') + '</span></td>' +
                    '<td>' + (user.webhook_url ? '✅ 已配置' : '❌ 未配置') + '</td>' +
                    '<td>' + this.formatDate(user.created_at) + '</td>' +
                    '<td>' +
                        '<button class="btn btn-sm btn-primary" onclick="AdminManager.sendUserInfo(' + user.id + ')">发送信息</button> ' +
                        (user.user_type !== 'admin' ? '<button class="btn btn-sm btn-danger" onclick="AdminManager.deleteUser(' + user.id + ')">删除</button>' : '') +
                    '</td>' +
                '</tr>'
            ).join('') +
            '</tbody></table></div>';

        usersList.innerHTML = usersHtml;
    },

    // 加载转发规则
    async loadForwardRules() {
        const rulesList = document.getElementById('rulesList');
        if (!rulesList) return;

        UI.showLoading(rulesList);

        try {
            const response = await API.get('/api/admin/forward-rules');
            if (response.success) {
                this.renderRulesList(response.data.rules);
            }
        } catch (error) {
            rulesList.innerHTML = '<p>加载转发规则失败: ' + (error.message || '未知错误') + '</p>';
        }
    },

    // 渲染转发规则列表
    renderRulesList(rules) {
        const rulesList = document.getElementById('rulesList');
        if (!rulesList) return;

        if (rules.length === 0) {
            rulesList.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 40px;">暂无转发规则</p>';
            return;
        }

        const rulesHtml = '<div class="table-responsive"><table class="table">' +
            '<thead><tr><th>规则名称</th><th>类型</th><th>过滤条件</th><th>状态</th><th>操作</th></tr></thead>' +
            '<tbody>' +
            rules.map(rule =>
                '<tr>' +
                    '<td>' + this.escapeHtml(rule.rule_name) + '</td>' +
                    '<td><span class="badge badge-' + rule.webhook_type + '">' +
                        (rule.webhook_type === 'dingtalk' ? '钉钉' : rule.webhook_type === 'feishu' ? '飞书' : '自定义') + '</span></td>' +
                    '<td>' +
                        (rule.sender_filter ? '发件人: ' + this.escapeHtml(rule.sender_filter) + '<br>' : '') +
                        (rule.keyword_filter ? '关键字: ' + this.escapeHtml(rule.keyword_filter) + '<br>' : '') +
                        (rule.recipient_filter ? '收件人: ' + this.escapeHtml(rule.recipient_filter) : '') +
                    '</td>' +
                    '<td><span class="badge ' + (rule.enabled ? 'badge-success' : 'badge-secondary') + '">' +
                        (rule.enabled ? '启用' : '禁用') + '</span></td>' +
                    '<td>' +
                        '<button class="btn btn-sm btn-warning" onclick="AdminManager.editRule(' + rule.id + ')">编辑</button> ' +
                        '<button class="btn btn-sm btn-danger" onclick="AdminManager.deleteRule(' + rule.id + ')">删除</button>' +
                    '</td>' +
                '</tr>'
            ).join('') +
            '</tbody></table></div>';

        rulesList.innerHTML = rulesHtml;
    },

    // 加载全部邮件
    async loadAllEmails() {
        const adminEmailsList = document.getElementById('adminEmailsList');
        if (!adminEmailsList) return;

        UI.showLoading(adminEmailsList);

        try {
            const response = await API.get('/api/admin/emails');
            if (response.success) {
                this.renderAllEmails(response.data.emails);
            }
        } catch (error) {
            adminEmailsList.innerHTML = '<p>加载邮件列表失败: ' + (error.message || '未知错误') + '</p>';
        }
    },

    // 渲染全部邮件列表
    renderAllEmails(emails) {
        const adminEmailsList = document.getElementById('adminEmailsList');
        if (!adminEmailsList) return;

        if (emails.length === 0) {
            adminEmailsList.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 40px;">暂无邮件</p>';
            return;
        }

        const emailsHtml = emails.map(email =>
            '<div class="email-item" onclick="EmailManager.showEmailDetail(' + email.id + ')">' +
                '<div class="email-header">' +
                    '<div class="email-sender">' + this.escapeHtml(email.sender_email) + ' → ' + this.escapeHtml(email.recipient_email) + '</div>' +
                    '<div class="email-time">' + this.formatDate(email.received_at) + '</div>' +
                '</div>' +
                '<div class="email-subject">' + this.escapeHtml(email.subject || '(无主题)') + '</div>' +
                '<div class="email-preview">' + this.escapeHtml((email.text_content || '(无内容)').substring(0, 100)) +
                    (email.text_content && email.text_content.length > 100 ? '...' : '') + '</div>' +
                (email.has_attachments ? '<div class="email-attachments">📎 有附件</div>' : '') +
            '</div>'
        ).join('');

        adminEmailsList.innerHTML = emailsHtml;
    },

    // 加载系统设置
    async loadSystemSettings() {
        const systemSettingsForm = document.getElementById('systemSettingsForm');
        if (!systemSettingsForm) return;

        UI.showLoading(systemSettingsForm);

        try {
            const response = await API.get('/api/admin/settings');
            if (response.success) {
                this.renderSystemSettings(response.data.config);
            }
        } catch (error) {
            systemSettingsForm.innerHTML = '<p>加载系统设置失败: ' + (error.message || '未知错误') + '</p>';
        }
    },

    // 渲染系统设置表单
    renderSystemSettings(config) {
        const systemSettingsForm = document.getElementById('systemSettingsForm');
        if (!systemSettingsForm) return;

        const settingsHtml = '<form id="systemConfigForm">' +
            '<div class="form-row">' +
                '<div class="form-col">' +
                    '<div class="form-group">' +
                        '<label for="allowRegistration">允许用户注册</label>' +
                        '<select id="allowRegistration" name="allow_registration" class="form-control">' +
                            '<option value="true"' + (config.allow_registration ? ' selected' : '') + '>是</option>' +
                            '<option value="false"' + (!config.allow_registration ? ' selected' : '') + '>否</option>' +
                        '</select>' +
                    '</div>' +
                '</div>' +
                '<div class="form-col">' +
                    '<div class="form-group">' +
                        '<label for="debugMode">调试模式</label>' +
                        '<select id="debugMode" name="debug_mode" class="form-control">' +
                            '<option value="true"' + (config.debug_mode ? ' selected' : '') + '>开启</option>' +
                            '<option value="false"' + (!config.debug_mode ? ' selected' : '') + '>关闭</option>' +
                        '</select>' +
                    '</div>' +
                '</div>' +
            '</div>' +
            '<div class="form-row">' +
                '<div class="form-col">' +
                    '<div class="form-group">' +
                        '<label for="cleanupDays">邮件清理天数</label>' +
                        '<input type="number" id="cleanupDays" name="cleanup_days" class="form-control" value="' + config.cleanup_days + '" min="1" max="365">' +
                    '</div>' +
                '</div>' +
                '<div class="form-col">' +
                    '<div class="form-group">' +
                        '<label for="maxAttachmentSize">最大附件大小 (MB)</label>' +
                        '<input type="number" id="maxAttachmentSize" name="max_attachment_size_mb" class="form-control" value="' + Math.round(config.max_attachment_size / 1024 / 1024) + '" min="1" max="100">' +
                    '</div>' +
                '</div>' +
            '</div>' +
            '<div class="form-group">' +
                '<label for="domains">支持的域名（每行一个）</label>' +
                '<textarea id="domains" name="domains" class="form-control" rows="4" placeholder="example.com">' + config.domains.join('\\n') + '</textarea>' +
            '</div>' +
            '<div class="form-group">' +
                '<label for="jwtSecret">JWT 密钥</label>' +
                '<input type="text" id="jwtSecret" name="jwt_secret" class="form-control" value="' + (config.jwt_secret || '') + '" placeholder="输入新的JWT密钥">' +
            '</div>' +
            '<div class="form-group">' +
                '<label for="adminEmail">管理员邮箱</label>' +
                '<input type="email" id="adminEmail" name="admin_email" class="form-control" value="' + (config.admin_email || '') + '" placeholder="admin@example.com">' +
            '</div>' +
            '<button type="button" class="btn btn-primary" onclick="AdminManager.saveSystemSettings()">保存设置</button>' +
        '</form>';

        systemSettingsForm.innerHTML = settingsHtml;
    },

    // 保存系统设置
    async saveSystemSettings() {
        try {
            const allowRegistration = document.getElementById('allowRegistration').value === 'true';
            const debugMode = document.getElementById('debugMode').value === 'true';
            const cleanupDays = parseInt(document.getElementById('cleanupDays').value);
            const maxAttachmentSize = parseInt(document.getElementById('maxAttachmentSize').value) * 1024 * 1024;
            const domainsText = document.getElementById('domains').value;
            const domains = domainsText.split('\\n').map(d => d.trim()).filter(d => d);

            const config = {
                allow_registration: allowRegistration,
                debug_mode: debugMode,
                cleanup_days: cleanupDays,
                max_attachment_size: maxAttachmentSize,
                domains: domains
            };

            const response = await API.put('/api/admin/settings', config);
            if (response.success) {
                UI.showMessage('系统设置保存成功', 'success');
                // 重新加载系统配置
                await AuthManager.loadSystemConfig();
            }
        } catch (error) {
            UI.showMessage(error.message || '保存系统设置失败', 'error');
        }
    },

    // 发送用户信息
    async sendUserInfo(userId) {
        try {
            const response = await API.post('/api/admin/users/' + userId + '/send-info');
            if (response.success) {
                UI.showMessage('用户信息发送成功', 'success');
            }
        } catch (error) {
            UI.showMessage(error.message || '发送用户信息失败', 'error');
        }
    },

    // 删除用户
    async deleteUser(userId) {
        if (!confirm('确定要删除此用户吗？此操作不可恢复！')) {
            return;
        }

        try {
            const response = await API.delete('/api/admin/users/' + userId);
            if (response.success) {
                UI.showMessage('用户删除成功', 'success');
                await this.loadUsers();
            }
        } catch (error) {
            UI.showMessage(error.message || '删除用户失败', 'error');
        }
    },

    // 删除转发规则
    async deleteRule(ruleId) {
        if (!confirm('确定要删除此转发规则吗？')) {
            return;
        }

        try {
            const response = await API.delete('/api/admin/forward-rules/' + ruleId);
            if (response.success) {
                UI.showMessage('转发规则删除成功', 'success');
                await this.loadForwardRules();
            }
        } catch (error) {
            UI.showMessage(error.message || '删除转发规则失败', 'error');
        }
    },

    // 删除用户
    async deleteUser(userId) {
        if (!confirm('确定要删除此用户吗？')) {
            return;
        }

        try {
            const response = await API.delete('/api/admin/users/' + userId);
            if (response.success) {
                UI.showMessage('用户删除成功', 'success');
                await this.loadUsers();
            }
        } catch (error) {
            UI.showMessage(error.message || '删除用户失败', 'error');
        }
    },

    // 发送用户信息
    async sendUserInfo(userId) {
        if (!confirm('确定要发送用户信息到其邮箱吗？')) {
            return;
        }

        try {
            const response = await API.post('/api/admin/users/' + userId + '/send-info', {});
            if (response.success) {
                UI.showMessage('用户信息已发送', 'success');
            }
        } catch (error) {
            UI.showMessage(error.message || '发送用户信息失败', 'error');
        }
    },

    // 保存系统设置
    async saveSystemSettings() {
        const form = document.getElementById('systemConfigForm');
        if (!form) return;

        const formData = new FormData(form);
        const settings = {};
        
        for (const [key, value] of formData.entries()) {
            // 特殊处理某些字段
            if (key === 'max_attachment_size_mb') {
                settings['max_attachment_size'] = parseInt(value) * 1024 * 1024; // 转换为字节
            } else if (key === 'domains') {
                // 将换行分隔的域名转换为数组
                settings[key] = value.split('\\n').filter(d => d.trim()).map(d => d.trim());
            } else if (key === 'allow_registration' || key === 'debug_mode') {
                // 布尔值转换
                settings[key] = value === 'true';
            } else if (key === 'cleanup_days') {
                // 数字转换
                settings[key] = parseInt(value);
            } else {
                settings[key] = value;
            }
        }

        try {
            const response = await API.put('/api/admin/settings', settings);
            if (response.success) {
                UI.showMessage('系统设置保存成功', 'success');
                await this.loadSystemSettings();
            }
        } catch (error) {
            UI.showMessage(error.message || '保存系统设置失败', 'error');
        }
    },

    // 工具函数
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    },

    formatDate(dateString) {
        if (!dateString) return '-';
        const date = new Date(dateString);
        return date.toLocaleDateString('zh-CN') + ' ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
    }
};

// 调试管理模块（占位符）
const DebugManager = {
    async loadDebugInfo() {
        console.log('TODO: 实现调试信息');
    }
};

// 全局函数绑定
window.login = AuthManager.login.bind(AuthManager);
window.register = AuthManager.register.bind(AuthManager);
window.logout = AuthManager.logout.bind(AuthManager);
window.switchTab = AuthManager.switchTab.bind(AuthManager);
window.showSection = UI.showSection.bind(UI);
window.toggleSidebar = UI.toggleSidebar.bind(UI);
window.updateSettings = UserManager.updateSettings.bind(UserManager);
window.closeModal = UI.hideModal.bind(UI);

// 管理员功能绑定
window.AdminManager = AdminManager;  // 直接暴露 AdminManager 对象
window.loadSystemSettings = AdminManager.loadSystemSettings.bind(AdminManager);
window.saveSystemSettings = AdminManager.saveSystemSettings.bind(AdminManager);
window.showCreateUserModal = function() { UI.showModal('createUserModal'); };
window.showCreateRuleModal = function() { UI.showModal('createRuleModal'); };

// 刷新数据函数
window.refreshData = async function() {
    try {
        await AuthManager.loadSystemConfig();
        UI.showMessage('数据已刷新', 'success');
        await UI.loadSectionData(State.currentSection);
    } catch (error) {
        UI.showMessage('刷新数据失败', 'error');
    }
};

// 应用初始化
async function initApp() {
    try {
        console.log('开始初始化应用...');

        // 初始化侧边栏状态（确保类名正确）
        const sidebar = document.getElementById('sidebar');
        const mainContent = document.querySelector('.main-content');
        if (sidebar && mainContent) {
            sidebar.classList.add('open');
            mainContent.classList.add('sidebar-open');
        }

        // 检查认证状态
        const isAuthenticated = await AuthManager.checkAuth();

        if (isAuthenticated) {
            // 已登录，显示主界面
            const loginSection = document.getElementById('loginSection');
            const mainSection = document.getElementById('mainSection');

            if (loginSection) loginSection.classList.add('hidden');
            if (mainSection) mainSection.classList.remove('hidden');

            // 确保侧边栏打开
            UI.openSidebar();
            UI.showSection('emails');
        } else {
            // 未登录，显示登录界面
            const mainSection = document.getElementById('mainSection');
            const loginSection = document.getElementById('loginSection');

            if (mainSection) mainSection.classList.add('hidden');
            if (loginSection) loginSection.classList.remove('hidden');

            // 加载系统配置（用于显示注册按钮等）
            await AuthManager.loadSystemConfig();
        }

        // 绑定事件监听器
        bindEventListeners();

        console.log('应用初始化完成');
    } catch (error) {
        console.error('应用初始化失败:', error);
        UI.showMessage('应用初始化失败', 'error');
    }
}

// 绑定事件监听器
function bindEventListeners() {
    // 回车键登录
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                window.login();
            }
        });
    }

    // 回车键注册
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                window.register();
            }
        });
    }

    // 点击模态框外部关闭
    document.addEventListener('click', function(e) {
        if (e.target.classList && e.target.classList.contains('modal')) {
            e.target.classList.remove('show');
            e.target.style.display = 'none';
        }
    });

    // ESC键关闭模态框
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            const openModal = document.querySelector('.modal.show');
            if (openModal) {
                openModal.classList.remove('show');
                openModal.style.display = 'none';
            }
        }
    });

    // 搜索功能
    const emailSearch = document.getElementById('emailSearch');
    if (emailSearch) {
        let searchTimeout;
        emailSearch.addEventListener('input', function(e) {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(function() {
                // TODO: 实现搜索功能
                console.log('搜索:', e.target.value);
            }, 500);
        });
    }
}

// 页面加载完成后初始化应用
document.addEventListener('DOMContentLoaded', initApp);

// 导出到全局作用域供模板使用
window.AuthManager = AuthManager;
window.UI = UI;
window.EmailManager = EmailManager;
window.UserManager = UserManager;
window.AdminManager = AdminManager;
`;
}
