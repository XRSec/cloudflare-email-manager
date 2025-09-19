/**
 * 前端应用JavaScript代码生成器
 */

export async function getJavaScript(): Promise<string> {
    return `
// 前端调试系统
const VueDebug = {
    enabled: false,
    
    // 初始化调试模式
    async init() {
        try {
            // 检查系统配置中的调试模式
            const response = await fetch('/api/system/config');
            if (response.ok) {
                const data = await response.json();
                if (data.success && data.data.config) {
                    this.enabled = data.data.config.debug_mode === true;
                }
            }
            
            // 检查环境变量（开发环境）
            if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
                this.enabled = true;
            }
            
            // 如果调试模式关闭，禁用console.debug
            if (!this.enabled) {
                console.debug = function() {};
            }
            
            console.log('[VueDebug] 调试模式:', this.enabled ? '已启用' : '已禁用');
        } catch (error) {
            console.warn('[VueDebug] 初始化失败:', error);
            // 默认在开发环境启用调试
            this.enabled = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
        }
    },
    
    // 调试日志
    debug(message, ...args) {
        if (this.enabled) {
            console.debug('[DEBUG]', message, ...args);
        }
    },
    
    // 信息日志
    info(message, ...args) {
        if (this.enabled) {
            console.log('[INFO]', message, ...args);
        }
    },
    
    // 错误日志（总是显示）
    error(message, ...args) {
        console.error('[ERROR]', message, ...args);
    },
    
    // 警告日志（总是显示）
    warn(message, ...args) {
        console.warn('[WARN]', message, ...args);
    }
};

// 初始化调试系统
VueDebug.init();
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
                // 处理401未授权错误
                if (response.status === 401) {
                    console.warn('认证失败，重定向到登录页面');
                    // 清除本地状态
                    State.clearCurrentUser();
                    API.clearToken();
                    // 重定向到首页（去掉hash）
                    window.location.href = '/';
                    return;
                }
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

    // 清除认证令牌
    clearToken() {
        this.token = null;
        localStorage.removeItem('cem_persist_auth_token');
        localStorage.removeItem('auth_token');
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

    // 获取当前用户
    getCurrentUser() {
        return this.currentUser;
    },

    // 设置系统配置
    setSystemConfig(config) {
        this.systemConfig = config;
        this.updateConfigUI();
    },

    // 更新用户界面
    updateUserUI() {
        if (!this.currentUser) {
            VueDebug.debug('updateUserUI: 没有当前用户');
            return;
        }

        VueDebug.debug('updateUserUI: 当前用户', this.currentUser);

        const userEmail = document.getElementById('userEmail');
        const userType = document.getElementById('userType');
        const userAvatar = document.getElementById('userAvatar');
        const sidebarUserInfo = document.getElementById('sidebarUserInfo');

        const domain = this.systemConfig?.domains?.[0] || 'domain.com';

        if (userEmail) {
            userEmail.textContent = this.currentUser.username;
        }

        if (userType) {
            userType.textContent = this.currentUser.user_type === 'admin' ? '管理员' : '普通用户';
        }

        if (userAvatar) {
            userAvatar.textContent = this.currentUser.username.charAt(0).toUpperCase();
        }

        if (sidebarUserInfo) {
            sidebarUserInfo.textContent = this.currentUser.username + ' (' +
                (this.currentUser.user_type === 'admin' ? '管理员' : '用户') + ')';
        }

        // 显示/隐藏管理员菜单
        const adminMenuItems = document.getElementById('adminMenuItems');
        VueDebug.debug('管理员菜单元素:', adminMenuItems, '用户类型:', this.currentUser.user_type);
        
        if (adminMenuItems) {
            if (this.currentUser.user_type === 'admin') {
                adminMenuItems.classList.remove('hidden');
                VueDebug.debug('已显示管理员菜单');
            } else {
                adminMenuItems.classList.add('hidden');
                VueDebug.debug('已隐藏管理员菜单');
            }
        }

        // 更新调试模式菜单项显示状态
        this.updateDebugMenuItem();
    },

    // 更新调试模式菜单项显示状态
    updateDebugMenuItem() {
        const debugMenuItem = document.getElementById('debugMenuItem');
        VueDebug.debug('updateDebugMenuItem: debugMenuItem元素:', debugMenuItem);
        VueDebug.debug('updateDebugMenuItem: systemConfig:', this.systemConfig);
        VueDebug.debug('updateDebugMenuItem: currentUser:', this.currentUser);
        
        if (debugMenuItem) {
            // 检查是否启用调试模式且用户是管理员
            const isDebugMode = this.systemConfig?.debug_mode || 
                               (typeof window !== 'undefined' && 
                                (window.location.hostname === 'localhost' || 
                                 window.location.hostname === '127.0.0.1'));
            const isAdmin = this.currentUser?.user_type === 'admin';
            
            VueDebug.debug('updateDebugMenuItem: isDebugMode:', isDebugMode);
            VueDebug.debug('updateDebugMenuItem: isAdmin:', isAdmin);
            
            if (isDebugMode && isAdmin) {
                debugMenuItem.classList.remove('hidden');
                VueDebug.debug('已显示调试模式菜单项');
            } else {
                debugMenuItem.classList.add('hidden');
                VueDebug.debug('已隐藏调试模式菜单项');
            }
        } else {
            VueDebug.debug('updateDebugMenuItem: debugMenuItem元素未找到');
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

        // 更新调试模式菜单项显示状态
        this.updateDebugMenuItem();
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
        console.log('[UI] showSection 被调用:', sectionName, '时间:', new Date().toISOString());
        console.trace('[UI] showSection 调用堆栈:');
        
        // ID 映射
        const sectionIdMap = {
            'emails': 'emailsSection',
            'settings': 'settingsSection',
            'mailboxes': 'mailboxesSection',
            'mailbox-applications': 'mailboxApplicationsSection',
            'admin-users': 'adminUsersSection',
            'admin-rules': 'adminRulesSection',
            'admin-emails': 'adminEmailsSection',
            'admin-mailboxes': 'adminMailboxesSection',
            'admin-mailbox-applications': 'adminMailboxApplicationsSection',
            'admin-settings': 'adminSettingsSection',
            'debug': 'debugSection'
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
        const selector = \`[href="#\${sectionName}"]\`;
        console.log('[UI] 查找菜单项选择器:', selector);
        console.log('[UI] 当前sectionName:', sectionName);
        
        const menuItem = document.querySelector(selector);
        if (menuItem) {
            menuItem.classList.add('active');
            console.log('[UI] 成功激活菜单项:', menuItem.textContent);
        } else {
            console.warn('[UI] 未找到对应的菜单项:', sectionName);
            // 调试：显示所有可用的href属性
            const allItems = document.querySelectorAll('.sidebar-item');
            console.log('[UI] 所有侧边栏菜单项的href属性:');
            allItems.forEach((item, index) => {
                console.log(\`  \${index}: \${item.getAttribute('href')} - \${item.textContent}\`);
            });
        }

        // 设置当前状态
        State.currentSection = sectionName;
        
        // 更新URL锚点
        if (window.history && window.history.pushState) {
            const hash = sectionName === 'emails' ? '' : '#' + sectionName;
            window.history.pushState(null, null, hash);
        }

        // 加载对应数据
        this.loadSectionData(sectionName).catch(error => {
            console.error('加载页面数据失败:', error);
        });

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
                // 绑定搜索事件
                EmailManager.bindSearchEvents();
                break;
            case 'settings':
                await UserManager.loadSettings();
                break;
            case 'mailboxes':
                await MailboxManager.loadUserMailboxes();
                break;
            case 'mailbox-applications':
                await MailboxManager.loadUserApplications();
                break;
            case 'admin-users':
                if (State.currentUser?.user_type === 'admin') {
                    await AdminManager.loadUsers();
                    // 绑定搜索事件
                    AdminManager.bindSearchEvents();
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
                    // 绑定搜索事件
                    AdminManager.bindEmailSearchEvents();
                }
                break;
            case 'admin-mailboxes':
                if (State.currentUser?.user_type === 'admin') {
                    await MailboxManager.loadAdminMailboxes();
                }
                break;
            case 'admin-mailbox-applications':
                if (State.currentUser?.user_type === 'admin') {
                    await MailboxManager.loadAdminApplications();
                    // 绑定搜索事件
                    MailboxManager.bindApplicationSearchEvents();
                }
                break;
            case 'admin-settings':
                if (State.currentUser?.user_type === 'admin') {
                    await AdminManager.loadSystemSettings();
                }
                break;
            case 'debug':
                if (State.systemConfig?.debug_mode) {
                    await DebugManager.initializeDebugSection();
                }
                break;
        }
    },

    // 显示通用邮件发送模态框（已移至模板中）
    showEmailModal(options) {
        const {
            modalId = 'emailModal',
            title = '发送邮件',
            fromEmail = '',
            toEmail = '',
            subject = '',
            content = '',
            onSubmit = null,
            onClear = null,
            submitText = '发送邮件',
            clearText = '清空表单'
        } = options;

        // 直接显示模板中的模态框
        const modal = document.getElementById(modalId);
        if (modal) {
            // 设置表单值
            const fromInput = document.getElementById(modalId + 'From');
            const toInput = document.getElementById(modalId + 'To');
            const subjectInput = document.getElementById(modalId + 'Subject');
            const contentInput = document.getElementById(modalId + 'Content');
            
            if (fromInput) fromInput.value = fromEmail;
            if (toInput) toInput.value = toEmail;
            if (subjectInput) subjectInput.value = subject;
            if (contentInput) contentInput.value = content;
            
            // 显示模态框
            modal.style.display = 'flex';
            modal.classList.add('show');
        }
    }
};

// 认证管理模块
const AuthManager = {
    // 登录
    async login() {
        const usernameInput = document.getElementById('loginUsername');
        const passwordInput = document.getElementById('loginPassword');

        if (!usernameInput?.value || !passwordInput?.value) {
            UI.showMessage('请填写用户名和密码', 'error');
            return;
        }

        try {
            const response = await API.post('/api/login', {
                username: usernameInput.value.trim(),
                password: passwordInput.value
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
        const accountIdInput = document.getElementById('registerAccountId');
        const passwordInput = document.getElementById('registerPassword');

        if (!accountIdInput?.value) {
            UI.showMessage('请填写用户名', 'error');
            return;
        }

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
                username: accountIdInput.value.trim(),
                password: passwordInput.value
            });

            if (response.success) {
                UI.showMessage('注册成功！您的用户名是：' + response.data.username, 'success');

                // 自动填入登录表单
                const loginUsernameInput = document.getElementById('loginUsername');
                if (loginUsernameInput) {
                    loginUsernameInput.value = response.data.username;
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

// 邮件管理基类 - 提供通用功能
const BaseEmailManager = {
    // 通用工具函数
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    },

    // 安全的HTML渲染（只允许基本标签）
    safeHtml(html) {
        if (!html) return '';
        // 创建一个临时元素来解析HTML
        const temp = document.createElement('div');
        temp.innerHTML = html;
        
        // 只保留安全的标签
        const allowedTags = ['p', 'br', 'strong', 'b', 'em', 'i', 'u', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'];
        const walker = document.createTreeWalker(temp, NodeFilter.SHOW_ELEMENT);
        const elementsToRemove = [];
        
        let node;
        while (node = walker.nextNode()) {
            if (!allowedTags.includes(node.tagName.toLowerCase())) {
                elementsToRemove.push(node);
            }
            // 移除所有属性（防止XSS）
            while (node.attributes.length > 0) {
                node.removeAttribute(node.attributes[0].name);
            }
        }
        
        // 移除不安全的标签
        elementsToRemove.forEach(el => {
            el.replaceWith(...el.childNodes);
        });
        
        return temp.innerHTML;
    },

    // 简单文本渲染（移除Markdown支持）
    renderTextContent(text) {
        if (!text) return '';
        return this.escapeHtml(text);
    },

    // 简单内容类型检测（移除Markdown支持）
    detectContentType(content) {
        if (!content || typeof content !== 'string') {
            return 'text';
        }
        
        const trimmedContent = content.trim();
        
        // 检查是否为HTML内容
        if (this.hasHtmlTags(trimmedContent)) {
            return 'html';
        }
        
        // 默认为纯文本
        return 'text';
    },

    // 检查是否为完整的HTML文档
    isCompleteHtmlDocument(content) {
        const htmlDocPatterns = [
            /^<!DOCTYPE\\s+html/i,
            /^<html[^>]*>/i,
            /<head[^>]*>[\\s\\S]*<\\/head>/i,
            /<body[^>]*>[\\s\\S]*<\\/body>/i,
        ];
        
        return htmlDocPatterns.some(pattern => pattern.test(content));
    },

    // 检查是否包含HTML标签
    hasHtmlTags(content) {
        const htmlTagPattern = /<[a-zA-Z][^>]*>/;
        return htmlTagPattern.test(content);
    },


    // 计算HTML结构得分
    calculateHtmlScore(content) {
        let score = 0;
        
        const patterns = [
            { pattern: /<div[^>]*>/gi, weight: 1 },
            { pattern: /<span[^>]*>/gi, weight: 1 },
            { pattern: /<p[^>]*>/gi, weight: 2 },
            { pattern: /<h[1-6][^>]*>/gi, weight: 3 },
            { pattern: /<a[^>]*>/gi, weight: 2 },
            { pattern: /<img[^>]*>/gi, weight: 2 },
            { pattern: /<ul[^>]*>/gi, weight: 2 },
            { pattern: /<ol[^>]*>/gi, weight: 2 },
            { pattern: /<li[^>]*>/gi, weight: 1 },
            { pattern: /<table[^>]*>/gi, weight: 3 },
            { pattern: /<iframe[^>]*>/gi, weight: 4 },
            { pattern: /<script[^>]*>/gi, weight: 5 },
            { pattern: /<style[^>]*>/gi, weight: 5 },
            { pattern: /<form[^>]*>/gi, weight: 4 },
            { pattern: /<input[^>]*>/gi, weight: 3 },
            { pattern: /<button[^>]*>/gi, weight: 3 },
        ];
        
        patterns.forEach(({ pattern, weight }) => {
            const matches = content.match(pattern);
            if (matches) {
                score += matches.length * weight;
            }
        });
        
        return score;
    },


    formatDate(dateString) {
        if (!dateString) return '-';
        const date = new Date(dateString);
        return date.toLocaleDateString('zh-CN') + ' ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
    },

    // 智能渲染邮件内容
    renderEmailContent(email) {
        let contentHtml = '';
        
        // 检查邮件内容
        const hasContent = email.content && email.content.trim();
        const contentType = email.content_type || 'text';
        
        if (hasContent) {
            if (contentType === 'html') {
                // HTML内容直接显示为文本
                const textContent = this.stripHtml(email.content);
                contentHtml += '<div class="email-detail-row">' +
                    '<span class="detail-label">📧 邮件内容 (HTML):</span>' +
                    '</div><div class="detail-value text-content">' + this.escapeHtml(textContent.substring(0, 800)) + 
                    (textContent.length > 800 ? '<div class="truncated">...（内容已截断，点击查看详情查看完整内容）</div>' : '') + '</div>';
            } else {
                // 纯文本内容
                contentHtml += '<div class="email-detail-row">' +
                    '<span class="detail-label">📄 邮件内容:</span>' +
                    '</div><div class="detail-value text-content">' + this.escapeHtml(email.content.substring(0, 600)) + 
                    (email.content.length > 600 ? '<div class="truncated">...（内容已截断）</div>' : '') + '</div>';
            }
        } else {
            // 无内容
            contentHtml += '<div class="email-detail-row">' +
                '<span class="detail-label">📄 邮件内容:</span>' +
                '<div class="detail-value" style="color: #6c757d; font-style: italic;">（此邮件无内容）</div>' +
            '</div>';
        }
        
        return contentHtml;
    },

    // 检测是否为富HTML内容
    isRichHtml(html) {
        if (!html) return false;
        
        // 移除常见的简单标签
        const withoutSimpleTags = html.replace(/<\\/?(?:p|br|div|span)\\b[^>]*>/gi, '');
        
        // 检测是否包含富文本标签
        const richTags = /<(?:strong|b|em|i|u|h[1-6]|ul|ol|li|table|tr|td|th|img|a\s+href|style|color|font)/i;
        
        return richTags.test(withoutSimpleTags);
    },

    // 从HTML中提取纯文本
    stripHtml(html) {
        if (!html) return '';
        
        // 创建临时元素
        const temp = document.createElement('div');
        temp.innerHTML = html;
        
        // 获取纯文本，保留换行
        return temp.textContent || temp.innerText || '';
    },

    // 通用邮件渲染函数
    renderEmailItem(email, isExpanded = false, managerName = 'EmailManager') {
        const emailId = email.id;
        
        // 获取邮件内容预览
        let contentPreview = '';
        if (email.content && email.content.trim()) {
            if (email.content_type === 'html') {
                // HTML内容直接提取文本
                contentPreview = this.stripHtml(email.content).trim();
            } else {
                contentPreview = email.content.trim();
            }
        }
        
        // 截断到20个字符
        const shortContent = contentPreview ? 
            (contentPreview.length > 20 ? contentPreview.substring(0, 20) + '...' : contentPreview) : 
            '(无内容)';
        
        // 检测是否为移动端
        const isMobile = window.innerWidth <= 768;
        
        return '<div class="email-item" data-email-id="' + emailId + '">' +
            '<div class="email-header" onclick="' + managerName + '.toggleEmailExpansion(' + emailId + ')">' +
                '<div class="email-main-info">' +
                    '<div class="email-sender-line">' +
                        '<span class="email-sender">' + this.escapeHtml(email.sender_email) + 
                            (managerName === 'AdminManager' ? ' → ' + this.escapeHtml(email.recipient_email) : '') + '</span>' +
                        '<span class="email-content-preview">' + this.escapeHtml(shortContent) + '</span>' +
                    '</div>' +
                '</div>' +
                '<div class="email-meta">' +
                    '<div class="email-time">' + this.formatDate(email.received_at) + '</div>' +
                    (email.has_attachments ? '<div class="email-attachments">📎</div>' : '') +
                    '<div class="email-toggle">' + (isExpanded ? '▼' : '▶') + '</div>' +
                '</div>' +
            '</div>' +
            '<div class="email-details' + (isExpanded ? ' expanded' : '') + '">' +
                (isMobile ? this.renderMobileEmailDetails(email, managerName) : this.renderDesktopEmailDetails(email, managerName)) +
            '</div>' +
        '</div>';
    },

    // 移动端邮件详情（完整显示）
    renderMobileEmailDetails(email, managerName) {
        return '<div class="email-detail-row">' +
                    '<span class="detail-label">📧 主题:</span>' +
                    '<span class="detail-value">' + this.escapeHtml(email.subject || '(无主题)') + '</span>' +
                '</div>' +
                '<div class="email-detail-row">' +
                    '<span class="detail-label">收件人:</span>' +
                    '<span class="detail-value">' + this.escapeHtml(email.recipient_email) + '</span>' +
                '</div>' +
                '<div class="email-detail-row">' +
                    '<span class="detail-label">邮件ID:</span>' +
                    '<span class="detail-value">' + this.escapeHtml(email.message_id) + '</span>' +
                '</div>' +
                (managerName === 'AdminManager' ? 
                    '<div class="email-detail-row">' +
                        '<span class="detail-label">用户ID:</span>' +
                        '<span class="detail-value">' + email.user_id + '</span>' +
                    '</div>' : '') +
                '<div class="email-detail-row">' +
                    '<span class="detail-label">接收时间:</span>' +
                    '<span class="detail-value">' + this.formatDate(email.received_at) + '</span>' +
                '</div>' +
                '<div class="email-detail-row">' +
                    '<span class="detail-label">创建时间:</span>' +
                    '<span class="detail-value">' + this.formatDate(email.created_at) + '</span>' +
                '</div>' +
                this.renderEmailContent(email) +
                '<div class="email-actions">' +
            '<button class="btn btn-primary btn-sm" onclick="' + managerName + '.showEmailDetail(' + email.id + ')">查看详情</button>' +
            '<button class="btn btn-secondary btn-sm" onclick="' + managerName + '.copyEmailId(' + email.id + ')">复制ID</button>' +
            '<button class="btn btn-danger btn-sm" onclick="' + managerName + '.deleteEmail(' + email.id + ')">删除邮件</button>' +
        '</div>';
    },

    // 电脑端邮件详情（简化显示）
    renderDesktopEmailDetails(email, managerName) {
        return '<div class="email-detail-row">' +
            '<span class="detail-label">📧 主题:</span>' +
            '<span class="detail-value">' + this.escapeHtml(email.subject || '(无主题)') + '</span>' +
                '</div>' +
        '<div class="email-detail-row">' +
            '<span class="detail-label">收件人:</span>' +
            '<span class="detail-value">' + this.escapeHtml(email.recipient_email) + '</span>' +
            '</div>' +
        this.renderEmailContent(email) +
        '<div class="email-actions">' +
            '<button class="btn btn-primary btn-sm" onclick="' + managerName + '.showEmailDetail(' + email.id + ')">查看详情</button>' +
            '<button class="btn btn-secondary btn-sm" onclick="' + managerName + '.copyEmailId(' + email.id + ')">复制ID</button>' +
            '<button class="btn btn-danger btn-sm" onclick="' + managerName + '.deleteEmail(' + email.id + ')">删除邮件</button>' +
        '</div>';
    },

    // 通用展开/收起功能
    updateEmailExpansionUI(containerSelector, expandedEmails) {
        const emailItems = document.querySelectorAll(containerSelector + ' .email-item');
        emailItems.forEach(item => {
            const emailId = parseInt(item.dataset.emailId);
            if (emailId) {
                const details = item.querySelector('.email-details');
                const toggle = item.querySelector('.email-toggle');
                
                if (details && toggle) {
                    if (expandedEmails.has(emailId)) {
                        details.classList.add('expanded');
                        toggle.textContent = '▼';
                    } else {
                        details.classList.remove('expanded');
                        toggle.textContent = '▶';
                    }
                }
            }
        });
    },

    // 通用复制邮件ID
    copyEmailId(emailId) {
        navigator.clipboard.writeText(emailId.toString()).then(() => {
            UI.showMessage('邮件ID已复制到剪贴板', 'success');
        }).catch(() => {
            UI.showMessage('复制失败', 'error');
        });
    },

    // 通用显示邮件详情
    async showEmailDetail(emailId) {
        try {
            const response = await API.get('/api/protected/emails/' + emailId);
            if (response.success) {
                const email = response.data;
                BaseEmailManager.showEmailDetailModal(email);
            } else {
                UI.showMessage('获取邮件详情失败', 'error');
            }
        } catch (error) {
            UI.showMessage('获取邮件详情失败: ' + error.message, 'error');
        }
    },

    // 显示邮件详情模态框
    showEmailDetailModal(email) {
        // 创建模态框HTML
        const modalHtml = \`
            <div id="emailDetailModal" class="modal show" style="display: flex;">
                <div class="modal-content" style="max-width: 800px; width: 95%;">
                    <div class="modal-header">
                        <h3>📧 邮件详情</h3>
                        <button class="btn btn-secondary btn-sm" onclick="BaseEmailManager.closeEmailDetailModal()" style="position: absolute; right: 20px; top: 20px;">✕</button>
                    </div>
                    <div class="modal-body" style="max-height: 70vh; overflow-y: auto;">
                        <div class="email-detail-info">
                            <div class="email-detail-row">
                                <span class="detail-label">📧 主题:</span>
                                <span class="detail-value">\${this.escapeHtml(email.subject || '(无主题)')}</span>
                            </div>
                            <div class="email-detail-row">
                                <span class="detail-label">👤 发件人:</span>
                                <span class="detail-value">\${this.escapeHtml(email.sender_email)}</span>
                            </div>
                            <div class="email-detail-row">
                                <span class="detail-label">📮 收件人:</span>
                                <span class="detail-value">\${this.escapeHtml(email.recipient_email)}</span>
                            </div>
                            <div class="email-detail-row">
                                <span class="detail-label">🆔 邮件ID:</span>
                                <span class="detail-value" style="font-family: monospace; font-size: 0.9rem;">\${this.escapeHtml(email.message_id)}</span>
                            </div>
                            <div class="email-detail-row">
                                <span class="detail-label">📅 接收时间:</span>
                                <span class="detail-value">\${this.formatDate(email.received_at)}</span>
                            </div>
                            <div class="email-detail-row">
                                <span class="detail-label">📅 创建时间:</span>
                                <span class="detail-value">\${this.formatDate(email.created_at)}</span>
                            </div>
                            \${email.has_attachments ? '<div class="email-detail-row"><span class="detail-label">📎 附件:</span><span class="detail-value">有附件</span></div>' : ''}
                        </div>
                        <div class="email-content-section" style="margin-top: 20px; border-top: 1px solid #e9ecef; padding-top: 20px;">
                            <h4 style="margin-bottom: 15px; color: #2c3e50;">📄 邮件内容</h4>
                            \${this.renderEmailContentForModal(email)}
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" onclick="BaseEmailManager.closeEmailDetailModal()">取消</button>
                        <button class="btn btn-primary" onclick="BaseEmailManager.copyEmailId(\${email.id})">复制ID</button>
                        <button class="btn btn-danger" onclick="BaseEmailManager.deleteEmailFromModal(\${email.id})">删除邮件</button>
                    </div>
                </div>
            </div>
        \`;

        // 移除已存在的模态框
        const existingModal = document.getElementById('emailDetailModal');
        if (existingModal) {
            existingModal.remove();
        }

        // 添加新模态框到页面
        document.body.insertAdjacentHTML('beforeend', modalHtml);
    },

    // 为模态框渲染邮件内容
    renderEmailContentForModal(email) {
        let contentHtml = '';
        
        // 检查邮件内容
        const hasContent = email.content && email.content.trim();
        const contentType = email.content_type || 'text';
        
        if (hasContent) {
            if (contentType === 'html') {
                // HTML内容直接显示为文本
                const textContent = this.stripHtml(email.content);
                contentHtml += '<div class="text-content">' + this.escapeHtml(textContent) + '</div>';
            } else {
                // 纯文本内容
                contentHtml += '<div class="text-content">' + this.escapeHtml(email.content) + '</div>';
            }
        } else {
            // 无内容
            contentHtml += '<div style="color: #6c757d; font-style: italic; text-align: center; padding: 40px;">（此邮件无内容）</div>';
        }
        
        return contentHtml;
    },

    // 切换邮件内容标签
    switchEmailContentTab(tab) {
        // 移除所有活动状态
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        
        // 激活选中的标签
        if (tab === 'html') {
            document.querySelector('.tab-btn[onclick*="html"]')?.classList.add('active');
            document.getElementById('emailContentHtml')?.classList.add('active');
        } else if (tab === 'text') {
            document.querySelector('.tab-btn[onclick*="text"]')?.classList.add('active');
            document.getElementById('emailContentText')?.classList.add('active');
        }
    },

    // 关闭邮件详情模态框
    closeEmailDetailModal() {
        const modal = document.getElementById('emailDetailModal');
        if (modal) {
            modal.remove();
        }
    },

    // 从模态框删除邮件
    async deleteEmailFromModal(emailId) {
        if (!confirm('确定要删除这封邮件吗？此操作不可撤销。')) {
            return;
        }

        try {
            const response = await API.delete('/api/protected/emails/' + emailId);
            if (response.success) {
                UI.showMessage('邮件已删除', 'success');
                this.closeEmailDetailModal();
                // 刷新邮件列表
                if (window.EmailManager && window.EmailManager.loadEmails) {
                    await window.EmailManager.loadEmails();
                }
                if (window.AdminManager && window.AdminManager.loadAllEmails) {
                    await window.AdminManager.loadAllEmails();
                }
            } else {
                UI.showMessage('删除失败: ' + response.error, 'error');
            }
        } catch (error) {
            UI.showMessage('删除失败: ' + error.message, 'error');
        }
    }
};

// 邮件管理模块
const EmailManager = {
    currentPage: 1,
    pageSize: 20,
    expandedEmails: new Set(), // 存储展开的邮件ID

    // 加载邮件列表
    async loadEmails(page = 1, searchParams = {}) {
        this.currentPage = page;
        const emailList = document.getElementById('emailList');

        if (!emailList) return;

        UI.showLoading(emailList);

        try {
            // 构建查询参数
            const params = new URLSearchParams({
                page: page.toString(),
                limit: this.pageSize.toString()
            });

            // 添加搜索参数
            if (searchParams.search) {
                params.append('search', searchParams.search);
            }
            if (searchParams.sender) {
                params.append('sender', searchParams.sender);
            }
            if (searchParams.subject) {
                params.append('subject', searchParams.subject);
            }
            if (searchParams.start_date) {
                params.append('start_date', searchParams.start_date);
            }
            if (searchParams.end_date) {
                params.append('end_date', searchParams.end_date);
            }
            if (searchParams.has_attachments !== undefined) {
                params.append('has_attachments', searchParams.has_attachments.toString());
            }
            if (searchParams.sort) {
                params.append('sort', searchParams.sort);
            }
            if (searchParams.order) {
                params.append('order', searchParams.order);
            }

            const response = await API.get('/api/protected/emails?' + params.toString());

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

        const emailsHtml = emails.map(email => {
            const isExpanded = this.expandedEmails && this.expandedEmails.has(email.id);
            return BaseEmailManager.renderEmailItem(email, isExpanded, 'EmailManager');
        }).join('');

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
                                (email.content_type === 'html' ? this.safeHtml(email.content || '(无内容)') :
                                    '<pre style="white-space: pre-wrap; margin: 0;">' + this.escapeHtml(email.content || '(无内容)') + '</pre>') +
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
    },

    // 一键展开所有邮件
    expandAllEmails() {
        const emailItems = document.querySelectorAll('#emailList .email-item');
        emailItems.forEach(item => {
            const emailId = parseInt(item.dataset.emailId);
            if (emailId) {
                this.expandedEmails.add(emailId);
            }
        });
        BaseEmailManager.updateEmailExpansionUI('#emailList', this.expandedEmails);
    },

    // 一键收起所有邮件
    collapseAllEmails() {
        this.expandedEmails.clear();
        BaseEmailManager.updateEmailExpansionUI('#emailList', this.expandedEmails);
    },

    // 删除邮件
    async deleteEmail(emailId) {
        if (!confirm('确定要删除这封邮件吗？此操作不可撤销。')) {
            return;
        }

        try {
            const response = await API.delete('/api/protected/emails/' + emailId);
            if (response.success) {
                UI.showMessage('邮件已删除', 'success');
                // 重新加载邮件列表
                await this.loadEmails(this.currentPage);
            } else {
                UI.showMessage('删除失败: ' + response.error, 'error');
            }
        } catch (error) {
            UI.showMessage('删除失败: ' + error.message, 'error');
        }
    },

    // 切换邮件展开状态
    toggleEmailExpansion(emailId) {
        if (this.expandedEmails.has(emailId)) {
            this.expandedEmails.delete(emailId);
        } else {
            this.expandedEmails.add(emailId);
        }
        BaseEmailManager.updateEmailExpansionUI('#emailList', this.expandedEmails);
    },

    // 搜索邮件
    searchEmails() {
        const searchInput = document.getElementById('emailsSearch');
        if (!searchInput) return;

        const searchTerm = searchInput.value.trim();
        const searchParams = {
            search: searchTerm || undefined
        };

        // 重置到第一页并搜索
        this.loadEmails(1, searchParams);
    },

    // 清空搜索
    clearSearch() {
        const searchInput = document.getElementById('emailsSearch');
        if (searchInput) {
            searchInput.value = '';
        }
        this.loadEmails(1, {});
    },

    // 绑定搜索事件
    bindSearchEvents() {
        const searchInput = document.getElementById('emailsSearch');
        if (!searchInput) return;

        // 清除之前的事件监听器
        searchInput.removeEventListener('input', this.debouncedSearch);
        searchInput.removeEventListener('keypress', this.handleSearchKeypress);

        // 防抖搜索
        this.debouncedSearch = this.debounce(() => {
            this.searchEmails();
        }, 500);

        // 输入事件
        searchInput.addEventListener('input', this.debouncedSearch);

        // 回车键搜索
        this.handleSearchKeypress = (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                this.searchEmails();
            }
        };
        searchInput.addEventListener('keypress', this.handleSearchKeypress);
    },

    // 防抖函数
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // 使用BaseEmailManager的方法
    copyEmailId: BaseEmailManager.copyEmailId,
    showEmailDetail: BaseEmailManager.showEmailDetail,
    escapeHtml: BaseEmailManager.escapeHtml,
    safeHtml: BaseEmailManager.safeHtml,
    formatDate: BaseEmailManager.formatDate,

    // 发送站内邮件
    async sendInternalEmail() {
        try {
            console.log('[EmailManager] 开始发送站内邮件...');
            
            const fromEmail = document.getElementById('internalEmailModalFrom')?.value;
            const toEmail = document.getElementById('internalEmailModalTo')?.value;
            const subject = document.getElementById('internalEmailModalSubject')?.value;
            const content = document.getElementById('internalEmailModalContent')?.value;

            console.log('[EmailManager] 站内邮件数据:', { fromEmail, toEmail, subject, content });

            if (!fromEmail || !toEmail || !subject || !content) {
                UI.showMessage('请填写所有必填字段', 'error');
                return;
            }

            // 验证邮箱格式
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(fromEmail) || !emailRegex.test(toEmail)) {
                UI.showMessage('请输入有效的邮箱地址', 'error');
                return;
            }

            UI.showMessage('正在发送站内邮件...', 'info');

            console.log('[EmailManager] 准备调用站内邮件API...');
            
            // 首先需要获取收件人的用户ID
            const usersResponse = await API.get('/api/admin/users');
            if (!usersResponse.success) {
                UI.showMessage('获取用户列表失败', 'error');
                return;
            }

            // 查找收件人用户 - 需要先获取用户的邮箱列表
            let recipientUser = null;
            for (const user of usersResponse.data.users) {
                // 获取用户的邮箱列表
                const mailboxesResponse = await API.get(\`/api/mailbox/admin/mailboxes?user_id=\${user.id}\`);
                if (mailboxesResponse.success) {
                    const hasMatchingEmail = mailboxesResponse.data.mailboxes.some(mailbox => 
                        mailbox.email_address === toEmail
                    );
                    if (hasMatchingEmail) {
                        recipientUser = user;
                        break;
                    }
                }
            }

            if (!recipientUser) {
                UI.showMessage('收件人用户不存在，请检查邮箱地址', 'error');
                return;
            }

            console.log('[EmailManager] 找到收件人用户:', recipientUser);

            // 调用发送用户信息API
            const response = await API.post('/api/admin/users/' + recipientUser.id + '/send-info', {
                to_email: toEmail,
                from_email: fromEmail,
                subject: subject,
                content: content,
                content_type: 'markdown'
            });
            
            console.log('[EmailManager] 站内邮件API响应:', response);

            if (response.success) {
                UI.showMessage('站内邮件发送成功', 'success');
                
                // 清空表单
                this.clearInternalForm();
                
                // 刷新邮件列表
                await this.loadEmails();
            } else {
                UI.showMessage('发送失败: ' + (response.error || '未知错误'), 'error');
            }
        } catch (error) {
            console.error('[EmailManager] 站内邮件发送失败:', error);
            UI.showMessage('站内邮件发送失败: ' + error.message, 'error');
        }
    },

    // 清空站内邮件表单
    clearInternalForm() {
        const fromInput = document.getElementById('internalEmailModalFrom');
        const toInput = document.getElementById('internalEmailModalTo');
        const subjectInput = document.getElementById('internalEmailModalSubject');
        const contentInput = document.getElementById('internalEmailModalContent');
        
        if (fromInput) fromInput.value = '';
        if (toInput) toInput.value = '';
        if (subjectInput) subjectInput.value = '';
        if (contentInput) contentInput.value = '';
        
        // 重置编辑器标签
        this.switchEditorTab('write');
        console.log('[EmailManager] 站内邮件表单已清空');
    },

    // 切换Markdown编辑器标签
    switchEditorTab(tab) {
        const writeTab = document.querySelector('.editor-tabs .tab-btn[onclick*="write"]');
        const previewTab = document.querySelector('.editor-tabs .tab-btn[onclick*="preview"]');
        const textarea = document.getElementById('intContent');
        const preview = document.getElementById('markdownPreview');
        
        if (!writeTab || !previewTab || !textarea || !preview) return;
        
        // 移除所有活动状态
        writeTab.classList.remove('active');
        previewTab.classList.remove('active');
        
        if (tab === 'write') {
            writeTab.classList.add('active');
            textarea.style.display = 'block';
            preview.style.display = 'none';
        } else if (tab === 'preview') {
            previewTab.classList.add('active');
            textarea.style.display = 'none';
            preview.style.display = 'block';
            
            // 更新预览内容（直接显示文本）
            const textContent = textarea.value;
            if (textContent) {
                preview.innerHTML = this.escapeHtml(textContent);
            } else {
                preview.innerHTML = '<p style="color: #6c757d; font-style: italic;">暂无内容</p>';
            }
        }
    },

    // 回复邮件
    async replyToEmail(emailId) {
        try {
            console.log('[EmailManager] 开始回复邮件:', emailId);
            
            // 获取邮件详情
            const response = await API.get(\`/api/protected/emails/\${emailId}\`);
            if (!response.success) {
                UI.showMessage('获取邮件详情失败', 'error');
                return;
            }
            
            const email = response.data;
            console.log('[EmailManager] 邮件详情:', email);
            
            // 显示回复模态框
            const modal = document.getElementById('replyEmailModal');
            if (modal) {
                modal.style.display = 'flex';
                modal.classList.add('show');
                
                // 填充表单
                const toInput = document.getElementById('replyEmailModalTo');
                const subjectInput = document.getElementById('replyEmailModalSubject');
                const contentInput = document.getElementById('replyEmailModalContent');
                
                if (toInput) toInput.value = email.from_email || '';
                if (subjectInput) subjectInput.value = email.subject ? 'Re: ' + email.subject : 'Re: ';
                if (contentInput) contentInput.value = \`
                
                --- 原邮件 ---
                发件人: \${email.from_email}
                收件人: \${email.to_email}
                时间: \${this.formatDate(email.created_at)}
                主题: \${email.subject}
                
                \${(email.content || '')}\`;
                
                // 加载发件人邮箱列表
                await this.loadReplySenderEmails();
                
                // 存储当前邮件ID
                window.currentReplyEmailId = emailId;
            }
        } catch (error) {
            console.error('[EmailManager] 回复邮件失败:', error);
            UI.showMessage('回复邮件失败: ' + error.message, 'error');
        }
    },

    // 加载回复发件人邮箱列表
    async loadReplySenderEmails() {
        try {
            const response = await API.get('/api/mailbox/user/mailboxes');
            if (response.success) {
                const select = document.getElementById('replyEmailModalFrom');
                if (select) {
                    select.innerHTML = '<option value="">选择发件人邮箱...</option>';
                    response.data.forEach(mailbox => {
                        const option = document.createElement('option');
                        option.value = mailbox.email_address;
                        option.textContent = mailbox.email_address;
                        select.appendChild(option);
                    });
                }
            }
        } catch (error) {
            console.error('[EmailManager] 加载发件人邮箱失败:', error);
        }
    },

    // 发送回复邮件
    async sendReplyEmail() {
        try {
            console.log('[EmailManager] 开始发送回复邮件...');
            
            const toEmail = document.getElementById('replyEmailModalTo')?.value;
            const fromEmail = document.getElementById('replyEmailModalFrom')?.value;
            const subject = document.getElementById('replyEmailModalSubject')?.value;
            const content = document.getElementById('replyEmailModalContent')?.value;

            console.log('[EmailManager] 回复邮件数据:', { toEmail, fromEmail, subject, content });

            if (!toEmail || !fromEmail || !subject || !content) {
                UI.showMessage('请填写所有必填字段', 'error');
                return;
            }

            // 验证邮箱格式
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(fromEmail) || !emailRegex.test(toEmail)) {
                UI.showMessage('请输入有效的邮箱地址', 'error');
                return;
            }

            // 发送回复邮件（使用站内邮件API）
            const response = await API.post('/api/admin/users/2/send-info', {
                to: toEmail,
                from: fromEmail,
                subject: subject,
                content: content
            });

            if (response.success) {
                UI.showMessage('回复邮件发送成功', 'success');
                
                // 关闭模态框
                UI.hideModal('replyEmailModal');
                
                // 刷新邮件列表
                await this.loadEmails();
            } else {
                UI.showMessage('发送失败: ' + (response.error || '未知错误'), 'error');
            }
        } catch (error) {
            console.error('[EmailManager] 回复邮件发送失败:', error);
            UI.showMessage('回复邮件发送失败: ' + error.message, 'error');
        }
    }
};

// 用户管理模块
const UserManager = {
    // 加载用户设置
    async loadSettings() {
        try {
            // 加载webhook配置
            await this.loadWebhooks();
            // 加载转发规则
            await this.loadRules();
        } catch (error) {
            UI.showMessage(error.message || '加载设置失败', 'error');
        }
    },

    // 加载webhook配置
    async loadWebhooks() {
        try {
            const response = await API.get('/api/protected/webhooks');
            const webhooksContainer = document.getElementById('webhooksContainer');
            
            if (!webhooksContainer) return;

            if (response.success) {
                this.renderWebhooks(response.data.webhooks);
            } else {
                webhooksContainer.innerHTML = '<p>加载webhook配置失败</p>';
            }
        } catch (error) {
            console.error('加载webhook配置失败:', error);
            const webhooksContainer = document.getElementById('webhooksContainer');
            if (webhooksContainer) {
                webhooksContainer.innerHTML = '<p>加载webhook配置失败</p>';
            }
        }
    },

    // 渲染webhook配置
    renderWebhooks(webhooks) {
        const webhooksContainer = document.getElementById('webhooksContainer');
        if (!webhooksContainer) return;

        if (webhooks.length === 0) {
            webhooksContainer.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 20px;">暂无webhook配置</p>';
            return;
        }

        const webhooksHtml = webhooks.map(webhook => \`
            <div class="webhook-item" data-webhook-id="\${webhook.id}">
                <div class="webhook-info">
                    <div class="webhook-name">\${BaseEmailManager.escapeHtml(webhook.webhook_name)}</div>
                    <div class="webhook-url">\${BaseEmailManager.escapeHtml(webhook.webhook_url)}</div>
                    <div class="webhook-type">\${this.getWebhookTypeLabel(webhook.webhook_type)}</div>
                </div>
                <div class="webhook-actions">
                    <button class="webhook-edit" onclick="UserManager.editWebhook(\${webhook.id})" title="编辑">✏️</button>
                    <button class="webhook-remove" onclick="UserManager.removeWebhook(\${webhook.id})" title="删除">🗑️</button>
                </div>
            </div>
        \`).join('');

        webhooksContainer.innerHTML = webhooksHtml;
    },

    // 获取webhook类型标签
    getWebhookTypeLabel(type) {
        const typeMap = {
            'custom': '自定义',
            'dingtalk': '钉钉',
            'feishu': '飞书'
        };
        return typeMap[type] || '未知';
    },

    // 添加webhook
    async addWebhook() {
        const nameInput = document.getElementById('newWebhookName');
        const urlInput = document.getElementById('newWebhookUrl');
        const secretInput = document.getElementById('newWebhookSecret');
        const typeSelect = document.getElementById('newWebhookType');

        const name = nameInput.value.trim();
        const url = urlInput.value.trim();
        const secret = secretInput.value.trim();
        const type = typeSelect.value;

        if (!name || !url) {
            UI.showMessage('名称和URL不能为空', 'warning');
            return;
        }

        if (!url.startsWith('http')) {
            UI.showMessage('URL必须以http或https开头', 'error');
            return;
        }

        try {
            const response = await API.post('/api/protected/webhooks', {
                webhook_name: name,
                webhook_url: url,
                webhook_secret: secret || undefined,
                webhook_type: type
            });

            if (response.success) {
                UI.showMessage('Webhook配置添加成功', 'success');
                // 清空输入框
                nameInput.value = '';
                urlInput.value = '';
                secretInput.value = '';
                typeSelect.value = 'custom';
                // 重新加载webhook列表
                await this.loadWebhooks();
            } else {
                UI.showMessage(response.error || '添加失败', 'error');
            }
        } catch (error) {
            UI.showMessage(error.message || '添加失败', 'error');
        }
    },

    // 编辑webhook
    editWebhook(webhookId) {
        // 这里可以实现编辑功能，暂时显示提示
        UI.showMessage('编辑功能开发中...', 'info');
    },

    // 删除webhook
    async removeWebhook(webhookId) {
        if (!confirm('确定要删除这个webhook配置吗？')) {
            return;
        }

        try {
            const response = await API.delete(\`/api/protected/webhooks/\${webhookId}\`);

            if (response.success) {
                UI.showMessage('Webhook配置删除成功', 'success');
                // 重新加载webhook列表
                await this.loadWebhooks();
            } else {
                UI.showMessage(response.error || '删除失败', 'error');
            }
        } catch (error) {
            UI.showMessage(error.message || '删除失败', 'error');
        }
    },

    // 更新设置（现在只处理密码）
    async updateSettings() {
        const passwordInput = document.getElementById('newPassword');

        const updates = {};

        if (passwordInput?.value.trim()) {
            if (passwordInput.value.length < 6) {
                UI.showMessage('密码长度至少为6位', 'error');
                return;
            }
            updates.password = passwordInput.value;
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
            }
        } catch (error) {
            UI.showMessage(error.message || '更新设置失败', 'error');
        }
    },

    // 加载转发规则
    async loadRules() {
        try {
            const response = await API.get('/api/protected/forward-rules');
            const rulesContainer = document.getElementById('userRulesContainer');
            
            if (!rulesContainer) return;

            if (response.success) {
                this.renderRules(response.data.rules);
            } else {
                rulesContainer.innerHTML = '<p>加载转发规则失败</p>';
            }
        } catch (error) {
            console.error('加载转发规则失败:', error);
            const rulesContainer = document.getElementById('userRulesContainer');
            if (rulesContainer) {
                rulesContainer.innerHTML = '<p>加载转发规则失败</p>';
            }
        }
    },

    // 渲染转发规则
    renderRules(rules) {
        const rulesContainer = document.getElementById('userRulesContainer');
        if (!rulesContainer) return;

        if (rules.length === 0) {
            rulesContainer.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 20px;">暂无转发规则</p>';
            return;
        }

        const rulesHtml = rules.map(rule => \`
            <div class="rule-item" data-rule-id="\${rule.id}">
                <div class="rule-info">
                    <div class="rule-name">\${BaseEmailManager.escapeHtml(rule.rule_name)}</div>
                    <div class="rule-filters">
                        \${rule.sender_filter ? '发件人: ' + BaseEmailManager.escapeHtml(rule.sender_filter) + '<br>' : ''}
                        \${rule.keyword_filter ? '关键字: ' + BaseEmailManager.escapeHtml(rule.keyword_filter) + '<br>' : ''}
                        \${rule.recipient_filter ? '收件人: ' + BaseEmailManager.escapeHtml(rule.recipient_filter) : ''}
                    </div>
                    <div class="rule-webhook">
                        \${BaseEmailManager.escapeHtml(rule.webhook_url)} (\${this.getWebhookTypeLabel(rule.webhook_type)})
                    </div>
                    <div class="rule-status">
                        <span class="badge \${rule.enabled ? 'badge-success' : 'badge-secondary'}">
                            \${rule.enabled ? '启用' : '禁用'}
                        </span>
                    </div>
                </div>
                <div class="rule-actions">
                    <button class="rule-edit" onclick="UserManager.editRule(\${rule.id})" title="编辑">✏️</button>
                    <button class="rule-remove" onclick="UserManager.removeRule(\${rule.id})" title="删除">🗑️</button>
                </div>
            </div>
        \`).join('');

        rulesContainer.innerHTML = rulesHtml;
    },

    // 显示创建转发规则模态框
    async showCreateRuleModal() {
        UI.showModal('userCreateRuleModal');
        await this.loadUserRecipientEmails();
    },

    // 加载用户邮箱列表到收件人下拉框
    async loadUserRecipientEmails() {
        try {
            const response = await API.get('/api/protected/mailboxes');
            if (response.success) {
                const recipientSelect = document.getElementById('userRuleRecipient');
                if (recipientSelect) {
                    // 清空现有选项（保留第一个默认选项）
                    recipientSelect.innerHTML = '<option value="">选择收件人邮箱（可选）</option>';
                    
                    // 添加邮箱选项
                    response.data?.forEach(mailbox => {
                        const option = document.createElement('option');
                        option.value = mailbox.email_address;
                        option.textContent = mailbox.email_address;
                        recipientSelect.appendChild(option);
                    });
                }
            }
        } catch (error) {
            console.error('加载收件人邮箱列表失败:', error);
        }
    },

    // 创建转发规则
    async createRule() {
        const ruleName = document.getElementById('userRuleName').value.trim();
        const ruleSender = document.getElementById('userRuleSender').value.trim();
        const ruleKeyword = document.getElementById('userRuleKeyword').value.trim();
        const ruleRecipient = document.getElementById('userRuleRecipient').value;
        const ruleWebhook = document.getElementById('userRuleWebhook').value.trim();
        const ruleWebhookType = document.getElementById('userRuleWebhookType').value;

        if (!ruleName || !ruleWebhook) {
            UI.showMessage('规则名称和Webhook URL不能为空', 'error');
            return;
        }

        if (!ruleWebhook.startsWith('http')) {
            UI.showMessage('Webhook URL必须以http或https开头', 'error');
            return;
        }

        try {
            const response = await API.post('/api/protected/forward-rules', {
                rule_name: ruleName,
                sender_filter: ruleSender || null,
                keyword_filter: ruleKeyword || null,
                recipient_filter: ruleRecipient || null,
                webhook_url: ruleWebhook,
                webhook_type: ruleWebhookType
            });

            if (response.success) {
                UI.showMessage('转发规则创建成功', 'success');
                UI.hideModal('userCreateRuleModal');
                // 清空表单
                document.getElementById('userRuleName').value = '';
                document.getElementById('userRuleSender').value = '';
                document.getElementById('userRuleKeyword').value = '';
                document.getElementById('userRuleRecipient').value = '';
                document.getElementById('userRuleWebhook').value = '';
                document.getElementById('userRuleWebhookType').value = 'custom';
                // 重新加载规则列表
                await this.loadRules();
            } else {
                UI.showMessage('创建失败: ' + response.error, 'error');
            }
        } catch (error) {
            console.error('创建转发规则失败:', error);
            UI.showMessage('创建转发规则失败', 'error');
        }
    }
};

// 管理员管理模块
const AdminManager = {
    expandedEmails: new Set(), // 存储展开的邮件ID
    // 加载用户列表
    async loadUsers(searchParams = {}) {
        const usersList = document.getElementById('usersList');
        if (!usersList) return;

        UI.showLoading(usersList);

        try {
            // 构建查询参数
            const params = new URLSearchParams();
            if (searchParams.search) {
                params.append('search', searchParams.search);
            }
            if (searchParams.user_type) {
                params.append('user_type', searchParams.user_type);
            }
            if (searchParams.created_after) {
                params.append('created_after', searchParams.created_after);
            }
            if (searchParams.created_before) {
                params.append('created_before', searchParams.created_before);
            }

            const response = await API.get('/api/admin/users?' + params.toString());
            if (response.success) {
                this.renderUsersList(response.data.users);
            }
        } catch (error) {
            usersList.innerHTML = '<p>加载用户列表失败: ' + (error.message || '未知错误') + '</p>';
        }
    },

    // 搜索用户
    async searchUsers() {
        const searchInput = document.getElementById('userSearch');
        if (!searchInput) return;

        const searchTerm = searchInput.value.trim();
        const searchParams = {};

        if (searchTerm) {
            searchParams.search = searchTerm;
        }

        await this.loadUsers(searchParams);
    },

    // 绑定搜索事件
    bindSearchEvents() {
        const searchInput = document.getElementById('userSearch');
        if (!searchInput) return;

        // 清除之前的事件监听器
        searchInput.removeEventListener('input', this.debouncedSearch);
        searchInput.removeEventListener('keypress', this.handleSearchKeypress);

        // 防抖搜索
        this.debouncedSearch = this.debounce(() => {
            this.searchUsers();
        }, 300);

        // 输入事件
        searchInput.addEventListener('input', this.debouncedSearch);

        // 回车键搜索
        this.handleSearchKeypress = (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                this.searchUsers();
            }
        };
        searchInput.addEventListener('keypress', this.handleSearchKeypress);
    },

    // 防抖函数
    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // 绑定邮件搜索事件
    bindEmailSearchEvents() {
        const searchInput = document.getElementById('adminEmailsSearch');
        if (!searchInput) return;

        // 清除之前的事件监听器
        searchInput.removeEventListener('input', this.debouncedEmailSearch);
        searchInput.removeEventListener('keypress', this.handleEmailSearchKeypress);

        // 防抖搜索
        this.debouncedEmailSearch = this.debounce(() => {
            this.searchAllEmails();
        }, 500);

        // 输入事件
        searchInput.addEventListener('input', this.debouncedEmailSearch);

        // 回车键搜索
        this.handleEmailSearchKeypress = (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                this.searchAllEmails();
            }
        };
        searchInput.addEventListener('keypress', this.handleEmailSearchKeypress);
    },

    // 搜索全部邮件
    searchAllEmails() {
        const searchInput = document.getElementById('adminEmailsSearch');
        if (!searchInput) return;

        const searchTerm = searchInput.value.trim();
        const searchParams = {
            search: searchTerm || undefined
        };

        // 重置到第一页并搜索
        this.loadAllEmails(1, searchParams);
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
            '<thead><tr><th>用户名</th><th>用户类型</th><th>Webhook</th><th>创建时间</th><th>操作</th></tr></thead>' +
            '<tbody>' +
            users.map(user =>
                '<tr>' +
                    '<td>' + this.escapeHtml(user.username) + '</td>' +
                    '<td><span class="badge ' + (user.user_type === 'admin' ? 'badge-admin' : 'badge-user') + '">' +
                        (user.user_type === 'admin' ? '管理员' : '用户') + '</span></td>' +
                    '<td>' + (user.webhook_url ? '✅ 已配置' : '❌ 未配置') + '</td>' +
                    '<td>' + this.formatDate(user.created_at) + '</td>' +
                    '<td>' +
                        '<button class="btn btn-sm btn-primary" style="display:block; margin-bottom: 3px;" onclick="AdminManager.sendUserInfo(' + user.id + ')">发送信息</button> ' +
                        (user.user_type !== 'admin' ? '<button class="btn btn-sm btn-danger" style="display:block; margin-bottom: 0;" onclick="AdminManager.deleteUser(' + user.id + ')">删除</button>' : '') +
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
    async loadAllEmails(page = 1, searchParams = {}) {
        const adminEmailsList = document.getElementById('adminEmailsList');
        if (!adminEmailsList) return;

        UI.showLoading(adminEmailsList);

        try {
            // 构建查询参数
            const params = new URLSearchParams({
                page: page.toString(),
                limit: '20'
            });

            // 添加搜索参数
            if (searchParams.search) {
                params.append('search', searchParams.search);
            }

            const response = await API.get('/api/admin/emails?' + params.toString());
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

        const emailsHtml = emails.map(email => {
            const isExpanded = this.expandedEmails && this.expandedEmails.has(email.id);
            return BaseEmailManager.renderEmailItem(email, isExpanded, 'AdminManager');
        }).join('');

        adminEmailsList.innerHTML = emailsHtml;
    },

    // 复制邮件ID
    copyEmailId(emailId) {
        navigator.clipboard.writeText(emailId.toString()).then(() => {
            UI.showMessage('邮件ID已复制到剪贴板', 'success');
        }).catch(() => {
            UI.showMessage('复制失败', 'error');
        });
    },

    // 显示邮件详情
    showEmailDetail(emailId) {
        // 这里可以打开一个模态框显示更详细的邮件信息
        UI.showMessage('邮件详情功能开发中...', 'info');
    },

    // 删除邮件
    async deleteEmail(emailId) {
        if (!confirm('确定要删除这封邮件吗？此操作不可撤销。')) {
            return;
        }

        try {
            const response = await API.delete('/api/admin/emails/' + emailId);
            if (response.success) {
                UI.showMessage('邮件已删除', 'success');
                // 重新加载邮件列表
                await this.loadAllEmails();
            } else {
                UI.showMessage('删除失败: ' + response.error, 'error');
            }
        } catch (error) {
            UI.showMessage('删除失败: ' + error.message, 'error');
        }
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
                        '<label for="autoApproveMailbox">自动审核邮箱申请</label>' +
                        '<select id="autoApproveMailbox" name="auto_approve_mailbox" class="form-control">' +
                            '<option value="true"' + (config.auto_approve_mailbox ? ' selected' : '') + '>开启</option>' +
                            '<option value="false"' + (!config.auto_approve_mailbox ? ' selected' : '') + '>关闭</option>' +
                        '</select>' +
                    '</div>' +
                '</div>' +
                '<div class="form-col">' +
                    '<div class="form-group">' +
                        '<label for="adminEmail">管理员邮箱</label>' +
                        '<input type="email" id="adminEmail" name="admin_email" class="form-control" value="' + (config.admin_email || '') + '" placeholder="admin@example.com">' +
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
                '<label>支持的域名</label>' +
                '<div id="domainsContainer" class="domains-container">' +
                    config.domains.map(domain => 
                        '<div class="domain-item">' +
                            '<span class="domain-text">' + domain + '</span>' +
                            '<button type="button" class="domain-remove" onclick="AdminManager.removeDomain(this)">&times;</button>' +
                        '</div>'
                    ).join('') +
                '</div>' +
                '<div class="domain-input-group">' +
                    '<input type="text" id="newDomain" class="form-control" placeholder="输入新域名，按回车添加" onkeypress="if(event.key===\\'Enter\\'){event.preventDefault();AdminManager.addDomain();}">' +
                    '<button type="button" class="btn btn-secondary" onclick="AdminManager.addDomain()">+ 添加</button>' +
                '</div>' +
            '</div>' +
            '<div class="form-group">' +
                '<label for="jwtSecret">JWT 密钥</label>' +
                '<input type="text" id="jwtSecret" name="jwt_secret" class="form-control" value="' + (config.jwt_secret === '**********' ? '' : (config.jwt_secret || '')) + '" placeholder="输入新的JWT密钥（留空则不更新）">' +
            '</div>' +
            '<button type="button" class="btn btn-primary" onclick="AdminManager.saveSystemSettings()">保存设置</button>' +
        '</form>';

        systemSettingsForm.innerHTML = settingsHtml;
    },

    // 添加域名
    addDomain() {
        const newDomainInput = document.getElementById('newDomain');
        const domain = newDomainInput.value.trim();
        
        if (!domain) {
            UI.showMessage('请输入域名', 'warning');
            return;
        }
        
        // 验证域名格式
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
        if (!domainRegex.test(domain)) {
            UI.showMessage('域名格式不正确', 'error');
            return;
        }
        
        // 检查是否已存在
        const existingDomains = Array.from(document.querySelectorAll('.domain-text')).map(el => el.textContent);
        if (existingDomains.includes(domain)) {
            UI.showMessage('域名已存在', 'warning');
            return;
        }
        
        // 添加域名块
        const domainsContainer = document.getElementById('domainsContainer');
        const domainItem = document.createElement('div');
        domainItem.className = 'domain-item';
        domainItem.innerHTML = 
            '<span class="domain-text">' + domain + '</span>' +
            '<button type="button" class="domain-remove" onclick="AdminManager.removeDomain(this)">&times;</button>';
        
        domainsContainer.appendChild(domainItem);
        newDomainInput.value = '';
    },
    
    // 删除域名
    removeDomain(button) {
        if (confirm('确定要删除这个域名吗？')) {
            button.parentElement.remove();
        }
    },
    
    // 获取当前域名列表
    getCurrentDomains() {
        return Array.from(document.querySelectorAll('.domain-text')).map(el => el.textContent);
    },

    // 保存系统设置
    async saveSystemSettings() {
        try {
            const allowRegistration = document.getElementById('allowRegistration').value === 'true';
            const debugMode = document.getElementById('debugMode').value === 'true';
            const autoApproveMailbox = document.getElementById('autoApproveMailbox').value === 'true';
            const cleanupDays = parseInt(document.getElementById('cleanupDays').value);
            const maxAttachmentSize = parseInt(document.getElementById('maxAttachmentSize').value) * 1024 * 1024;
            const domains = this.getCurrentDomains();
            console.log(domains)
            const adminEmail = document.getElementById('adminEmail').value;

            const config = {
                allow_registration: allowRegistration,
                debug_mode: debugMode,
                auto_approve_mailbox: autoApproveMailbox,
                cleanup_days: cleanupDays,
                max_attachment_size: maxAttachmentSize,
                domains: domains,
                admin_email: adminEmail
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
            // 设置当前用户ID到全局变量
            window.currentUserId = userId;
            
            // 获取用户信息
            const userResponse = await API.get('/api/admin/users');
            if (!userResponse.success) {
                UI.showMessage('获取用户信息失败', 'error');
                return;
            }

            const user = userResponse.data.users.find(u => u.id === userId);
            if (!user) {
                UI.showMessage('用户不存在', 'error');
                return;
            }

            // 获取系统配置中的域名
            const configResponse = await API.get('/api/system/config');
            const domains = configResponse.success && configResponse.data.config ? configResponse.data.config.domains : ['example.com'];
            const userEmail = user.username + '@' + domains[0];

            // 直接显示模板中的模态框
            const modal = document.getElementById('sendUserInfoModal');
            if (modal) {
                // 设置表单值
                const toInput = document.getElementById('sendUserInfoModalTo');
                const subjectInput = document.getElementById('sendUserInfoModalSubject');
                const contentInput = document.getElementById('sendUserInfoModalContent');
                
                if (toInput) toInput.value = userEmail;
                if (subjectInput) subjectInput.value = '您的临时邮箱账户信息';
                if (contentInput) {
                    contentInput.value = \`您好！

以下是您的临时邮箱账户信息：

用户名：\${this.escapeHtml(user.username)}
完整邮箱：\${this.escapeHtml(userEmail)}
用户类型：\${user.user_type === 'admin' ? '管理员' : '普通用户'}
创建时间：\${this.formatDate(user.created_at)}

请妥善保管您的账户信息。

此致
临时邮箱系统管理员\`;
                }
                
                // 显示模态框
                modal.style.display = 'flex';
                modal.classList.add('show');
            }
            
            // 加载可用的发件人邮箱
            await this.loadSenderEmails();
            
        } catch (error) {
            UI.showMessage('打开发送邮件窗口失败: ' + error.message, 'error');
        }
    },

    // 加载可用的发件人邮箱
    async loadSenderEmails() {
        try {
            const response = await API.get('/api/mailbox/admin/mailboxes?page=1&page_size=100');
            if (response.success) {
                const select = document.getElementById('sendUserInfoModalFrom');
                if (select) {
                    // 添加管理员邮箱选项
                    const adminEmails = response.data.mailboxes
                        .filter(mailbox => mailbox.user_type === 'admin')
                        .map(mailbox => \`<option value="\${this.escapeHtml(mailbox.email_address)}">\${this.escapeHtml(mailbox.email_address)} (管理员)</option>\`)
                        .join('');
                    
                    select.innerHTML = '<option value="">选择发件人邮箱...</option>' + adminEmails;
                }
            }
        } catch (error) {
            console.error('加载发件人邮箱失败:', error);
        }
    },

    // 发送用户信息邮件
    async sendUserInfoEmail(userId) {
        try {
            // 获取表单数据
            const toEmail = document.getElementById('sendUserInfoModalTo')?.value;
            const fromEmail = document.getElementById('sendUserInfoModalFrom')?.value;
            const subject = document.getElementById('sendUserInfoModalSubject')?.value;
            const content = document.getElementById('sendUserInfoModalContent')?.value;

            if (!fromEmail) {
                UI.showMessage('请选择发件人邮箱', 'error');
                return;
            }

            if (!subject || !content) {
                UI.showMessage('请填写邮件主题和内容', 'error');
                return;
            }

            const response = await API.post('/api/admin/users/' + userId + '/send-info', {
                to_email: toEmail,
                from_email: fromEmail,
                subject: subject,
                content: content
            });

            if (response.success) {
                UI.showMessage('用户信息邮件发送成功', 'success');
                UI.hideModal('sendUserInfoModal');
            } else {
                UI.showMessage('发送失败: ' + response.error, 'error');
            }
        } catch (error) {
            UI.showMessage('发送邮件失败: ' + error.message, 'error');
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

    // 编辑转发规则
    async editRule(ruleId) {
        try {
            // 获取规则详情
            const response = await API.get('/api/admin/forward-rules/' + ruleId);
            if (!response.success) {
                UI.showMessage('获取规则详情失败: ' + response.error, 'error');
                return;
            }

            const rule = response.data.rule;
            
            // 创建编辑模态框
            const modalHtml = \`
                <div id="editRuleModal" class="modal show" style="display: flex;">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h3>编辑转发规则</h3>
                            <button class="modal-close" onclick="UI.hideModal('editRuleModal')">取消</button>
                        </div>
                        <div class="modal-body">
                            <form id="editRuleForm">
                                <div class="form-group">
                                    <label for="editRuleName">规则名称:</label>
                                    <input type="text" id="editRuleName" class="form-control" value="\${this.escapeHtml(rule.rule_name)}" required>
                                </div>
                                <div class="form-group">
                                    <label for="editRuleType">Webhook类型:</label>
                                    <select id="editRuleType" class="form-control">
                                        <option value="custom" \${rule.webhook_type === 'custom' ? 'selected' : ''}>自定义</option>
                                        <option value="dingtalk" \${rule.webhook_type === 'dingtalk' ? 'selected' : ''}>钉钉</option>
                                        <option value="feishu" \${rule.webhook_type === 'feishu' ? 'selected' : ''}>飞书</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="editRuleUrl">Webhook URL:</label>
                                    <input type="url" id="editRuleUrl" class="form-control" value="\${this.escapeHtml(rule.webhook_url)}" required>
                                </div>
                                <div class="form-group">
                                    <label for="editRuleSecret">密钥 (可选):</label>
                                    <input type="text" id="editRuleSecret" class="form-control" value="\${this.escapeHtml(rule.webhook_secret || '')}">
                                </div>
                                <div class="form-group">
                                    <label for="editRuleSender">发件人过滤 (可选):</label>
                                    <input type="text" id="editRuleSender" class="form-control" value="\${this.escapeHtml(rule.sender_filter || '')}" placeholder="例如: noreply@example.com">
                                </div>
                                <div class="form-group">
                                    <label for="editRuleKeyword">关键字过滤 (可选):</label>
                                    <input type="text" id="editRuleKeyword" class="form-control" value="\${this.escapeHtml(rule.keyword_filter || '')}" placeholder="例如: 重要">
                                </div>
                                <div class="form-group">
                                    <label for="editRuleRecipient">收件人过滤 (可选):</label>
                                    <select id="editRuleRecipient" class="form-control">
                                        <option value="">选择收件人邮箱（可选）</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>
                                        <input type="checkbox" id="editRuleEnabled" \${rule.enabled ? 'checked' : ''}> 启用规则
                                    </label>
                                </div>
                            </form>
                        </div>
                        <div class="modal-footer">
                            <button class="btn btn-primary" onclick="AdminManager.saveEditRule(\${ruleId})">保存</button>
                            <button class="btn btn-secondary" onclick="UI.hideModal('editRuleModal')">取消</button>
                        </div>
                    </div>
                </div>
            \`;
            
            // 添加模态框到页面
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            
            // 加载收件人邮箱列表并设置当前值
            await this.loadEditRecipientEmails(rule.recipient_filter);
            
        } catch (error) {
            UI.showMessage('编辑规则失败: ' + error.message, 'error');
        }
    },

    // 保存编辑的转发规则
    async saveEditRule(ruleId) {
        try {
            const ruleName = document.getElementById('editRuleName').value.trim();
            const ruleType = document.getElementById('editRuleType').value;
            const ruleUrl = document.getElementById('editRuleUrl').value.trim();
            const ruleSecret = document.getElementById('editRuleSecret').value.trim();
            const ruleSender = document.getElementById('editRuleSender').value.trim();
            const ruleKeyword = document.getElementById('editRuleKeyword').value.trim();
            const ruleRecipient = document.getElementById('editRuleRecipient').value;
            const ruleEnabled = document.getElementById('editRuleEnabled').checked;

            if (!ruleName || !ruleUrl) {
                UI.showMessage('规则名称和Webhook URL不能为空', 'error');
                return;
            }

            if (!ruleUrl.startsWith('http')) {
                UI.showMessage('Webhook URL必须以http或https开头', 'error');
                return;
            }

            const updateData = {
                rule_name: ruleName,
                webhook_type: ruleType,
                webhook_url: ruleUrl,
                webhook_secret: ruleSecret || undefined,
                sender_filter: ruleSender || undefined,
                keyword_filter: ruleKeyword || undefined,
                recipient_filter: ruleRecipient || undefined,
                enabled: ruleEnabled
            };

            const response = await API.put('/api/admin/forward-rules/' + ruleId, updateData);
            if (response.success) {
                UI.showMessage('转发规则更新成功', 'success');
                UI.hideModal('editRuleModal');
                await this.loadForwardRules();
            } else {
                UI.showMessage('更新失败: ' + response.error, 'error');
            }
        } catch (error) {
            UI.showMessage('保存规则失败: ' + error.message, 'error');
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


    // 切换邮件展开状态
    toggleEmailExpansion(emailId) {
        if (this.expandedEmails.has(emailId)) {
            this.expandedEmails.delete(emailId);
        } else {
            this.expandedEmails.add(emailId);
        }
        BaseEmailManager.updateEmailExpansionUI('#adminEmailsList', this.expandedEmails);
    },

    // 一键展开所有邮件
    expandAllEmails() {
        const emailItems = document.querySelectorAll('#adminEmailsList .email-item');
        emailItems.forEach(item => {
            const emailId = parseInt(item.dataset.emailId);
            if (emailId) {
                this.expandedEmails.add(emailId);
            }
        });
        BaseEmailManager.updateEmailExpansionUI('#adminEmailsList', this.expandedEmails);
    },

    // 一键收起所有邮件
    collapseAllEmails() {
        this.expandedEmails.clear();
        BaseEmailManager.updateEmailExpansionUI('#adminEmailsList', this.expandedEmails);
    },

    // 复制邮件ID
    copyEmailId(emailId) {
        navigator.clipboard.writeText(emailId.toString()).then(() => {
            UI.showMessage('邮件ID已复制到剪贴板', 'success');
        }).catch(() => {
            UI.showMessage('复制失败', 'error');
        });
    },

    // 创建用户
    async createUser() {
        const username = document.getElementById('createUserPrefix').value;
        const password = document.getElementById('createUserPassword').value;
        const userType = document.getElementById('createUserType').value;

        if (!username || !password) {
            UI.showMessage('请填写所有必填字段', 'error');
            return;
        }

        try {
            const response = await API.post('/api/admin/users', {
                username: username,
                password: password,
                user_type: userType
            });

            if (response.success) {
                UI.showMessage(response.message, 'success');
                window.closeModal('createUserModal');
                // 清空表单
                document.getElementById('createUserPrefix').value = '';
                document.getElementById('createUserPassword').value = '';
                document.getElementById('createUserType').value = 'user';
                // 刷新用户列表
                await this.loadUsers();
            } else {
                UI.showMessage('创建失败: ' + response.error, 'error');
            }
        } catch (error) {
            console.error('创建用户失败:', error);
            UI.showMessage('创建用户失败', 'error');
        }
    },

    // 创建转发规则
    async createRule() {
        const ruleName = document.getElementById('ruleName').value.trim();
        const ruleSender = document.getElementById('ruleSender').value.trim();
        const ruleKeyword = document.getElementById('ruleKeyword').value.trim();
        const ruleRecipient = document.getElementById('ruleRecipient').value;
        const ruleWebhook = document.getElementById('ruleWebhook').value.trim();
        const ruleWebhookType = document.getElementById('ruleWebhookType').value;

        if (!ruleName || !ruleWebhook) {
            UI.showMessage('规则名称和Webhook URL不能为空', 'error');
            return;
        }

        if (!ruleWebhook.startsWith('http')) {
            UI.showMessage('Webhook URL必须以http或https开头', 'error');
            return;
        }

        try {
            const response = await API.post('/api/admin/forward-rules', {
                rule_name: ruleName,
                sender_filter: ruleSender || undefined,
                keyword_filter: ruleKeyword || undefined,
                recipient_filter: ruleRecipient || undefined,
                webhook_url: ruleWebhook,
                webhook_type: ruleWebhookType,
                enabled: 1
            });

            if (response.success) {
                UI.showMessage('转发规则创建成功', 'success');
                UI.hideModal('createRuleModal');
                // 清空表单
                document.getElementById('ruleName').value = '';
                document.getElementById('ruleSender').value = '';
                document.getElementById('ruleKeyword').value = '';
                document.getElementById('ruleRecipient').value = '';
                document.getElementById('ruleWebhook').value = '';
                document.getElementById('ruleWebhookType').value = 'custom';
                // 刷新规则列表
                await this.loadForwardRules();
            } else {
                UI.showMessage('创建失败: ' + response.error, 'error');
            }
        } catch (error) {
            console.error('创建规则失败:', error);
            UI.showMessage('创建规则失败', 'error');
        }
    },

    // 加载用户邮箱列表到收件人下拉框
    async loadRecipientEmails() {
        try {
            const response = await API.get('/api/mailbox/admin/mailboxes');
            if (response.success) {
                const recipientSelect = document.getElementById('ruleRecipient');
                if (recipientSelect) {
                    // 清空现有选项（保留第一个默认选项）
                    recipientSelect.innerHTML = '<option value="">选择收件人邮箱（可选）</option>';
                    
                    // 添加邮箱选项
                    response.data.mailboxes?.forEach(mailbox => {
                        const option = document.createElement('option');
                        option.value = mailbox.email_address;
                        option.textContent = \`\${mailbox.email_address} (\${mailbox.user_type === 'admin' ? '管理员' : '用户'})\`;
                        recipientSelect.appendChild(option);
                    });
                }
            }
        } catch (error) {
            console.error('加载收件人邮箱列表失败:', error);
        }
    },

    // 加载编辑规则的收件人邮箱列表
    async loadEditRecipientEmails(currentValue) {
        try {
            const response = await API.get('/api/mailbox/admin/mailboxes');
            if (response.success) {
                const recipientSelect = document.getElementById('editRuleRecipient');
                if (recipientSelect) {
                    // 清空现有选项（保留第一个默认选项）
                    recipientSelect.innerHTML = '<option value="">选择收件人邮箱（可选）</option>';
                    
                    // 添加邮箱选项
                    response.data.mailboxes.forEach(mailbox => {
                        const option = document.createElement('option');
                        option.value = mailbox.email_address;
                        option.textContent = \`\${mailbox.email_address} (\${mailbox.user_type === 'admin' ? '管理员' : '用户'})\`;
                        if (currentValue && mailbox.email_address === currentValue) {
                            option.selected = true;
                        }
                        recipientSelect.appendChild(option);
                    });
                }
            }
        } catch (error) {
            console.error('加载编辑收件人邮箱列表失败:', error);
        }
    },

    // 使用BaseEmailManager的方法
    copyEmailId: BaseEmailManager.copyEmailId,
    showEmailDetail: BaseEmailManager.showEmailDetail,
    escapeHtml: BaseEmailManager.escapeHtml,
    safeHtml: BaseEmailManager.safeHtml,
    formatDate: BaseEmailManager.formatDate,

    // 回复邮件（管理员）
    async replyToEmail(emailId) {
        try {
            console.log('[AdminManager] 开始回复邮件:', emailId);
            
            // 获取邮件详情
            const response = await API.get(\`/api/protected/emails/\${emailId}\`);
            if (!response.success) {
                UI.showMessage('获取邮件详情失败', 'error');
                return;
            }
            
            const email = response.data;
            console.log('[AdminManager] 邮件详情:', email);
            
            // 显示回复模态框
            const modal = document.getElementById('replyEmailModal');
            if (modal) {
                modal.style.display = 'flex';
                modal.classList.add('show');
                
                // 填充表单
                const toInput = document.getElementById('replyEmailModalTo');
                const subjectInput = document.getElementById('replyEmailModalSubject');
                const contentInput = document.getElementById('replyEmailModalContent');
                
                if (toInput) toInput.value = email.from_email || '';
                if (subjectInput) subjectInput.value = email.subject ? 'Re: ' + email.subject : 'Re: ';
                if (contentInput) contentInput.value = \`
                
                --- 原邮件 ---
                发件人: \${email.from_email}
                收件人: \${email.to_email}
                时间: \${this.formatDate(email.created_at)}
                主题: \${email.subject}
                
                \${(email.content || '')}\`;
                
                // 加载发件人邮箱列表
                await this.loadReplySenderEmails();
                
                // 存储当前邮件ID
                window.currentReplyEmailId = emailId;
            }
        } catch (error) {
            console.error('[AdminManager] 回复邮件失败:', error);
            UI.showMessage('回复邮件失败: ' + error.message, 'error');
        }
    },

    // 加载回复发件人邮箱列表（管理员）
    async loadReplySenderEmails() {
        try {
            const response = await API.get('/api/mailbox/admin/mailboxes');
            if (response.success) {
                const select = document.getElementById('replyEmailModalFrom');
                if (select) {
                    select.innerHTML = '<option value="">选择发件人邮箱...</option>';
                    response.data.forEach(mailbox => {
                        const option = document.createElement('option');
                        option.value = mailbox.email_address;
                        option.textContent = mailbox.email_address;
                        select.appendChild(option);
                    });
                }
            }
        } catch (error) {
            console.error('[AdminManager] 加载发件人邮箱失败:', error);
        }
    },

    // 发送回复邮件（管理员）
    async sendReplyEmail() {
        try {
            console.log('[AdminManager] 开始发送回复邮件...');
            
            const toEmail = document.getElementById('replyEmailModalTo')?.value;
            const fromEmail = document.getElementById('replyEmailModalFrom')?.value;
            const subject = document.getElementById('replyEmailModalSubject')?.value;
            const content = document.getElementById('replyEmailModalContent')?.value;

            console.log('[AdminManager] 回复邮件数据:', { toEmail, fromEmail, subject, content });

            if (!toEmail || !fromEmail || !subject || !content) {
                UI.showMessage('请填写所有必填字段', 'error');
                return;
            }

            // 验证邮箱格式
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(fromEmail) || !emailRegex.test(toEmail)) {
                UI.showMessage('请输入有效的邮箱地址', 'error');
                return;
            }

            // 发送回复邮件（使用站内邮件API）
            const response = await API.post('/api/admin/users/2/send-info', {
                to: toEmail,
                from: fromEmail,
                subject: subject,
                content: content
            });

            if (response.success) {
                UI.showMessage('回复邮件发送成功', 'success');
                
                // 关闭模态框
                UI.hideModal('replyEmailModal');
                
                // 刷新邮件列表
                await this.loadEmails();
            } else {
                UI.showMessage('发送失败: ' + (response.error || '未知错误'), 'error');
            }
        } catch (error) {
            console.error('[AdminManager] 回复邮件发送失败:', error);
            UI.showMessage('回复邮件发送失败: ' + error.message, 'error');
        }
    }
};

// 调试管理模块
const DebugManager = {
    // 初始化调试部分
    async initializeDebugSection() {
        VueDebug.info('[Debug] 初始化调试部分');
        
        // 更新调试信息
        await this.refreshDebugInfo();
        
        // 设置默认的收件人邮箱
        const toEmailInput = document.getElementById('simTo');
        const currentUser = State.getCurrentUser();
        if (toEmailInput && currentUser) {
            // 获取系统配置中的域名
            try {
                const response = await API.get('/api/system/config');
                if (response.success && response.data.config && response.data.config.domains && response.data.config.domains.length > 0) {
                    toEmailInput.value = currentUser.username + '@' + response.data.config.domains[0];
                } else {
                    toEmailInput.value = currentUser.username + '@example.com';
                }
            } catch (error) {
                toEmailInput.value = currentUser.username + '@example.com';
            }
        }
        
        // 绑定模拟邮件表单提交事件
        setTimeout(() => {
        const simulateForm = document.getElementById('simulateEmailForm');
        if (simulateForm) {
                // 移除之前的事件监听器（如果存在）
                simulateForm.removeEventListener('submit', this.handleSimulateFormSubmit);
                
                // 添加新的事件监听器
                this.handleSimulateFormSubmit = async (e) => {
                e.preventDefault();
                    e.stopPropagation();
                    console.log('[Debug] 模拟邮件表单提交事件触发');
                await this.simulateEmailReceive();
                };
                
                simulateForm.addEventListener('submit', this.handleSimulateFormSubmit);
                console.log('[Debug] 模拟邮件表单事件已绑定');
            } else {
                console.warn('[Debug] 未找到模拟邮件表单元素');
            }
        }, 100);
    },

    // 刷新调试信息
    async refreshDebugInfo() {
        try {
            const now = new Date().toLocaleString();
            
            // 更新系统状态
            const debugSystemStatus = document.getElementById('debugSystemStatus');
            if (debugSystemStatus) {
                debugSystemStatus.textContent = '✅ 运行正常';
                debugSystemStatus.className = 'status-success';
                debugSystemStatus.style.color = '#28a745';
            }
            
            // 更新调试模式状态
            const debugModeStatus = document.getElementById('debugModeStatus');
            if (debugModeStatus) {
                const isDebugMode = State.systemConfig?.debug_mode || 
                                   (typeof window !== 'undefined' && 
                                    (window.location.hostname === 'localhost' || 
                                     window.location.hostname === '127.0.0.1'));
                if (isDebugMode) {
                debugModeStatus.textContent = '✅ 已启用';
                    debugModeStatus.className = 'status-success';
                debugModeStatus.style.color = '#28a745';
                } else {
                    debugModeStatus.textContent = '❌ 已禁用';
                    debugModeStatus.className = 'status-error';
                    debugModeStatus.style.color = '#dc3545';
                }
            }
            
            // 显示当前用户信息
            const debugCurrentUser = document.getElementById('debugCurrentUser');
            if (debugCurrentUser) {
                const currentUser = State.getCurrentUser();
                if (currentUser) {
                    debugCurrentUser.textContent = currentUser.username + ' (' + (currentUser.user_type === 'admin' ? '管理员' : '用户') + ')';
                    debugCurrentUser.style.color = '#28a745';
                } else {
                    debugCurrentUser.textContent = '❌ 未登录';
                    debugCurrentUser.style.color = '#dc3545';
                }
            }
            
            // 显示系统配置
            const debugSystemConfig = document.getElementById('debugSystemConfig');
            if (debugSystemConfig) {
                try {
                    const response = await API.get('/api/system/config');
                    if (response.success) {
                        const config = response.data.config;
                        debugSystemConfig.innerHTML = 
                            '<div style="font-size: 0.9em; line-height: 1.4;">' +
                            '<div>注册: ' + (config.allow_registration ? '✅ 开启' : '❌ 关闭') + '</div>' +
                            '<div>自动审核: ' + (config.auto_approve_mailbox ? '✅ 开启' : '❌ 关闭') + '</div>' +
                            '<div>清理: ' + config.cleanup_days + '天</div>' +
                            '<div>域名: ' + (config.domains ? config.domains.join(', ') : '未配置') + '</div>' +
                            '<div>附件大小: ' + Math.round(config.max_attachment_size / 1024 / 1024) + 'MB</div>' +
                            '</div>';
                        debugSystemConfig.style.color = '#28a745';
                    } else {
                        debugSystemConfig.textContent = '❌ 获取失败';
                        debugSystemConfig.style.color = '#dc3545';
                    }
                } catch (error) {
                    debugSystemConfig.textContent = '❌ 错误: ' + error.message;
                    debugSystemConfig.style.color = '#dc3545';
                }
            }
            
            // 更新最后更新时间
            const debugLastUpdate = document.getElementById('debugLastUpdate');
            if (debugLastUpdate) {
                debugLastUpdate.textContent = now;
                debugLastUpdate.style.color = '#6c757d';
            }
            
        } catch (error) {
            console.error('[Debug] 刷新调试信息失败:', error);
            
            // 显示错误状态
            const debugSystemStatus = document.getElementById('debugSystemStatus');
            if (debugSystemStatus) {
                debugSystemStatus.textContent = '❌ 系统错误';
                debugSystemStatus.className = 'status-error';
                debugSystemStatus.style.color = '#dc3545';
            }
        }
    },

    // 模拟邮件接收
    async simulateEmailReceive() {
        try {
            console.log('[Debug] 开始模拟邮件接收...');
            
            const fromEmail = document.getElementById('simFrom').value;
            const toEmail = document.getElementById('simTo').value;
            const subject = document.getElementById('simSubject').value;
            const contentType = document.getElementById('simContentType').value;
            const content = document.getElementById('simContent').value;

            console.log('[Debug] 表单数据:', { fromEmail, toEmail, subject, contentType, content });

            if (!fromEmail || !toEmail || !subject || !content) {
                UI.showMessage('请填写必填字段：发件人、收件人、主题和内容', 'error');
                return;
            }

            UI.showMessage('正在模拟邮件接收...', 'info');

            console.log('[Debug] 准备调用API...');

            // 调用调试 API
            const response = await API.post('/api/debug/simulate-email', {
                from: fromEmail,
                to: toEmail,
                subject: subject,
                content: content,
                content_type: contentType
            });
            
            console.log('[Debug] API响应:', response);

            if (response.success) {
                UI.showMessage('模拟邮件接收成功', 'success');
                
                // 更新最近模拟邮件信息
                const lastSimulatedEmail = document.getElementById('lastSimulatedEmail');
                if (lastSimulatedEmail) {
                    const now = new Date().toLocaleString();
                    lastSimulatedEmail.textContent = subject + ' (' + now + ')';
                }
                
                // 清空表单
                // this.clearSimulateForm();
                
                // 刷新邮件列表
                if (EmailManager && EmailManager.loadEmails) {
                    await EmailManager.loadEmails();
                }
            } else {
                UI.showMessage('模拟邮件失败: ' + response.error, 'error');
            }
        } catch (error) {
            console.error('[Debug] 模拟邮件失败:', error);
            UI.showMessage('模拟邮件失败: ' + error.message, 'error');
        }
    },

    // 清空模拟表单
    clearSimulateForm() {
        const fromEmailInput = document.getElementById('simFrom');
        const toEmailInput = document.getElementById('simTo');
        const subjectInput = document.getElementById('simSubject');
        const contentTypeInput = document.getElementById('simContentType');
        const contentInput = document.getElementById('simContent');
        
        if (fromEmailInput) fromEmailInput.value = '';
        if (toEmailInput) toEmailInput.value = '';
        if (subjectInput) subjectInput.value = '';
        if (contentTypeInput) contentTypeInput.value = 'text';
        if (contentInput) contentInput.value = '';
        
        UI.showMessage('表单已清空', 'info');
    },

    // 切换内容类型
    toggleContentType() {
        const contentTypeSelect = document.getElementById('simContentType');
        const contentTextarea = document.getElementById('simContent');
        
        if (!contentTypeSelect || !contentTextarea) return;
        
        const contentType = contentTypeSelect.value;
        
        if (contentType === 'html') {
            contentTextarea.placeholder = '请输入HTML内容，例如：<p>这是一封<strong>测试邮件</strong></p>';
        } else {
            contentTextarea.placeholder = '请输入纯文本内容...';
        }
    },

    // 清空调试日志
    clearDebugLogs() {
        if (confirm('确定要清空调试日志吗？')) {
            // 清空控制台（如果可能）
            if (console.clear) {
                console.clear();
            }
            
            // 重置最近模拟邮件
            const lastSimulatedEmail = document.getElementById('lastSimulatedEmail');
            if (lastSimulatedEmail) {
                lastSimulatedEmail.textContent = '无';
            }
            
            UI.showMessage('调试日志已清空', 'info');
        }
    }
};

// 全局刷新配置函数
window.refreshConfig = async function() {
    try {
        UI.showMessage('正在刷新配置...', 'info');
        
        // 重新加载系统配置
        await AuthManager.loadSystemConfig();
        
        // 根据当前页面刷新对应数据
        const currentSection = State.currentSection;
        switch (currentSection) {
            case 'emails':
                await EmailManager.loadEmails();
                break;
            case 'settings':
                await UserManager.loadSettings();
                break;
            case 'mailboxes':
                await MailboxManager.loadUserMailboxes();
                break;
            case 'mailbox-applications':
                await MailboxManager.loadUserApplications();
                break;
            case 'admin-users':
                if (State.currentUser?.user_type === 'admin') {
                    await AdminManager.loadUsers();
                    // 绑定搜索事件
                    AdminManager.bindSearchEvents();
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
                    // 绑定搜索事件
                    AdminManager.bindEmailSearchEvents();
                }
                break;
            case 'admin-mailboxes':
                if (State.currentUser?.user_type === 'admin') {
                    await MailboxManager.loadAdminMailboxes();
                }
                break;
            case 'admin-mailbox-applications':
                if (State.currentUser?.user_type === 'admin') {
                    await MailboxManager.loadAdminApplications();
                    // 绑定搜索事件
                    MailboxManager.bindApplicationSearchEvents();
                }
                break;
            case 'admin-settings':
                if (State.currentUser?.user_type === 'admin') {
                    await AdminManager.loadSystemSettings();
                }
                break;
            case 'debug':
                if (State.systemConfig?.debug_mode) {
                    await DebugManager.refreshDebugInfo();
                }
                break;
        }
        
        UI.showMessage('配置刷新完成', 'success');
    } catch (error) {
        console.error('刷新配置失败:', error);
        UI.showMessage('刷新配置失败: ' + error.message, 'error');
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

// 邮件管理功能绑定
window.EmailManager = EmailManager;
window.AdminManager = AdminManager;
window.DebugManager = DebugManager;

// 邮箱管理模块
const MailboxManager = {
    // 加载用户邮箱列表
    async loadUserMailboxes() {
        try {
            const response = await API.get('/api/mailbox/user/mailboxes');
            if (response.success) {
                this.renderUserMailboxes(response.data.mailboxes);
            } else {
                UI.showMessage('加载邮箱失败: ' + response.error, 'error');
            }
        } catch (error) {
            console.error('加载邮箱失败:', error);
            UI.showMessage('加载邮箱失败', 'error');
        }
    },

    // 渲染用户邮箱列表
    renderUserMailboxes(mailboxes) {
        const container = document.getElementById('mailboxesList');
        if (!container) return;

        if (mailboxes.length === 0) {
            container.innerHTML = '<div class="empty-state">您还没有任何邮箱，点击上方按钮申请新邮箱</div>';
            return;
        }

        const mailboxesHtml = mailboxes.map(mailbox => 
            '<div class="mailbox-item">' +
                '<div class="mailbox-info">' +
                    '<div class="mailbox-address">' +
                        '📮 ' + BaseEmailManager.escapeHtml(mailbox.email_address) +
                        (mailbox.is_default ? '<span class="badge badge-primary">默认</span>' : '') +
                        (mailbox.is_active ? '<span class="badge badge-success">启用</span>' : '<span class="badge badge-secondary">禁用</span>') +
                    '</div>' +
                    '<div class="mailbox-date">创建时间: ' + BaseEmailManager.formatDate(mailbox.created_at) + '</div>' +
                '</div>' +
                    '<div class="mailbox-actions">' +
                        '<button class="btn btn-danger btn-sm" onclick="deleteUserMailbox(' + mailbox.id + ')">删除</button>' +
                    '</div>' +
            '</div>'
        ).join('');

        container.innerHTML = mailboxesHtml;
    },

    // 加载用户申请列表
    async loadUserApplications() {
        try {
            console.log('[MailboxManager] 开始加载用户申请列表...');
            console.log('[MailboxManager] 当前section状态:', document.getElementById('mailboxApplicationsSection')?.className);
            console.log('[MailboxManager] 当前时间:', new Date().toISOString());
            
            const response = await API.get('/api/mailbox/user/applications');
            console.log('[MailboxManager] 用户申请API响应:', response);
            console.log('[MailboxManager] API调用后section状态:', document.getElementById('mailboxApplicationsSection')?.className);
            console.log('[MailboxManager] API调用后时间:', new Date().toISOString());
            
            if (response.success) {
                console.log('[MailboxManager] 用户申请数据:', response.data.applications);
                this.renderUserApplications(response.data.applications);
                console.log('[MailboxManager] 渲染后section状态:', document.getElementById('mailboxApplicationsSection')?.className);
                console.log('[MailboxManager] 渲染后时间:', new Date().toISOString());
                
                // 延迟检查section状态，看是否被其他操作修改
                setTimeout(() => {
                    console.log('[MailboxManager] 延迟检查section状态:', document.getElementById('mailboxApplicationsSection')?.className);
                    console.log('[MailboxManager] 延迟检查时间:', new Date().toISOString());
                }, 100);
            } else {
                console.error('[MailboxManager] 用户申请API错误:', response.error);
                UI.showMessage('加载申请记录失败: ' + response.error, 'error');
            }
        } catch (error) {
            console.error('[MailboxManager] 加载用户申请记录失败:', error);
            console.error('[MailboxManager] 错误详情:', error);
            UI.showMessage('加载申请记录失败', 'error');
        }
    },

    // 渲染用户申请列表
    renderUserApplications(applications) {
        console.log('[MailboxManager] 开始渲染用户申请列表, 数据:', applications);
        
        const container = document.getElementById('applicationsList');
        if (!container) {
            console.error('[MailboxManager] 找不到容器元素 applicationsList');
            return;
        }

        console.log('[MailboxManager] 找到用户申请容器元素:', container);

        if (applications.length === 0) {
            console.log('[MailboxManager] 用户申请列表为空，显示空状态');
            container.innerHTML = '<div class="empty-state">您还没有任何申请记录</div>';
            return;
        }

        const applicationsHtml = applications.map(app => {
            const statusClass = app.status === 'approved' ? 'success' : 
                              app.status === 'rejected' ? 'danger' : 'warning';
            const statusText = app.status === 'approved' ? '已批准' : 
                             app.status === 'rejected' ? '已拒绝' : '待审核';

            return '<div class="application-item">' +
                '<div class="application-info">' +
                    '<div class="application-email">📧 ' + BaseEmailManager.escapeHtml(app.email_address) + '</div>' +
                    '<div class="application-status">' +
                        '<span class="badge badge-' + statusClass + '">' + statusText + '</span>' +
                    '</div>' +
                    '<div class="application-date">申请时间: ' + BaseEmailManager.formatDate(app.applied_at) + '</div>' +
                    (app.reason ? '<div class="application-reason">申请理由: ' + BaseEmailManager.escapeHtml(app.reason) + '</div>' : '') +
                    (app.admin_comment ? '<div class="application-comment">管理员备注: ' + BaseEmailManager.escapeHtml(app.admin_comment) + '</div>' : '') +
                '</div>' +
            '</div>';
        }).join('');

        console.log('[MailboxManager] 生成的用户申请HTML长度:', applicationsHtml.length);
        container.innerHTML = applicationsHtml;
        console.log('[MailboxManager] 用户申请列表渲染完成');
        console.log('[MailboxManager] 渲染完成后section状态:', document.getElementById('mailboxApplicationsSection')?.className);
    },

    // 加载管理员邮箱列表
    async loadAdminMailboxes() {
        try {
            const response = await API.get('/api/mailbox/admin/mailboxes?page=1&page_size=50');
            if (response.success) {
                this.renderAdminMailboxes(response.data.mailboxes);
            } else {
                UI.showMessage('加载邮箱失败: ' + response.error, 'error');
            }
        } catch (error) {
            console.error('加载邮箱失败:', error);
            UI.showMessage('加载邮箱失败', 'error');
        }
    },

    // 渲染管理员邮箱列表
    renderAdminMailboxes(mailboxes) {
        const container = document.getElementById('adminMailboxesList');
        if (!container) return;

        if (mailboxes.length === 0) {
            container.innerHTML = '<div class="empty-state">暂无邮箱</div>';
            return;
        }

        const mailboxesHtml = mailboxes.map(mailbox => 
            '<div class="mailbox-item">' +
                '<div class="mailbox-info">' +
                    '<div class="mailbox-address">' +
                        '📮 ' + BaseEmailManager.escapeHtml(mailbox.email_address) +
                        (mailbox.is_default ? '<span class="badge badge-primary">默认</span>' : '') +
                        (mailbox.is_active ? '<span class="badge badge-success">启用</span>' : '<span class="badge badge-secondary">禁用</span>') +
                    '</div>' +
                    '<div class="mailbox-user">用户: ' + BaseEmailManager.escapeHtml(mailbox.user_username) + ' (' + mailbox.user_type + ')</div>' +
                    '<div class="mailbox-date">创建时间: ' + BaseEmailManager.formatDate(mailbox.created_at) + '</div>' +
                '</div>' +
                '<div class="mailbox-actions">' +
                    '<button class="btn btn-danger btn-sm" onclick="deleteAdminMailbox(' + mailbox.id + ')">删除</button>' +
                '</div>' +
            '</div>'
        ).join('');

        container.innerHTML = mailboxesHtml;
    },

    // 加载管理员申请列表
    async loadAdminApplications(searchParams = {}) {
        try {
            console.log('[MailboxManager] 开始加载管理员申请列表...');
            
            // 构建查询参数
            const params = new URLSearchParams({
                page: '1',
                page_size: '50'
            });
            
            if (searchParams.search) {
                params.append('search', searchParams.search);
            }
            if (searchParams.status) {
                params.append('status', searchParams.status);
            }
            if (searchParams.user_type) {
                params.append('user_type', searchParams.user_type);
            }

            console.log('[MailboxManager] 请求参数:', params.toString());
            const response = await API.get('/api/mailbox/admin/applications?' + params.toString());
            console.log('[MailboxManager] API响应:', response);
            
            if (response.success) {
                console.log('[MailboxManager] 申请数据:', response.data.applications);
                this.renderAdminApplications(response.data.applications);
            } else {
                console.error('[MailboxManager] API错误:', response.error);
                UI.showMessage('加载申请列表失败: ' + response.error, 'error');
            }
        } catch (error) {
            console.error('[MailboxManager] 加载申请列表失败:', error);
            UI.showMessage('加载申请列表失败', 'error');
        }
    },

    // 搜索申请
    async searchApplications() {
        const searchInput = document.getElementById('applicationSearch');
        if (!searchInput) return;

        const searchTerm = searchInput.value.trim();
        const searchParams = {};

        if (searchTerm) {
            searchParams.search = searchTerm;
        }

        await this.loadAdminApplications(searchParams);
    },

    // 绑定申请搜索事件
    bindApplicationSearchEvents() {
        const searchInput = document.getElementById('applicationSearch');
        if (!searchInput) return;

        // 清除之前的事件监听器
        searchInput.removeEventListener('input', this.debouncedApplicationSearch);
        searchInput.removeEventListener('keypress', this.handleApplicationSearchKeypress);

        // 防抖搜索
        this.debouncedApplicationSearch = this.debounce(() => {
            this.searchApplications();
        }, 300);

        // 输入事件
        searchInput.addEventListener('input', this.debouncedApplicationSearch);

        // 回车键搜索
        this.handleApplicationSearchKeypress = (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                this.searchApplications();
            }
        };
        searchInput.addEventListener('keypress', this.handleApplicationSearchKeypress);
    },

    // 渲染管理员申请列表
    renderAdminApplications(applications) {
        console.log('[MailboxManager] 开始渲染申请列表, 数据:', applications);
        
        const container = document.getElementById('adminApplicationsList');
        if (!container) {
            console.error('[MailboxManager] 找不到容器元素 adminApplicationsList');
            return;
        }

        console.log('[MailboxManager] 找到容器元素:', container);

        if (applications.length === 0) {
            console.log('[MailboxManager] 申请列表为空，显示空状态');
            container.innerHTML = '<div class="empty-state">暂无待处理申请</div>';
            return;
        }

        const applicationsHtml = applications.map(app => {
            const statusClass = app.status === 'approved' ? 'success' : 
                              app.status === 'rejected' ? 'danger' : 'warning';
            const statusText = app.status === 'approved' ? '已批准' : 
                             app.status === 'rejected' ? '已拒绝' : '待审核';

            return '<div class="application-item">' +
                '<div class="application-info">' +
                    '<div class="application-email">📧 ' + BaseEmailManager.escapeHtml(app.email_address) + '</div>' +
                    '<div class="application-user">用户: ' + BaseEmailManager.escapeHtml(app.user_username) + '</div>' +
                    '<div class="application-status">' +
                        '<span class="badge badge-' + statusClass + '">' + statusText + '</span>' +
                    '</div>' +
                    '<div class="application-date">申请时间: ' + BaseEmailManager.formatDate(app.applied_at) + '</div>' +
                    (app.reason ? '<div class="application-reason">申请理由: ' + BaseEmailManager.escapeHtml(app.reason) + '</div>' : '') +
                    (app.admin_comment ? '<div class="application-comment">管理员备注: ' + BaseEmailManager.escapeHtml(app.admin_comment) + '</div>' : '') +
                '</div>' +
                '<div class="application-actions">' +
                    (app.status === 'pending' ? 
                        '<button class="btn btn-success btn-sm" onclick="showProcessApplicationModal(' + app.id + ', \\'' + BaseEmailManager.escapeHtml(app.email_address) + '\\', \\'' + BaseEmailManager.escapeHtml(app.user_username) + '\\')">处理</button>' 
                        : '') +
                '</div>' +
            '</div>';
        }).join('');

        console.log('[MailboxManager] 生成的HTML长度:', applicationsHtml.length);
        container.innerHTML = applicationsHtml;
        console.log('[MailboxManager] 申请列表渲染完成');
    }
};

// 管理员功能绑定
window.AdminManager = AdminManager;  // 直接暴露 AdminManager 对象
window.loadSystemSettings = AdminManager.loadSystemSettings.bind(AdminManager);
window.saveSystemSettings = AdminManager.saveSystemSettings.bind(AdminManager);
window.showCreateUserModal = function() { UI.showModal('createUserModal'); };
window.showCreateRuleModal = async function() { 
    UI.showModal('createRuleModal'); 
    await AdminManager.loadRecipientEmails();
};
window.createUser = AdminManager.createUser.bind(AdminManager);
window.createRule = AdminManager.createRule.bind(AdminManager);

// 邮箱管理功能绑定
window.MailboxManager = MailboxManager;
window.showApplyMailboxModal = function() { UI.showModal('applyMailboxModal'); };
window.showCreateMailboxModal = function() { UI.showModal('createMailboxModal'); };
window.submitMailboxApplication = async function() {
    const emailAddress = document.getElementById('applyEmailAddress').value;
    const reason = document.getElementById('applyReason').value;

    if (!emailAddress) {
        UI.showMessage('请输入邮箱地址', 'error');
        return;
    }

    try {
        const response = await API.post('/api/mailbox/user/applications', {
            email_address: emailAddress,
            reason: reason
        });

        if (response.success) {
            UI.showMessage(response.message, 'success');
            window.closeModal('applyMailboxModal');
            // 清空表单
            document.getElementById('applyEmailAddress').value = '';
            document.getElementById('applyReason').value = '';
            // 刷新申请列表
            await MailboxManager.loadUserApplications();
        } else {
            UI.showMessage('申请失败: ' + response.error, 'error');
        }
    } catch (error) {
        console.error('申请失败:', error);
        UI.showMessage('申请失败', 'error');
    }
};

window.createMailbox = async function() {
    const userId = document.getElementById('createMailboxUsername').value;
    const emailAddress = document.getElementById('createMailboxAddress').value;

    if (!userId || !emailAddress) {
        UI.showMessage('请填写所有字段', 'error');
        return;
    }

    try {
        const response = await API.post('/api/mailbox/admin/mailboxes', {
            user_id: parseInt(userId),
            email_address: emailAddress
        });

        if (response.success) {
            UI.showMessage(response.message, 'success');
            window.closeModal('createMailboxModal');
            // 清空表单
            document.getElementById('createMailboxUsername').value = '';
            document.getElementById('createMailboxAddress').value = '';
            // 刷新邮箱列表
            await MailboxManager.loadAdminMailboxes();
        } else {
            UI.showMessage('创建失败: ' + response.error, 'error');
        }
    } catch (error) {
        console.error('创建失败:', error);
        UI.showMessage('创建失败', 'error');
    }
};

window.deleteUserMailbox = async function(mailboxId) {
    if (!confirm('确定要删除这个邮箱吗？')) {
        return;
    }

    try {
        const response = await API.delete('/api/mailbox/user/mailboxes/' + mailboxId);
        if (response.success) {
            UI.showMessage(response.message, 'success');
            await MailboxManager.loadUserMailboxes();
        } else {
            UI.showMessage('删除失败: ' + response.error, 'error');
        }
    } catch (error) {
        console.error('删除失败:', error);
        UI.showMessage('删除失败', 'error');
    }
};


window.deleteAdminMailbox = async function(mailboxId) {
    if (!confirm('确定要删除这个邮箱吗？')) {
        return;
    }

    try {
        const response = await API.delete('/api/mailbox/admin/mailboxes/' + mailboxId);
        if (response.success) {
            UI.showMessage(response.message, 'success');
            await MailboxManager.loadAdminMailboxes();
        } else {
            UI.showMessage('删除失败: ' + response.error, 'error');
        }
    } catch (error) {
        console.error('删除失败:', error);
        UI.showMessage('删除失败', 'error');
    }
};

let currentApplicationId = null;

window.showProcessApplicationModal = function(applicationId, emailAddress, userPrefix) {
    currentApplicationId = applicationId;
    const details = document.getElementById('applicationDetails');
    details.innerHTML = 
        '<div class="application-details">' +
            '<p><strong>邮箱地址:</strong> ' + emailAddress + '</p>' +
            '<p><strong>申请用户:</strong> ' + userPrefix + '</p>' +
        '</div>';
    document.getElementById('adminComment').value = '';
    UI.showModal('processApplicationModal');
};

window.processApplication = async function(action) {
    if (!currentApplicationId) {
        UI.showMessage('无效的申请ID', 'error');
        return;
    }

    const adminComment = document.getElementById('adminComment').value;

    try {
        const response = await API.post('/api/mailbox/admin/applications/' + currentApplicationId + '/process', {
            action: action,
            admin_comment: adminComment
        });

        if (response.success) {
            UI.showMessage(response.message, 'success');
            window.closeModal('processApplicationModal');
            currentApplicationId = null;
            // 刷新申请列表
            await MailboxManager.loadAdminApplications();
        } else {
            UI.showMessage('处理失败: ' + response.error, 'error');
        }
    } catch (error) {
        console.error('处理失败:', error);
        UI.showMessage('处理失败', 'error');
    }
};

// 调试功能绑定
window.simulateEmailReceive = DebugManager.simulateEmailReceive.bind(DebugManager);
window.clearSimulateForm = DebugManager.clearSimulateForm.bind(DebugManager);
window.refreshDebugInfo = DebugManager.refreshDebugInfo.bind(DebugManager);
window.clearDebugLogs = DebugManager.clearDebugLogs.bind(DebugManager);
window.toggleContentType = DebugManager.toggleContentType.bind(DebugManager);

// 站内邮件功能绑定
window.showInternalEmailModal = function() {
    const currentUser = State.getCurrentUser();
    if (!currentUser) {
        UI.showMessage('请先登录', 'error');
        return;
    }

    // 直接显示模板中的模态框
    const modal = document.getElementById('internalEmailModal');
    if (modal) {
        // 设置表单值
        const fromInput = document.getElementById('internalEmailModalFrom');
        const toInput = document.getElementById('internalEmailModalTo');
        const subjectInput = document.getElementById('internalEmailModalSubject');
        const contentInput = document.getElementById('internalEmailModalContent');
        
        if (fromInput) fromInput.value = currentUser.username + '@example.com';
        if (toInput) toInput.value = 'admin@example.com';
        if (subjectInput) subjectInput.value = '站内邮件';
        if (contentInput) contentInput.value = '请输入邮件内容...';
        
        // 显示模态框
        modal.style.display = 'flex';
        modal.classList.add('show');
    }
};

window.sendInternalEmail = EmailManager.sendInternalEmail.bind(EmailManager);
window.clearInternalForm = EmailManager.clearInternalForm.bind(EmailManager);
window.sendReplyEmail = EmailManager.sendReplyEmail.bind(EmailManager);

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
        VueDebug.info('开始初始化应用...');

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
            // 已登录，确保主界面显示
            const loginSection = document.getElementById('loginSection');
            const mainSection = document.getElementById('mainSection');

            if (loginSection) loginSection.classList.add('hidden');
            if (mainSection) mainSection.classList.remove('hidden');

            // 确保侧边栏打开
            UI.openSidebar();
            
            // 根据URL锚点显示对应页面
            const hash = window.location.hash.replace('#', '');
            const targetSection = hash || 'emails';
            console.log('[initApp] 根据URL锚点显示页面:', targetSection);
            UI.showSection(targetSection);
        } else {
            // 未登录，显示登录界面
            const mainSection = document.getElementById('mainSection');
            const loginSection = document.getElementById('loginSection');
            const sidebar = document.getElementById('sidebar');

            if (mainSection) mainSection.classList.add('hidden');
            if (loginSection) loginSection.classList.remove('hidden');
            if (sidebar) sidebar.classList.add('hidden');

            // 加载系统配置（用于显示注册按钮等）
            await AuthManager.loadSystemConfig();
        }

        // 绑定事件监听器
        bindEventListeners();
        
        // 绑定hashchange事件监听器
        window.addEventListener('hashchange', handleHashChange);
        
        // 隐藏加载动画
        const loadingSection = document.getElementById('loadingSection');
        if (loadingSection) {
            loadingSection.classList.add('hidden');
        }

        VueDebug.info('应用初始化完成');
    } catch (error) {
        console.error('应用初始化失败:', error);
        UI.showMessage('应用初始化失败', 'error');
    }
}

// 处理URL锚点变化
function handleHashChange() {
    const hash = window.location.hash.replace('#', '');
    const targetSection = hash || 'emails';
    console.log('[handleHashChange] URL锚点变化，切换到页面:', targetSection);
    
    // 检查用户是否已登录
    if (State.getCurrentUser()) {
        UI.showSection(targetSection);
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
    const emailSearch = document.getElementById('emailsSearch');
    if (emailSearch) {
        let searchTimeout;
        emailSearch.addEventListener('input', function(e) {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(function() {
                EmailManager.searchEmails();
            }, 500);
        });
        
        // 添加回车键搜索
        emailSearch.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                EmailManager.searchEmails();
            }
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
window.DebugManager = DebugManager;
`;
}
