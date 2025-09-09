// 临时邮箱管理系统 - 前端应用

// 全局变量
let currentUser = null;
let currentToken = null;
let currentSection = 'emails';
let sidebarVisible = false;

// 初始化
window.addEventListener('DOMContentLoaded', () => {
    checkLoginStatus();
});

// ============= 认证相关 =============

// 检查登录状态
async function checkLoginStatus() {
    // 首先尝试从 localStorage 获取 token
    let token = localStorage.getItem('token');
    
    // 如果没有，尝试从 Cookie 获取
    if (!token) {
        const cookies = document.cookie.split(';').reduce((acc, cookie) => {
            const [key, value] = cookie.trim().split('=');
            acc[key] = value;
            return acc;
        }, {});
        token = cookies.auth_token;
    }
    
    if (token) {
        try {
            // 验证 token 有效性并获取用户信息
            const response = await fetch('/api/protected/me', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    currentToken = token;
                    currentUser = result.data;
                    localStorage.setItem('token', token);
                    showMainSection();
                    return;
                }
            }
        } catch (error) {
            console.warn('Token验证失败:', error);
        }
    }
    
    // 如果没有有效的 token，显示登录界面
    document.getElementById('loginSection').classList.remove('hidden');
    document.getElementById('mainSection').classList.add('hidden');
}

// 切换登录/注册标签
function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    document.querySelector(`[onclick="switchTab('${tab}')"]`).classList.add('active');
    document.getElementById(tab + 'Form').classList.add('active');
}

// 注册
async function register() {
    const password = document.getElementById('registerPassword').value;
    
    if (!password || password.length < 6) {
        showNotification('密码长度至少6位', 'error');
        return;
    }

    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email_password: password })
        });

        const result = await response.json();
        
        if (result.success) {
            showNotification('注册成功！', 'success');
            document.getElementById('loginPrefix').value = result.data.email_prefix;
            document.getElementById('loginPassword').value = password;
            switchTab('login');
        } else {
            showNotification(result.message || '注册失败', 'error');
        }
    } catch (error) {
        showNotification('注册失败: ' + error.message, 'error');
    }
}

// 登录
async function login() {
    const prefix = document.getElementById('loginPrefix').value;
    const password = document.getElementById('loginPassword').value;
    
    if (!prefix || !password) {
        showNotification('请填写邮箱前缀和密码', 'error');
        return;
    }

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email_prefix: prefix, email_password: password })
        });

        const result = await response.json();
        
        if (result.success) {
            currentToken = result.data.token;
            currentUser = result.data.user;
            localStorage.setItem('token', currentToken);
            
            showNotification('登录成功！', 'success');
            showMainSection();
        } else {
            showNotification(result.message || '登录失败', 'error');
        }
    } catch (error) {
        showNotification('登录失败: ' + error.message, 'error');
    }
}

// 退出登录
async function logout() {
    try {
        // 调用退出登录 API 来清除服务端 Cookie
        await fetch('/api/logout', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
    } catch (error) {
        console.warn('退出登录API调用失败:', error);
    }
    
    currentToken = null;
    currentUser = null;
    localStorage.removeItem('token');
    
    document.getElementById('loginSection').classList.remove('hidden');
    document.getElementById('mainSection').classList.add('hidden');
    
    // 重置侧边栏
    sidebarVisible = false;
    document.getElementById('sidebar').classList.remove('active');
    
    showNotification('已退出登录', 'success');
}

// ============= 界面管理 =============

// 显示主界面
function showMainSection() {
    document.getElementById('loginSection').classList.add('hidden');
    document.getElementById('mainSection').classList.remove('hidden');
    
    // 更新用户信息
    document.getElementById('userEmail').textContent = currentUser.email_address;
    document.getElementById('userType').textContent = currentUser.user_type === 'admin' ? '管理员' : '普通用户';
    document.getElementById('userAvatar').textContent = currentUser.email_prefix[0].toUpperCase();
    document.getElementById('sidebarUserInfo').textContent = currentUser.email_address;
    
    // 显示/隐藏管理员菜单
    if (currentUser.user_type === 'admin') {
        document.getElementById('adminMenuItems').classList.remove('hidden');
    }
    
    // 显示/隐藏调试菜单（仅在调试模式下显示）
    const isDebugMode = console.debug.toString().indexOf('function () {}') === -1;
    if (isDebugMode) {
        document.getElementById('debugMenuItem').classList.remove('hidden');
    }
    
    // 加载初始数据
    showSection('emails');
    toggleSidebar(); // 自动显示侧边栏
}

// 切换侧边栏
function toggleSidebar() {
    sidebarVisible = !sidebarVisible;
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('mainSection');
    
    if (sidebarVisible) {
        sidebar.classList.add('active');
        if (window.innerWidth > 768) {
            mainContent.classList.add('with-sidebar');
        }
    } else {
        sidebar.classList.remove('active');
        mainContent.classList.remove('with-sidebar');
    }
}

// 显示不同的功能区域
function showSection(section) {
    console.debug('切换到页面区域:', section);
    
    // 隐藏所有区域
    document.querySelectorAll('[id$="Section"]').forEach(el => {
        if (el.id !== 'loginSection' && el.id !== 'mainSection') {
            el.classList.add('hidden');
        }
    });
    
    // 更新侧边栏激活状态
    document.querySelectorAll('.sidebar-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // 显示对应区域
    currentSection = section;
    const elementId = getElementId(section);
    const targetSection = document.getElementById(elementId);
    console.debug('目标页面元素ID:', elementId, '元素:', targetSection);
    if (targetSection) {
        targetSection.classList.remove('hidden');
        console.debug('页面已显示:', section);
    } else {
        console.error('未找到页面元素:', elementId);
    }
    
    // 激活对应的侧边栏项
    const sidebarItems = document.querySelectorAll('.sidebar-item');
    sidebarItems.forEach(item => {
        if (item.textContent.includes(getSectionName(section))) {
            item.classList.add('active');
        }
    });
    
    // 加载对应数据
    loadSectionData(section);
    
    // 在移动端自动关闭侧边栏
    if (window.innerWidth <= 768) {
        toggleSidebar();
    }
}

// 获取区域显示名称和实际的元素ID
function getSectionName(section) {
    const names = {
        'emails': '我的邮件',
        'settings': '账户设置',
        'debug': '调试模式',
        'admin-users': '用户管理',
        'admin-rules': '转发规则',
        'admin-emails': '全部邮件',
        'admin-settings': '系统设置'
    };
    return names[section] || section;
}

// 获取实际的元素ID（处理连字符转换）
function getElementId(section) {
    const idMap = {
        'emails': 'emailsSection',
        'settings': 'settingsSection',
        'debug': 'debugSection',
        'admin-users': 'adminUsersSection',
        'admin-rules': 'adminRulesSection', 
        'admin-emails': 'adminEmailsSection',
        'admin-settings': 'adminSettingsSection'
    };
    return idMap[section] || (section + 'Section');
}

// 加载区域数据
async function loadSectionData(section) {
    switch (section) {
        case 'emails':
            await loadEmails();
            break;
        case 'settings':
            await loadUserSettings();
            break;
        case 'debug':
            console.debug('切换到调试模式页面');
            await initializeDebugSection();
            break;
        case 'admin-users':
            if (currentUser.user_type === 'admin') {
                await loadUsers();
            }
            break;
        case 'admin-rules':
            if (currentUser.user_type === 'admin') {
                await loadForwardRules();
            }
            break;
        case 'admin-emails':
            if (currentUser.user_type === 'admin') {
                await loadAllEmails();
            }
            break;
        case 'admin-settings':
            console.debug('切换到系统设置页面，用户类型:', currentUser?.user_type);
            if (currentUser && currentUser.user_type === 'admin') {
                console.debug('开始加载系统设置...');
                await loadSystemSettings();
            } else {
                console.error('用户不是管理员或用户信息为空');
            }
            break;
    }
}

// ============= 数据加载 =============

// 加载邮件列表
async function loadEmails() {
    try {
        const response = await fetch('/api/protected/emails', {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });

        const result = await response.json();
        
        if (result.success) {
            const emailsHtml = result.data.emails.map(email => `
                <div class="email-item" onclick="showEmailDetail(${email.id})">
                    <div class="email-sender">${email.sender_email}</div>
                    <div class="email-subject">${email.subject || '(无主题)'}</div>
                    <div class="email-date">${new Date(email.received_at).toLocaleString()}</div>
                    ${email.has_attachments ? '<div class="attachment-badge">📎 有附件</div>' : ''}
                </div>
            `).join('');

            document.getElementById('emailList').innerHTML = emailsHtml || '<p style="color: #6c757d; text-align: center; padding: 40px;">暂无邮件</p>';
        }
    } catch (error) {
        console.error('加载邮件失败:', error);
        document.getElementById('emailList').innerHTML = '<p style="color: #dc3545; text-align: center; padding: 40px;">加载失败</p>';
    }
}

// 加载用户设置
async function loadUserSettings() {
    try {
        const response = await fetch('/api/protected/user/settings', {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });

        const result = await response.json();
        
        if (result.success) {
            document.getElementById('settingsWebhookUrl').value = result.data.webhook_url || '';
            // 注意：不显示实际的密钥值，只显示是否已设置
        }
    } catch (error) {
        console.error('加载用户设置失败:', error);
    }
}

// 更新用户设置
async function updateSettings() {
    const password = document.getElementById('settingsPassword').value;
    const webhookUrl = document.getElementById('settingsWebhookUrl').value;
    const webhookSecret = document.getElementById('settingsWebhookSecret').value;

    try {
        const response = await fetch('/api/protected/user/settings', {
            method: 'PUT',
            headers: { 
                'Authorization': `Bearer ${currentToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email_password: password,
                webhook_url: webhookUrl,
                webhook_secret: webhookSecret
            })
        });

        const result = await response.json();
        
        if (result.success) {
            showNotification('设置更新成功', 'success');
            // 清空密码输入框
            document.getElementById('settingsPassword').value = '';
            document.getElementById('settingsWebhookSecret').value = '';
        } else {
            showNotification(result.message || '更新失败', 'error');
        }
    } catch (error) {
        showNotification('更新失败: ' + error.message, 'error');
    }
}

// 加载系统设置
async function loadSystemSettings() {
    try {
        console.debug('开始加载系统设置...');
        const response = await fetch('/api/admin/settings', {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });

        console.debug('API 响应状态:', response.status);
        
        if (!response.ok) {
            throw new Error(`API 调用失败: ${response.status} ${response.statusText}`);
        }

        const result = await response.json();
        console.debug('系统设置 API 响应:', result);
        
        if (result.success) {
            const settings = result.data.settings || [];
            console.debug('系统设置数据:', settings);
            const settingsMap = settings.reduce((acc, setting) => {
                acc[setting.key] = setting.value;
                return acc;
            }, {});
            console.debug('设置映射:', settingsMap);

            const formHtml = `
                <form id="systemSettingsFormElement">
                    <div class="form-row">
                        <div class="form-col">
                            <div class="form-group">
                                <label for="allowRegistration">允许用户注册</label>
                                <select id="allowRegistration" class="form-control">
                                    <option value="true" ${settingsMap.allow_registration === 'true' ? 'selected' : ''}>允许</option>
                                    <option value="false" ${settingsMap.allow_registration === 'false' ? 'selected' : ''}>禁止</option>
                                </select>
                            </div>
                        </div>
                        <div class="form-col">
                            <div class="form-group">
                                <label for="cleanupDays">邮件保留天数</label>
                                <input type="number" id="cleanupDays" class="form-control" value="${settingsMap.cleanup_days || '7'}" min="1">
                            </div>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-col">
                            <div class="form-group">
                                <label for="maxAttachmentSize">最大附件大小 (MB)</label>
                                <input type="number" id="maxAttachmentSize" class="form-control" value="${Math.round((settingsMap.max_attachment_size || '52428800') / 1024 / 1024)}" min="1">
                            </div>
                        </div>
                        <div class="form-col">
                            <div class="form-group">
                                <label for="cookieMaxAge">Cookie有效期 (分钟)</label>
                                <input type="number" id="cookieMaxAge" class="form-control" value="${Math.round((settingsMap.cookie_max_age || '604800') / 60)}" min="60">
                            </div>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-col">
                            <div class="form-group">
                                <label for="domainSetting">域名</label>
                                <input type="text" id="domainSetting" class="form-control" value="${settingsMap.domain || ''}" placeholder="example.com">
                            </div>
                        </div>
                        <div class="form-col">
                            <div class="form-group">
                                <label for="adminEmail">管理员邮箱</label>
                                <input type="email" id="adminEmail" class="form-control" value="${settingsMap.admin_email || ''}" placeholder="admin@example.com">
                            </div>
                        </div>
                    </div>
                    <button type="button" class="btn btn-primary" onclick="updateSystemSettings()">保存系统设置</button>
                </form>
            `;

            const formElement = document.getElementById('systemSettingsForm');
            console.debug('表单容器元素:', formElement);
            if (formElement) {
                formElement.innerHTML = formHtml;
                console.debug('表单HTML已设置');
            } else {
                console.error('未找到 systemSettingsForm 元素');
            }
        } else {
            console.error('API 调用失败:', result.message);
            // 即使 API 失败，也显示默认表单
            showDefaultSystemSettingsForm();
        }
    } catch (error) {
        console.error('加载系统设置失败:', error);
        // 显示默认表单
        showDefaultSystemSettingsForm();
    }
}

// 显示默认的系统设置表单
function showDefaultSystemSettingsForm() {
    console.debug('显示默认系统设置表单');
    const formHtml = `
        <form id="systemSettingsFormElement">
            <div class="form-row">
                <div class="form-col">
                    <div class="form-group">
                        <label for="allowRegistration">允许用户注册</label>
                        <select id="allowRegistration" class="form-control">
                            <option value="true">允许</option>
                            <option value="false" selected>禁止</option>
                        </select>
                    </div>
                </div>
                <div class="form-col">
                    <div class="form-group">
                        <label for="cleanupDays">邮件保留天数</label>
                        <input type="number" id="cleanupDays" class="form-control" value="7" min="1">
                    </div>
                </div>
            </div>
            <div class="form-row">
                <div class="form-col">
                    <div class="form-group">
                        <label for="maxAttachmentSize">最大附件大小 (MB)</label>
                        <input type="number" id="maxAttachmentSize" class="form-control" value="50" min="1">
                    </div>
                </div>
                <div class="form-col">
                    <div class="form-group">
                        <label for="cookieMaxAge">Cookie有效期 (分钟)</label>
                        <input type="number" id="cookieMaxAge" class="form-control" value="10080" min="60">
                    </div>
                </div>
            </div>
            <div class="form-row">
                <div class="form-col">
                    <div class="form-group">
                        <label for="domainSetting">域名</label>
                        <input type="text" id="domainSetting" class="form-control" value="" placeholder="example.com">
                    </div>
                </div>
                <div class="form-col">
                    <div class="form-group">
                        <label for="adminEmail">管理员邮箱</label>
                        <input type="email" id="adminEmail" class="form-control" value="" placeholder="admin@example.com">
                    </div>
                </div>
            </div>
            <button type="button" class="btn btn-primary" onclick="updateSystemSettings()">保存系统设置</button>
        </form>
    `;

    const formElement = document.getElementById('systemSettingsForm');
    console.debug('默认表单容器元素:', formElement);
    if (formElement) {
        formElement.innerHTML = formHtml;
        console.debug('默认表单HTML已设置');
    } else {
        console.error('未找到 systemSettingsForm 元素');
    }
}

// 更新系统设置
async function updateSystemSettings() {
    try {
        const settings = {
            allow_registration: document.getElementById('allowRegistration').value,
            cleanup_days: document.getElementById('cleanupDays').value,
            max_attachment_size: (parseInt(document.getElementById('maxAttachmentSize').value) * 1024 * 1024).toString(),
            cookie_max_age: (parseInt(document.getElementById('cookieMaxAge').value) * 60).toString(),
            domain: document.getElementById('domainSetting').value,
            admin_email: document.getElementById('adminEmail').value
        };

        const response = await fetch('/api/admin/settings', {
            method: 'PUT',
            headers: { 
                'Authorization': `Bearer ${currentToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(settings)
        });

        const result = await response.json();
        
        if (result.success) {
            showNotification('系统设置更新成功', 'success');
        } else {
            showNotification(result.message || '更新失败', 'error');
        }
    } catch (error) {
        showNotification('更新失败: ' + error.message, 'error');
    }
}

// ============= 调试功能 =============

// 初始化调试模式页面
async function initializeDebugSection() {
    console.debug('初始化调试模式页面');
    
    // 检查调试模式状态
    const debugStatus = document.getElementById('debugModeStatus');
    if (debugStatus) {
        // 通过检查 console.debug 是否被重写来判断调试模式
        const isDebugMode = console.debug.toString().indexOf('function () {}') === -1;
        debugStatus.textContent = isDebugMode ? '已启用' : '已禁用';
        debugStatus.style.color = isDebugMode ? '#28a745' : '#dc3545';
    }
    
    // 设置默认的收件人邮箱（当前用户的邮箱）
    const toEmailInput = document.getElementById('simToEmail');
    if (toEmailInput && currentUser) {
        toEmailInput.value = `${currentUser.email_prefix}@${window.location.hostname}`;
    }
}

// 模拟邮件接收
async function simulateEmailReceive() {
    try {
        const fromEmail = document.getElementById('simFromEmail').value;
        const toEmail = document.getElementById('simToEmail').value;
        const subject = document.getElementById('simSubject').value;
        const textContent = document.getElementById('simTextContent').value;
        const htmlContent = document.getElementById('simHtmlContent').value;

        if (!fromEmail || !toEmail || !subject) {
            showNotification('请填写必填字段：发件人、收件人和主题', 'error');
            return;
        }

        // 构造模拟邮件数据
        const simulatedEmail = {
            from: fromEmail,
            to: toEmail,
            subject: subject,
            text: textContent || '这是一封模拟邮件',
            html: htmlContent || `<p>${textContent || '这是一封模拟邮件'}</p>`,
            raw: async () => {
                return new TextEncoder().encode(`From: ${fromEmail}\r\nTo: ${toEmail}\r\nSubject: ${subject}\r\n\r\n${textContent}`);
            },
            attachments: [] // 暂不支持附件模拟
        };

        console.debug('准备模拟邮件:', simulatedEmail);

        // 调用邮件处理接口
        const response = await fetch('/api/debug/simulate-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentToken}`
            },
            body: JSON.stringify(simulatedEmail)
        });

        const result = await response.json();
        
        if (result.success) {
            showNotification('邮件模拟成功！', 'success');
            
            // 更新最近模拟邮件信息
            const lastSimulated = document.getElementById('lastSimulatedEmail');
            if (lastSimulated) {
                lastSimulated.textContent = `${fromEmail} → ${toEmail}: ${subject}`;
            }
            
            // 如果当前在邮件页面，刷新邮件列表
            if (currentSection === 'emails') {
                await loadEmails();
            }
        } else {
            showNotification('邮件模拟失败: ' + result.message, 'error');
        }

    } catch (error) {
        console.error('模拟邮件接收失败:', error);
        showNotification('模拟邮件接收失败', 'error');
    }
}

// 清空模拟表单
function clearSimulateForm() {
    document.getElementById('simFromEmail').value = '';
    document.getElementById('simSubject').value = '';
    document.getElementById('simTextContent').value = '';
    document.getElementById('simHtmlContent').value = '';
    
    // 重新设置收件人邮箱
    const toEmailInput = document.getElementById('simToEmail');
    if (toEmailInput && currentUser) {
        toEmailInput.value = `${currentUser.email_prefix}@${window.location.hostname}`;
    }
}

// ============= 管理员功能（待实现） =============

async function loadUsers() {
    // 实现用户列表加载
    document.getElementById('usersList').innerHTML = '<p>功能开发中...</p>';
}

async function loadForwardRules() {
    // 实现转发规则加载
    document.getElementById('rulesList').innerHTML = '<p>功能开发中...</p>';
}

async function loadAllEmails() {
    // 实现全部邮件加载
    document.getElementById('adminEmailsList').innerHTML = '<p>功能开发中...</p>';
}

function showCreateUserModal() {
    showModal('createUserModal');
}

function showCreateRuleModal() {
    showModal('createRuleModal');
}

function showEmailDetail(emailId) {
    // 实现邮件详情显示
    console.debug('显示邮件详情:', emailId);
}

// ============= 工具函数 =============

// 显示通知
function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// 显示模态框
function showModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

// 关闭模态框
function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

// 响应式处理
window.addEventListener('resize', () => {
    if (window.innerWidth <= 768 && sidebarVisible) {
        document.getElementById('mainSection').classList.remove('with-sidebar');
    } else if (window.innerWidth > 768 && sidebarVisible) {
        document.getElementById('mainSection').classList.add('with-sidebar');
    }
});

// ============= 调试函数（全局暴露） =============

// 调试函数 - 测试 JWT payload 传递
async function debugJWTPayload() {
    try {
        console.debug('当前 token:', currentToken);
        console.debug('当前 cookies:', document.cookie);
        
        const response = await fetch('/api/protected/debug', {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        
        const result = await response.json();
        console.debug('调试 API 响应:', result);
        
        if (result.success) {
            showNotification(`Payload 调试: ${result.data.hasPayload ? '成功' : '失败'}`, result.data.hasPayload ? 'success' : 'error');
        } else {
            showNotification('调试失败: ' + result.error, 'error');
        }
    } catch (error) {
        console.error('调试失败:', error);
        showNotification('调试失败: ' + error.message, 'error');
    }
}

// 调试页面元素
function debugPageElements() {
    console.debug('=== 页面元素调试 ===');
    console.debug('adminSettingsSection 元素:', document.getElementById('adminSettingsSection'));
    console.debug('systemSettingsForm 元素:', document.getElementById('systemSettingsForm'));
    console.debug('当前用户:', currentUser);
    console.debug('当前区域:', currentSection);
    
    // 检查所有相关元素
    const allSections = [
        'emailsSection', 'settingsSection', 'adminUsersSection', 
        'adminRulesSection', 'adminEmailsSection', 'adminSettingsSection', 'debugSection'
    ];
    allSections.forEach(id => {
        const element = document.getElementById(id);
        console.debug(`${id}: `, element, element ? (element.classList.contains('hidden') ? '(隐藏)' : '(显示)') : '(不存在)');
    });
    
    // 尝试直接显示系统设置页面
    const adminSection = document.getElementById('adminSettingsSection');
    if (adminSection) {
        adminSection.classList.remove('hidden');
        console.debug('手动显示了系统设置页面');
    }
}

// 强制加载系统设置（用于调试）
async function forceLoadSystemSettings() {
    console.debug('=== 强制加载系统设置 ===');
    
    // 1. 显示系统设置页面
    showSection('admin-settings');
    
    // 2. 等待一下然后加载设置
    setTimeout(async () => {
        await loadSystemSettings();
    }, 100);
}

// 将调试函数暴露到全局作用域
window.debugJWTPayload = debugJWTPayload;
window.debugPageElements = debugPageElements;
window.forceLoadSystemSettings = forceLoadSystemSettings;
window.initializeDebugSection = initializeDebugSection;
window.simulateEmailReceive = simulateEmailReceive;
window.clearSimulateForm = clearSimulateForm;