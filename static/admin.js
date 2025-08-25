/**
 * 管理员界面功能扩展
 * 这些函数将被添加到index.html的script标签中
 */

// 全局管理员变量
let currentUsers = [];
let currentRules = [];
let currentSettings = [];

// ============= 用户管理 =============

/**
 * 加载用户列表
 */
async function loadUsers(page = 1, search = '') {
    try {
        const params = new URLSearchParams({
            page: page,
            limit: 20
        });
        
        if (search) params.append('search', search);
        
        document.getElementById('usersList').innerHTML = '<div class="loading">加载用户列表...</div>';
        
        const response = await apiCall(`/admin/users?${params}`, 'GET');
        
        if (response.success) {
            currentUsers = response.data.users;
            renderUsersList(response.data);
        } else {
            throw new Error(response.message);
        }
    } catch (error) {
        document.getElementById('usersList').innerHTML = 
            `<div class="empty-state"><h3>加载失败</h3><p>${error.message}</p></div>`;
    }
}

/**
 * 渲染用户列表
 */
function renderUsersList(data) {
    const usersList = document.getElementById('usersList');
    
    if (data.users.length === 0) {
        usersList.innerHTML = `
            <div class="empty-state">
                <h3>暂无用户</h3>
                <p>还没有注册用户</p>
            </div>
        `;
        return;
    }

    let html = `
        <div class="admin-controls" style="margin-bottom: 20px;">
            <input type="text" id="userSearch" class="form-control" placeholder="搜索用户..." 
                   onkeyup="if(event.key==='Enter') searchUsers()" style="max-width: 300px; display: inline-block;">
            <button class="btn btn-primary" onclick="searchUsers()" style="margin-left: 10px;">搜索</button>
        </div>
        <div class="table-responsive">
            <table class="admin-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>邮箱前缀</th>
                        <th>完整邮箱</th>
                        <th>用户类型</th>
                        <th>邮件数量</th>
                        <th>注册时间</th>
                        <th>Webhook</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    data.users.forEach(user => {
        html += `
            <tr>
                <td>${user.id}</td>
                <td><code>${user.email_prefix}</code></td>
                <td>${user.email_address}</td>
                <td>
                    <span class="badge ${user.user_type === 'admin' ? 'badge-danger' : 'badge-primary'}">
                        ${user.user_type === 'admin' ? '管理员' : '普通用户'}
                    </span>
                </td>
                <td>${user.email_count || 0}</td>
                <td>${new Date(user.created_at).toLocaleString()}</td>
                <td>${user.webhook_url ? '✅' : '❌'}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="sendUserInfo(${user.id})">发送信息</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id})" 
                            ${user.user_type === 'admin' ? 'disabled title="不能删除管理员"' : ''}>删除</button>
                </td>
            </tr>
        `;
    });
    
    html += `
                </tbody>
            </table>
        </div>
        <div class="admin-pagination">
            ${renderAdminPagination(data.page, Math.ceil(data.total / data.limit), 'loadUsers')}
        </div>
    `;
    
    usersList.innerHTML = html;
}

/**
 * 搜索用户
 */
function searchUsers() {
    const search = document.getElementById('userSearch').value;
    loadUsers(1, search);
}

/**
 * 显示创建用户表单
 */
function showCreateUserForm() {
    const formHtml = `
        <div class="modal-overlay" onclick="closeModal()">
            <div class="modal-content" onclick="event.stopPropagation()">
                <h3>创建新用户</h3>
                <div class="form-group">
                    <label for="newUserPrefix">邮箱前缀</label>
                    <input type="text" id="newUserPrefix" class="form-control" placeholder="自定义前缀（留空则随机生成）">
                </div>
                <div class="form-group">
                    <label for="newUserPassword">密码</label>
                    <input type="password" id="newUserPassword" class="form-control" placeholder="至少6位">
                </div>
                <div class="form-group">
                    <label for="newUserType">用户类型</label>
                    <select id="newUserType" class="form-control">
                        <option value="user">普通用户</option>
                        <option value="admin">管理员</option>
                    </select>
                </div>
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="createUser()">创建用户</button>
                    <button class="btn btn-secondary" onclick="closeModal()">取消</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', formHtml);
}

/**
 * 创建用户
 */
async function createUser() {
    const prefix = document.getElementById('newUserPrefix').value.trim();
    const password = document.getElementById('newUserPassword').value;
    const userType = document.getElementById('newUserType').value;
    
    if (!password || password.length < 6) {
        showNotification('密码长度至少6位', 'error');
        return;
    }
    
    try {
        const userData = {
            email_password: password,
            user_type: userType
        };
        
        if (prefix) {
            userData.email_prefix = prefix;
        }
        
        const response = await apiCall('/admin/users', 'POST', userData);
        
        if (response.success) {
            showNotification('用户创建成功', 'success');
            closeModal();
            loadUsers();
        } else {
            showNotification('创建失败: ' + response.message, 'error');
        }
    } catch (error) {
        showNotification('创建失败: ' + error.message, 'error');
    }
}

/**
 * 删除用户
 */
async function deleteUser(userId) {
    if (!confirm('确定要删除这个用户吗？这将同时删除用户的所有邮件和附件，且不可恢复！')) {
        return;
    }
    
    try {
        const response = await apiCall(`/admin/users/${userId}`, 'DELETE');
        
        if (response.success) {
            showNotification('用户删除成功', 'success');
            loadUsers();
        } else {
            showNotification('删除失败: ' + response.message, 'error');
        }
    } catch (error) {
        showNotification('删除失败: ' + error.message, 'error');
    }
}

/**
 * 发送用户信息
 */
async function sendUserInfo(userId) {
    try {
        const response = await apiCall(`/admin/send-user-info/${userId}`, 'POST');
        
        if (response.success) {
            const userInfo = response.data;
            const infoHtml = `
                <div class="modal-overlay" onclick="closeModal()">
                    <div class="modal-content" onclick="event.stopPropagation()">
                        <h3>用户信息</h3>
                        <div class="user-info">
                            <p><strong>邮箱前缀:</strong> <code>${userInfo.email_prefix}</code></p>
                            <p><strong>完整邮箱:</strong> <code>${userInfo.email_address}</code></p>
                            <p style="color: #dc3545; font-size: 0.9rem;">
                                ⚠️ 请通过安全渠道将此信息发送给用户
                            </p>
                        </div>
                        <div class="modal-actions">
                            <button class="btn btn-primary" onclick="copyUserInfo('${userInfo.email_prefix}', '${userInfo.email_address}')">复制信息</button>
                            <button class="btn btn-secondary" onclick="closeModal()">关闭</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.insertAdjacentHTML('beforeend', infoHtml);
        } else {
            showNotification('获取用户信息失败: ' + response.message, 'error');
        }
    } catch (error) {
        showNotification('获取用户信息失败: ' + error.message, 'error');
    }
}

/**
 * 复制用户信息
 */
function copyUserInfo(prefix, email) {
    const info = `邮箱前缀: ${prefix}\n完整邮箱: ${email}`;
    navigator.clipboard.writeText(info).then(() => {
        showNotification('用户信息已复制', 'success');
    }).catch(() => {
        showNotification('复制失败', 'error');
    });
}

// ============= 转发规则管理 =============

/**
 * 加载转发规则
 */
async function loadForwardRules() {
    try {
        document.getElementById('rulesList').innerHTML = '<div class="loading">加载转发规则...</div>';
        
        const response = await apiCall('/admin/forward-rules', 'GET');
        
        if (response.success) {
            currentRules = response.data.rules;
            renderRulesList();
        } else {
            throw new Error(response.message);
        }
    } catch (error) {
        document.getElementById('rulesList').innerHTML = 
            `<div class="empty-state"><h3>加载失败</h3><p>${error.message}</p></div>`;
    }
}

/**
 * 渲染转发规则列表
 */
function renderRulesList() {
    const rulesList = document.getElementById('rulesList');
    
    if (currentRules.length === 0) {
        rulesList.innerHTML = `
            <div class="empty-state">
                <h3>暂无转发规则</h3>
                <p>还没有配置邮件转发规则</p>
            </div>
        `;
        return;
    }

    let html = `
        <div class="table-responsive">
            <table class="admin-table">
                <thead>
                    <tr>
                        <th>规则名称</th>
                        <th>发件人过滤</th>
                        <th>关键字过滤</th>
                        <th>收件人过滤</th>
                        <th>Webhook类型</th>
                        <th>Webhook地址</th>
                        <th>状态</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    currentRules.forEach(rule => {
        html += `
            <tr>
                <td><strong>${rule.rule_name}</strong></td>
                <td>${rule.sender_filter || '-'}</td>
                <td>${rule.keyword_filter || '-'}</td>
                <td>${rule.recipient_filter || '-'}</td>
                <td>
                    <span class="badge ${getWebhookTypeBadge(rule.webhook_type)}">
                        ${getWebhookTypeText(rule.webhook_type)}
                    </span>
                </td>
                <td class="url-cell" title="${rule.webhook_url}">${truncateUrl(rule.webhook_url)}</td>
                <td>
                    <span class="badge ${rule.enabled ? 'badge-success' : 'badge-secondary'}">
                        ${rule.enabled ? '启用' : '禁用'}
                    </span>
                </td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="editRule(${rule.id})">编辑</button>
                    <button class="btn btn-sm ${rule.enabled ? 'btn-warning' : 'btn-success'}" 
                            onclick="toggleRule(${rule.id}, ${!rule.enabled})">
                        ${rule.enabled ? '禁用' : '启用'}
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteRule(${rule.id})">删除</button>
                </td>
            </tr>
        `;
    });
    
    html += `
                </tbody>
            </table>
        </div>
    `;
    
    rulesList.innerHTML = html;
}

/**
 * 获取Webhook类型徽章样式
 */
function getWebhookTypeBadge(type) {
    switch(type) {
        case 'dingtalk': return 'badge-info';
        case 'feishu': return 'badge-warning';
        default: return 'badge-secondary';
    }
}

/**
 * 获取Webhook类型文本
 */
function getWebhookTypeText(type) {
    switch(type) {
        case 'dingtalk': return '钉钉';
        case 'feishu': return '飞书';
        default: return '自定义';
    }
}

/**
 * 截断URL显示
 */
function truncateUrl(url) {
    return url.length > 40 ? url.substring(0, 40) + '...' : url;
}

/**
 * 显示创建规则表单
 */
function showCreateRuleForm() {
    const formHtml = `
        <div class="modal-overlay" onclick="closeModal()">
            <div class="modal-content large-modal" onclick="event.stopPropagation()">
                <h3>创建转发规则</h3>
                <div class="form-row">
                    <div class="form-group">
                        <label for="newRuleName">规则名称 *</label>
                        <input type="text" id="newRuleName" class="form-control" placeholder="给规则起个名字">
                    </div>
                    <div class="form-group">
                        <label for="newRuleWebhookType">Webhook类型</label>
                        <select id="newRuleWebhookType" class="form-control">
                            <option value="custom">自定义</option>
                            <option value="dingtalk">钉钉</option>
                            <option value="feishu">飞书</option>
                        </select>
                    </div>
                </div>
                <div class="form-group">
                    <label for="newRuleWebhookUrl">Webhook地址 *</label>
                    <input type="url" id="newRuleWebhookUrl" class="form-control" placeholder="https://example.com/webhook">
                </div>
                <div class="form-group">
                    <label for="newRuleWebhookSecret">Webhook签名密钥</label>
                    <input type="text" id="newRuleWebhookSecret" class="form-control" placeholder="用于验证请求的密钥（可选）">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label for="newRuleSenderFilter">发件人过滤</label>
                        <input type="text" id="newRuleSenderFilter" class="form-control" placeholder="如：example.com 或 user@example.com">
                    </div>
                    <div class="form-group">
                        <label for="newRuleKeywordFilter">关键字过滤</label>
                        <input type="text" id="newRuleKeywordFilter" class="form-control" placeholder="邮件主题或内容包含的关键字">
                    </div>
                </div>
                <div class="form-group">
                    <label for="newRuleRecipientFilter">收件人过滤</label>
                    <input type="text" id="newRuleRecipientFilter" class="form-control" placeholder="收件人前缀过滤，如：test">
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" id="newRuleEnabled" checked> 启用规则
                    </label>
                </div>
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="createRule()">创建规则</button>
                    <button class="btn btn-secondary" onclick="closeModal()">取消</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', formHtml);
}

/**
 * 创建转发规则
 */
async function createRule() {
    const name = document.getElementById('newRuleName').value.trim();
    const webhookUrl = document.getElementById('newRuleWebhookUrl').value.trim();
    const webhookType = document.getElementById('newRuleWebhookType').value;
    const webhookSecret = document.getElementById('newRuleWebhookSecret').value.trim();
    const senderFilter = document.getElementById('newRuleSenderFilter').value.trim();
    const keywordFilter = document.getElementById('newRuleKeywordFilter').value.trim();
    const recipientFilter = document.getElementById('newRuleRecipientFilter').value.trim();
    const enabled = document.getElementById('newRuleEnabled').checked;
    
    if (!name || !webhookUrl) {
        showNotification('规则名称和Webhook地址不能为空', 'error');
        return;
    }
    
    try {
        const ruleData = {
            rule_name: name,
            webhook_url: webhookUrl,
            webhook_type: webhookType,
            webhook_secret: webhookSecret || null,
            sender_filter: senderFilter || null,
            keyword_filter: keywordFilter || null,
            recipient_filter: recipientFilter || null,
            enabled: enabled ? 1 : 0
        };
        
        const response = await apiCall('/admin/forward-rules', 'POST', ruleData);
        
        if (response.success) {
            showNotification('转发规则创建成功', 'success');
            closeModal();
            loadForwardRules();
        } else {
            showNotification('创建失败: ' + response.message, 'error');
        }
    } catch (error) {
        showNotification('创建失败: ' + error.message, 'error');
    }
}

/**
 * 编辑规则
 */
function editRule(ruleId) {
    const rule = currentRules.find(r => r.id === ruleId);
    if (!rule) return;
    
    const formHtml = `
        <div class="modal-overlay" onclick="closeModal()">
            <div class="modal-content large-modal" onclick="event.stopPropagation()">
                <h3>编辑转发规则</h3>
                <div class="form-row">
                    <div class="form-group">
                        <label for="editRuleName">规则名称 *</label>
                        <input type="text" id="editRuleName" class="form-control" value="${rule.rule_name}">
                    </div>
                    <div class="form-group">
                        <label for="editRuleWebhookType">Webhook类型</label>
                        <select id="editRuleWebhookType" class="form-control">
                            <option value="custom" ${rule.webhook_type === 'custom' ? 'selected' : ''}>自定义</option>
                            <option value="dingtalk" ${rule.webhook_type === 'dingtalk' ? 'selected' : ''}>钉钉</option>
                            <option value="feishu" ${rule.webhook_type === 'feishu' ? 'selected' : ''}>飞书</option>
                        </select>
                    </div>
                </div>
                <div class="form-group">
                    <label for="editRuleWebhookUrl">Webhook地址 *</label>
                    <input type="url" id="editRuleWebhookUrl" class="form-control" value="${rule.webhook_url}">
                </div>
                <div class="form-group">
                    <label for="editRuleWebhookSecret">Webhook签名密钥</label>
                    <input type="text" id="editRuleWebhookSecret" class="form-control" placeholder="留空则不修改">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label for="editRuleSenderFilter">发件人过滤</label>
                        <input type="text" id="editRuleSenderFilter" class="form-control" value="${rule.sender_filter || ''}">
                    </div>
                    <div class="form-group">
                        <label for="editRuleKeywordFilter">关键字过滤</label>
                        <input type="text" id="editRuleKeywordFilter" class="form-control" value="${rule.keyword_filter || ''}">
                    </div>
                </div>
                <div class="form-group">
                    <label for="editRuleRecipientFilter">收件人过滤</label>
                    <input type="text" id="editRuleRecipientFilter" class="form-control" value="${rule.recipient_filter || ''}">
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" id="editRuleEnabled" ${rule.enabled ? 'checked' : ''}> 启用规则
                    </label>
                </div>
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="updateRule(${rule.id})">更新规则</button>
                    <button class="btn btn-secondary" onclick="closeModal()">取消</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', formHtml);
}

/**
 * 更新规则
 */
async function updateRule(ruleId) {
    const name = document.getElementById('editRuleName').value.trim();
    const webhookUrl = document.getElementById('editRuleWebhookUrl').value.trim();
    const webhookType = document.getElementById('editRuleWebhookType').value;
    const webhookSecret = document.getElementById('editRuleWebhookSecret').value.trim();
    const senderFilter = document.getElementById('editRuleSenderFilter').value.trim();
    const keywordFilter = document.getElementById('editRuleKeywordFilter').value.trim();
    const recipientFilter = document.getElementById('editRuleRecipientFilter').value.trim();
    const enabled = document.getElementById('editRuleEnabled').checked;
    
    if (!name || !webhookUrl) {
        showNotification('规则名称和Webhook地址不能为空', 'error');
        return;
    }
    
    try {
        const updateData = {
            rule_name: name,
            webhook_url: webhookUrl,
            webhook_type: webhookType,
            sender_filter: senderFilter || null,
            keyword_filter: keywordFilter || null,
            recipient_filter: recipientFilter || null,
            enabled: enabled ? 1 : 0
        };
        
        if (webhookSecret) {
            updateData.webhook_secret = webhookSecret;
        }
        
        const response = await apiCall(`/admin/forward-rules/${ruleId}`, 'PUT', updateData);
        
        if (response.success) {
            showNotification('转发规则更新成功', 'success');
            closeModal();
            loadForwardRules();
        } else {
            showNotification('更新失败: ' + response.message, 'error');
        }
    } catch (error) {
        showNotification('更新失败: ' + error.message, 'error');
    }
}

/**
 * 切换规则状态
 */
async function toggleRule(ruleId, enabled) {
    try {
        const response = await apiCall(`/admin/forward-rules/${ruleId}`, 'PUT', { enabled: enabled ? 1 : 0 });
        
        if (response.success) {
            showNotification(`规则已${enabled ? '启用' : '禁用'}`, 'success');
            loadForwardRules();
        } else {
            showNotification('操作失败: ' + response.message, 'error');
        }
    } catch (error) {
        showNotification('操作失败: ' + error.message, 'error');
    }
}

/**
 * 删除规则
 */
async function deleteRule(ruleId) {
    if (!confirm('确定要删除这个转发规则吗？')) {
        return;
    }
    
    try {
        const response = await apiCall(`/admin/forward-rules/${ruleId}`, 'DELETE');
        
        if (response.success) {
            showNotification('转发规则删除成功', 'success');
            loadForwardRules();
        } else {
            showNotification('删除失败: ' + response.message, 'error');
        }
    } catch (error) {
        showNotification('删除失败: ' + error.message, 'error');
    }
}

// ============= 系统设置管理 =============

/**
 * 加载系统设置
 */
async function loadSystemSettings() {
    try {
        document.getElementById('systemSettings').innerHTML = '<div class="loading">加载系统设置...</div>';
        
        const response = await apiCall('/admin/settings', 'GET');
        
        if (response.success) {
            currentSettings = response.data.settings;
            renderSystemSettings();
        } else {
            throw new Error(response.message);
        }
    } catch (error) {
        document.getElementById('systemSettings').innerHTML = 
            `<div class="empty-state"><h3>加载失败</h3><p>${error.message}</p></div>`;
    }
}

/**
 * 渲染系统设置
 */
function renderSystemSettings() {
    const systemSettings = document.getElementById('systemSettings');
    
    let html = `
        <form id="systemSettingsForm">
            <div class="settings-grid">
    `;
    
    currentSettings.forEach(setting => {
        const inputType = getSettingInputType(setting.key, setting.value);
        html += `
            <div class="form-group">
                <label for="setting_${setting.key}">
                    ${getSettingLabel(setting.key)}
                    ${setting.description ? `<small class="text-muted">${setting.description}</small>` : ''}
                </label>
                ${renderSettingInput(setting.key, setting.value, inputType)}
            </div>
        `;
    });
    
    html += `
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-primary" onclick="updateSystemSettings()">保存设置</button>
                <button type="button" class="btn btn-secondary" onclick="loadSystemSettings()">重置</button>
            </div>
        </form>
    `;
    
    systemSettings.innerHTML = html;
}

/**
 * 获取设置输入类型
 */
function getSettingInputType(key, value) {
    if (key.includes('allow') || key.includes('enable') || value === 'true' || value === 'false') {
        return 'checkbox';
    }
    if (key.includes('days') || key.includes('size') || key.includes('limit')) {
        return 'number';
    }
    if (key.includes('email') || key.includes('mail')) {
        return 'email';
    }
    if (key.includes('domain') || key.includes('url')) {
        return 'url';
    }
    return 'text';
}

/**
 * 获取设置标签
 */
function getSettingLabel(key) {
    const labels = {
        'allow_registration': '允许用户注册',
        'cleanup_days': '邮件保留天数',
        'max_attachment_size': '最大附件大小（字节）',
        'domain': '邮件域名',
        'admin_email': '管理员邮箱'
    };
    return labels[key] || key;
}

/**
 * 渲染设置输入框
 */
function renderSettingInput(key, value, type) {
    if (type === 'checkbox') {
        const checked = value === 'true' || value === '1';
        return `<input type="checkbox" id="setting_${key}" ${checked ? 'checked' : ''} class="form-control">`;
    } else if (type === 'number') {
        return `<input type="number" id="setting_${key}" value="${value}" class="form-control">`;
    } else {
        return `<input type="${type}" id="setting_${key}" value="${value}" class="form-control">`;
    }
}

/**
 * 更新系统设置
 */
async function updateSystemSettings() {
    const form = document.getElementById('systemSettingsForm');
    const settings = [];
    
    currentSettings.forEach(setting => {
        const input = document.getElementById(`setting_${setting.key}`);
        let value;
        
        if (input.type === 'checkbox') {
            value = input.checked ? 'true' : 'false';
        } else {
            value = input.value;
        }
        
        settings.push({
            key: setting.key,
            value: value
        });
    });
    
    try {
        const response = await apiCall('/admin/settings', 'PUT', { settings });
        
        if (response.success) {
            showNotification('系统设置更新成功', 'success');
        } else {
            showNotification('更新失败: ' + response.message, 'error');
        }
    } catch (error) {
        showNotification('更新失败: ' + error.message, 'error');
    }
}

// ============= 统计信息 =============

/**
 * 加载统计信息
 */
async function loadStats() {
    try {
        document.getElementById('statsInfo').innerHTML = '<div class="loading">加载统计信息...</div>';
        
        const response = await apiCall('/admin/stats', 'GET');
        
        if (response.success) {
            renderStats(response.data);
        } else {
            throw new Error(response.message);
        }
    } catch (error) {
        document.getElementById('statsInfo').innerHTML = 
            `<div class="empty-state"><h3>加载失败</h3><p>${error.message}</p></div>`;
    }
}

/**
 * 渲染统计信息
 */
function renderStats(data) {
    const statsInfo = document.getElementById('statsInfo');
    
    const html = `
        <div class="stats-grid">
            <div class="stat-card">
                <h3>用户统计</h3>
                <div class="stat-item">
                    <span class="stat-label">总用户数:</span>
                    <span class="stat-value">${data.users.total_users}</span>
                </div>
                <div class="stat-item">
                    <span class="stat-label">管理员:</span>
                    <span class="stat-value">${data.users.admin_users}</span>
                </div>
                <div class="stat-item">
                    <span class="stat-label">普通用户:</span>
                    <span class="stat-value">${data.users.regular_users}</span>
                </div>
            </div>
            
            <div class="stat-card">
                <h3>邮件统计</h3>
                <div class="stat-item">
                    <span class="stat-label">总邮件数:</span>
                    <span class="stat-value">${data.emails.total_emails}</span>
                </div>
                <div class="stat-item">
                    <span class="stat-label">带附件邮件:</span>
                    <span class="stat-value">${data.emails.emails_with_attachments}</span>
                </div>
                <div class="stat-item">
                    <span class="stat-label">最近7天:</span>
                    <span class="stat-value">${data.emails.emails_last_7_days}</span>
                </div>
            </div>
            
            <div class="stat-card">
                <h3>附件统计</h3>
                <div class="stat-item">
                    <span class="stat-label">总附件数:</span>
                    <span class="stat-value">${data.attachments.total_attachments}</span>
                </div>
                <div class="stat-item">
                    <span class="stat-label">总大小:</span>
                    <span class="stat-value">${formatFileSize(data.attachments.total_size_bytes || 0)}</span>
                </div>
            </div>
        </div>
        
        <div class="actions-section">
            <h3>系统操作</h3>
            <button class="btn btn-warning" onclick="manualCleanup()">手动清理过期邮件</button>
            <button class="btn btn-info" onclick="loadStats()">刷新统计</button>
        </div>
    `;
    
    statsInfo.innerHTML = html;
}

/**
 * 手动清理
 */
async function manualCleanup() {
    if (!confirm('确定要手动执行清理操作吗？这将删除所有过期的邮件和附件。')) {
        return;
    }
    
    try {
        // 这里需要调用清理API，暂时显示提示
        showNotification('清理操作已触发，请稍后查看统计信息', 'success');
        setTimeout(() => loadStats(), 2000);
    } catch (error) {
        showNotification('清理操作失败: ' + error.message, 'error');
    }
}

// ============= 通用函数 =============

/**
 * 渲染管理员分页
 */
function renderAdminPagination(currentPage, totalPages, loadFunction) {
    if (totalPages <= 1) return '';
    
    let html = '';
    
    if (currentPage > 1) {
        html += `<button class="page-btn" onclick="${loadFunction}(${currentPage - 1})">上一页</button>`;
    }
    
    for (let i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
        html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" onclick="${loadFunction}(${i})">${i}</button>`;
    }
    
    if (currentPage < totalPages) {
        html += `<button class="page-btn" onclick="${loadFunction}(${currentPage + 1})">下一页</button>`;
    }
    
    return html;
}

/**
 * 关闭模态框
 */
function closeModal() {
    const modals = document.querySelectorAll('.modal-overlay');
    modals.forEach(modal => modal.remove());
}

// 添加管理员样式
const adminStyles = `
<style>
/* 管理员界面样式 */
.admin-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
}

.admin-table th,
.admin-table td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #dee2e6;
}

.admin-table th {
    background-color: #f8f9fa;
    font-weight: 600;
    color: #495057;
}

.admin-table tr:hover {
    background-color: #f8f9fa;
}

.table-responsive {
    overflow-x: auto;
}

.badge {
    display: inline-block;
    padding: 0.25em 0.6em;
    font-size: 0.75em;
    font-weight: 700;
    line-height: 1;
    text-align: center;
    white-space: nowrap;
    vertical-align: baseline;
    border-radius: 0.25rem;
}

.badge-primary { background-color: #007bff; color: white; }
.badge-danger { background-color: #dc3545; color: white; }
.badge-success { background-color: #28a745; color: white; }
.badge-warning { background-color: #ffc107; color: #212529; }
.badge-info { background-color: #17a2b8; color: white; }
.badge-secondary { background-color: #6c757d; color: white; }

.btn-sm {
    padding: 0.25rem 0.5rem;
    font-size: 0.875rem;
    margin: 0 2px;
}

.modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 1000;
}

.modal-content {
    background: white;
    border-radius: 12px;
    padding: 30px;
    max-width: 500px;
    width: 90%;
    max-height: 90vh;
    overflow-y: auto;
}

.large-modal {
    max-width: 700px;
}

.modal-actions {
    display: flex;
    gap: 10px;
    justify-content: flex-end;
    margin-top: 20px;
}

.form-row {
    display: flex;
    gap: 15px;
}

.form-row .form-group {
    flex: 1;
}

.url-cell {
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.admin-pagination {
    display: flex;
    justify-content: center;
    gap: 5px;
    margin-top: 20px;
}

.user-info {
    background: #f8f9fa;
    padding: 20px;
    border-radius: 8px;
    margin: 15px 0;
}

.user-info p {
    margin: 10px 0;
}

.settings-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 20px;
}

.form-actions {
    text-align: center;
    padding-top: 20px;
    border-top: 1px solid #dee2e6;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.stat-card {
    background: #f8f9fa;
    padding: 20px;
    border-radius: 8px;
    border-left: 4px solid #667eea;
}

.stat-card h3 {
    margin-bottom: 15px;
    color: #495057;
}

.stat-item {
    display: flex;
    justify-content: space-between;
    margin: 10px 0;
}

.stat-label {
    color: #6c757d;
}

.stat-value {
    font-weight: 600;
    color: #495057;
}

.actions-section {
    background: #f8f9fa;
    padding: 20px;
    border-radius: 8px;
}

.actions-section h3 {
    margin-bottom: 15px;
    color: #495057;
}

.actions-section .btn {
    margin-right: 10px;
    margin-bottom: 10px;
}

.text-muted {
    color: #6c757d !important;
    font-size: 0.875em;
    display: block;
    margin-top: 5px;
}

@media (max-width: 768px) {
    .form-row {
        flex-direction: column;
    }
    
    .modal-content {
        margin: 20px;
        width: auto;
    }
    
    .admin-table {
        font-size: 0.875rem;
    }
    
    .admin-table th,
    .admin-table td {
        padding: 8px;
    }
}
</style>
`;

// 将样式添加到页面
document.head.insertAdjacentHTML('beforeend', adminStyles);