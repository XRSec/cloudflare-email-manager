/**
 * 应用配置管理模块
 * 从 API 获取配置并缓存到 sessionStorage
 */

export const AppConfig = `
// SessionStorage 缓存管理器
const SessionCache = {
    prefix: 'cem_cache_',
    defaultTTL: 5 * 60 * 1000, // 5分钟缓存
    
    // 设置缓存（自动序列化 JSON）
    set(key, data, ttl) {
        if (!window.sessionStorage) return;
        
        const cacheItem = {
            data: data,
            timestamp: Date.now(),
            ttl: ttl || this.defaultTTL
        };
        
        try {
            sessionStorage.setItem(this.prefix + key, JSON.stringify(cacheItem));
            console.log('[SessionCache] 缓存已设置:', key);
        } catch (error) {
            console.error('[SessionCache] 设置缓存失败:', key, error);
            // 如果配额超出，清理过期缓存
            if (error.name === 'QuotaExceededError') {
                this.cleanExpired();
            }
        }
    },
    
    // 获取缓存（自动反序列化 JSON）
    get(key) {
        if (!window.sessionStorage) return null;
        
        try {
            const serialized = sessionStorage.getItem(this.prefix + key);
            if (!serialized) return null;
            
            const item = JSON.parse(serialized);
            
            // 检查是否过期
            if (Date.now() - item.timestamp > item.ttl) {
                this.delete(key);
                console.log('[SessionCache] 缓存已过期:', key);
                return null;
            }
            
            return item.data;
        } catch (error) {
            console.error('[SessionCache] 获取缓存失败:', key, error);
            this.delete(key);
            return null;
        }
    },
    
    // 删除缓存
    delete(key) {
        if (!window.sessionStorage) return;
        sessionStorage.removeItem(this.prefix + key);
    },
    
    // 清空所有缓存
    clear() {
        if (!window.sessionStorage) return;
        
        const keysToRemove = [];
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            if (key && key.startsWith(this.prefix)) {
                keysToRemove.push(key);
            }
        }
        
        keysToRemove.forEach(key => sessionStorage.removeItem(key));
        console.log('[SessionCache] 已清空缓存');
    },
    
    // 清理过期缓存
    cleanExpired() {
        if (!window.sessionStorage) return;
        
        const keysToCheck = [];
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            if (key && key.startsWith(this.prefix)) {
                keysToCheck.push(key.substring(this.prefix.length));
            }
        }
        
        keysToCheck.forEach(key => {
            this.get(key); // get 方法会自动删除过期项
        });
    }
};

// 持久化存储管理器（仅用于 token）
const PersistentStorage = {
    prefix: 'cem_persist_',
    
    setToken(token) {
        if (window.localStorage) {
            localStorage.setItem(this.prefix + 'token', token);
        }
    },
    
    getToken() {
        if (!window.localStorage) return null;
        return localStorage.getItem(this.prefix + 'token');
    },
    
    removeToken() {
        if (window.localStorage) {
            localStorage.removeItem(this.prefix + 'token');
        }
    }
};

// 配置管理器
const ConfigManager = {
    cacheTTL: 5 * 60 * 1000, // 5分钟缓存

    // 获取系统配置
    async getSystemConfig(forceRefresh = false) {
        const cacheKey = 'system_config';
        
        // 检查缓存
        if (!forceRefresh) {
            const cached = SessionCache.get(cacheKey);
            if (cached) return cached;
        }

        try {
            const response = await fetch('/api/system/config');
            if (!response.ok) throw new Error('获取配置失败');
            
            const data = await response.json();
            if (data.success) {
                SessionCache.set(cacheKey, data.data, this.cacheTTL);
                return data.data;
            }
        } catch (error) {
            console.error('获取系统配置失败:', error);
            // 返回默认配置
            return {
                allow_registration: false,
                debug_mode: false,
                domains: ['example.com'],
                max_attachment_size: 52428800
            };
        }
    },

    // 获取用户信息
    async getUserInfo(forceRefresh = false) {
        const cacheKey = 'user_info';
        
        if (!forceRefresh) {
            const cached = SessionCache.get(cacheKey);
            if (cached) return cached;
        }

        const token = PersistentStorage.getToken();
        if (!token) return null;

        try {
            const response = await fetch('/api/protected/me', {
                headers: {
                    'Authorization': 'Bearer ' + token
                }
            });
            
            if (!response.ok) throw new Error('获取用户信息失败');
            
            const data = await response.json();
            if (data.success) {
                SessionCache.set(cacheKey, data.data, this.cacheTTL);
                return data.data;
            }
        } catch (error) {
            console.error('获取用户信息失败:', error);
            return null;
        }
    },

    // 清空缓存
    clearCache() {
        SessionCache.clear();
        console.log('[ConfigManager] 缓存已清空');
    },

    // 刷新特定缓存
    refreshCache(key) {
        SessionCache.delete(key);
        console.log('[ConfigManager] 缓存已刷新:', key);
    },

    // 初始化配置
    async init() {
        // 获取系统配置
        const config = await this.getSystemConfig();
        
        // 更新UI
        this.updateUIBasedOnConfig(config);
        
        // 获取用户信息
        const userInfo = await this.getUserInfo();
        if (userInfo) {
            this.updateUserUI(userInfo);
        }
        
        return { config, userInfo };
    },

    // 根据配置更新UI
    updateUIBasedOnConfig(config) {
        // 显示/隐藏注册按钮
        const registerTab = document.querySelector('[data-tab="register"]');
        if (registerTab) {
            registerTab.style.display = config.allow_registration ? 'block' : 'none';
        }

        // 调试菜单现在由 State.updateDebugMenuItem() 统一处理

        // 更新域名显示
        const domainElements = document.querySelectorAll('.domain-display');
        domainElements.forEach(el => {
            el.textContent = config.domains[0] || 'example.com';
        });
    },

    // 更新用户UI
    updateUserUI(userInfo) {
        // 更新用户信息显示
        const userEmail = document.getElementById('userEmail');
        if (userEmail) {
            const systemConfig = SessionCache.get('system_config');
            const domain = systemConfig?.domains?.[0] || 'example.com';
            userEmail.textContent = userInfo.username + '@' + domain;
        }

        // 更新用户类型
        const userType = document.getElementById('userType');
        if (userType) {
            userType.textContent = userInfo.user_type === 'admin' ? '管理员' : '普通用户';
        }

        // 显示/隐藏管理员菜单
        const adminMenuItems = document.getElementById('adminMenuItems');
        if (adminMenuItems) {
            if (userInfo.user_type === 'admin') {
                adminMenuItems.classList.remove('hidden');
            } else {
                adminMenuItems.classList.add('hidden');
            }
        }
    }
};

// 全局刷新函数
window.refreshConfig = async function() {
    ConfigManager.clearCache();
    const { config, userInfo } = await ConfigManager.init();
    
    // 更新状态，触发UI更新
    if (window.State) {
        if (config) {
            window.State.setSystemConfig(config);
        }
        if (userInfo) {
            window.State.setCurrentUser(userInfo);
        }
        
        // 确保调试菜单项状态正确更新
        if (window.State.updateDebugMenuItem) {
            window.State.updateDebugMenuItem();
        }
    }
    
    // 刷新前端调试状态
    if (window.FrontendDebug && window.FrontendDebug.init) {
        await window.FrontendDebug.init();
    }
    
    // 刷新调试信息
    if (window.DebugManager && window.DebugManager.refreshDebugInfo) {
        await window.DebugManager.refreshDebugInfo();
    }
    
    // 刷新当前页面数据
    if (window.UI && window.UI.loadSectionData) {
        await window.UI.loadSectionData(window.UI.currentSection || 'emails');
    }
    
    // 再次确保调试菜单项正确显示（防止被loadSectionData覆盖）
    if (window.State && window.State.updateDebugMenuItem) {
        window.State.updateDebugMenuItem();
        
        // 使用setTimeout确保DOM更新完成后再次更新
        setTimeout(() => {
            if (window.State && window.State.updateDebugMenuItem) {
                window.State.updateDebugMenuItem();
            }
        }, 100);
    }
    
    if (window.UI && window.UI.showMessage) {
        window.UI.showMessage('配置已刷新', 'success');
    }
};

// 导出到全局
window.ConfigManager = ConfigManager;
`;