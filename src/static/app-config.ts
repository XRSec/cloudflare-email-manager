/**
 * 应用配置管理模块
 * 从 API 获取配置并缓存
 */

export const AppConfig = `
// 配置管理器
const ConfigManager = {
    cache: new Map(),
    cacheTTL: 5 * 60 * 1000, // 5分钟缓存

    // 获取系统配置
    async getSystemConfig(forceRefresh = false) {
        const cacheKey = 'system_config';
        
        // 检查缓存
        if (!forceRefresh && this.isCacheValid(cacheKey)) {
            return this.cache.get(cacheKey).data;
        }

        try {
            const response = await fetch('/api/system/config');
            if (!response.ok) throw new Error('获取配置失败');
            
            const data = await response.json();
            if (data.success) {
                this.setCache(cacheKey, data.data);
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
        
        if (!forceRefresh && this.isCacheValid(cacheKey)) {
            return this.cache.get(cacheKey).data;
        }

        const token = localStorage.getItem('token');
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
                this.setCache(cacheKey, data.data);
                return data.data;
            }
        } catch (error) {
            console.error('获取用户信息失败:', error);
            return null;
        }
    },

    // 设置缓存
    setCache(key, data) {
        this.cache.set(key, {
            data: data,
            timestamp: Date.now()
        });
    },

    // 检查缓存是否有效
    isCacheValid(key) {
        const cached = this.cache.get(key);
        if (!cached) return false;
        
        return (Date.now() - cached.timestamp) < this.cacheTTL;
    },

    // 清空缓存
    clearCache() {
        this.cache.clear();
        console.log('[ConfigManager] 缓存已清空');
    },

    // 刷新特定缓存
    refreshCache(key) {
        this.cache.delete(key);
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

        // 显示/隐藏调试菜单
        const debugMenuItem = document.getElementById('debugMenuItem');
        if (debugMenuItem) {
            if (config.debug_mode) {
                debugMenuItem.classList.remove('hidden');
            } else {
                debugMenuItem.classList.add('hidden');
            }
        }

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
            userEmail.textContent = userInfo.email_prefix + '@' + (ConfigManager.cache.get('system_config')?.data?.domains[0] || 'example.com');
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
    await ConfigManager.init();
    showMessage('配置已刷新', 'success');
};

// 导出到全局
window.ConfigManager = ConfigManager;
`;