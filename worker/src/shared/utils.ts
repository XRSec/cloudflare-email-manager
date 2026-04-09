/**
 * 共享工具库
 * 前后端通用的工具函数
 */

/**
 * HTML转义函数 - 防止XSS攻击
 */
export function escapeHtml(text: string): string {
    if (typeof text !== 'string') {
        return '';
    }
    
    const map: { [key: string]: string } = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
        '/': '&#x2F;',
        '`': '&#x60;',
        '=': '&#x3D;'
    };
    
    return text.replace(/[&<>"'`=\/]/g, (s) => map[s] || s);
}

/**
 * 格式化日期时间
 */
export function formatDate(dateString: string | Date): string {
    if (!dateString) return '';
    
    try {
        const date = new Date(dateString);
        if (isNaN(date.getTime())) return '';
        
        return date.toLocaleString('zh-CN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    } catch (error) {
        return '';
    }
}

/**
 * 格式化文件大小
 */
export function formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * 生成随机字符串
 */
export function generateRandomString(length: number = 8): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

/**
 * 验证邮箱格式
 */
export function isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * 验证密码强度
 */
export function validatePassword(password: string): { valid: boolean; message: string } {
    if (password.length < 8) {
        return { valid: false, message: '密码长度至少8位' };
    }
    
    if (!/[A-Z]/.test(password)) {
        return { valid: false, message: '密码必须包含大写字母' };
    }
    
    if (!/[a-z]/.test(password)) {
        return { valid: false, message: '密码必须包含小写字母' };
    }
    
    if (!/[0-9]/.test(password)) {
        return { valid: false, message: '密码必须包含数字' };
    }
    
    return { valid: true, message: '密码强度符合要求' };
}

/**
 * 截断文本
 */
export function truncateText(text: string, maxLength: number = 100): string {
    if (!text || text.length <= maxLength) {
        return text;
    }
    return text.substring(0, maxLength) + '...';
}

/**
 * 深度克隆对象
 */
export function deepClone<T>(obj: T): T {
    if (obj === null || typeof obj !== 'object') {
        return obj;
    }
    
    if (obj instanceof Date) {
        return new Date(obj.getTime()) as unknown as T;
    }
    
    if (obj instanceof Array) {
        return obj.map(item => deepClone(item)) as unknown as T;
    }
    
    if (typeof obj === 'object') {
        const clonedObj = {} as T;
        for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                clonedObj[key] = deepClone(obj[key]);
            }
        }
        return clonedObj;
    }
    
    return obj;
}

/**
 * 防抖函数
 */
export function debounce<T extends (...args: any[]) => any>(
    func: T,
    wait: number
): (...args: Parameters<T>) => void {
    let timeout: ReturnType<typeof setTimeout> | null = null;
    
    return (...args: Parameters<T>) => {
        if (timeout) {
            clearTimeout(timeout);
        }
        timeout = setTimeout(() => func(...args), wait);
    };
}

/**
 * 节流函数
 */
export function throttle<T extends (...args: any[]) => any>(
    func: T,
    limit: number
): (...args: Parameters<T>) => void {
    let inThrottle: boolean = false;
    
    return (...args: Parameters<T>) => {
        if (!inThrottle) {
            func(...args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

/**
 * 生成UUID
 */
export function generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

type BrowserGlobal = typeof globalThis & {
    navigator?: {
        userAgent?: string;
    };
    location?: {
        search?: string;
        href?: string;
    };
    history?: {
        replaceState: (data: unknown, unused: string, url?: string | URL | null) => void;
    };
};

function getBrowserGlobal(): BrowserGlobal | null {
    const candidate = globalThis as BrowserGlobal;

    if (!candidate.location || !candidate.history) {
        return null;
    }

    return candidate;
}

/**
 * 检查是否为移动设备
 */
export function isMobile(): boolean {
    const candidate = globalThis as BrowserGlobal;
    const userAgent = candidate.navigator?.userAgent;

    if (!userAgent) return false;

    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
}

/**
 * 获取URL参数
 */
export function getUrlParams(): { [key: string]: string } {
    const browserGlobal = getBrowserGlobal();
    if (!browserGlobal?.location?.search) return {};

    const params: { [key: string]: string } = {};
    const urlParams = new URLSearchParams(browserGlobal.location.search);

    urlParams.forEach((value, key) => {
        params[key] = value;
    });
    
    return params;
}

/**
 * 设置URL参数
 */
export function setUrlParam(key: string, value: string): void {
    const browserGlobal = getBrowserGlobal();
    if (!browserGlobal?.location?.href) return;

    const url = new URL(browserGlobal.location.href);
    url.searchParams.set(key, value);
    browserGlobal.history?.replaceState({}, '', url.toString());
}

/**
 * 移除URL参数
 */
export function removeUrlParam(key: string): void {
    const browserGlobal = getBrowserGlobal();
    if (!browserGlobal?.location?.href) return;

    const url = new URL(browserGlobal.location.href);
    url.searchParams.delete(key);
    browserGlobal.history?.replaceState({}, '', url.toString());
}
