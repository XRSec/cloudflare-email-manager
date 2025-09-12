/**
 * 调试相关工具函数
 */

/**
 * 初始化调试模式
 * 注意：调试模式由系统设置中的 debug_mode 控制，而不是环境变量
 */
export function initDebugMode(env: any): void {
    // 环境变量 cem_debug 仅用于开发环境强制开启调试
    if (env?.cem_debug === 'true') {
        console.log('[调试模式] 通过环境变量强制开启');
        return;
    }
    
    // 生产环境默认关闭 console.debug
    if (!env?.cem_debug) {
        console.debug = function () {};
    }
}

/**
 * 调试日志输出
 */
export function debugLog(message: string, ...args: any[]): void {
    console.debug(`[DEBUG] ${message}`, ...args);
}

/**
 * 错误日志输出
 */
export function errorLog(message: string, error?: any): void {
    console.error(`[ERROR] ${message}`, error);
}

/**
 * 信息日志输出
 */
export function infoLog(message: string, ...args: any[]): void {
    console.log(`[INFO] ${message}`, ...args);
}
