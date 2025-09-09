/**
 * 调试相关工具函数
 */

/**
 * 初始化调试模式
 */
export function initDebugMode(env: any): void {
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
