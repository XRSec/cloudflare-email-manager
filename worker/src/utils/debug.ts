/**
 * 调试相关工具函数
 */

// 全局调试模式状态
let globalDebugMode = false;

/**
 * 设置全局调试模式状态
 */
export function setGlobalDebugMode(enabled: boolean): void {
    globalDebugMode = enabled;
}

/**
 * 获取全局调试模式状态
 */
export function getGlobalDebugMode(): boolean {
    return globalDebugMode;
}

/**
 * 初始化调试模式
 * 注意：调试模式完全由系统设置中的 debug_mode 控制
 */
export async function initDebugMode(env: any): Promise<void> {
    try {
        // 获取系统配置中的调试模式设置
        const { getSystemConfig } = await import('../services/settings');
        const config = await getSystemConfig(env.DB);

        const isEnabled = config.debug_mode === 1;
        setGlobalDebugMode(isEnabled);

        if (isEnabled) {
            console.log('[DEBUG] [系统] 调试模式已启用');
        } else {
            console.log('[DEBUG] [系统] 调试模式已禁用');
        }
    } catch (error) {
        console.warn('[DEBUG] [系统] 调试模式初始化失败，默认禁用:', error);
        setGlobalDebugMode(false);
    }
}

/**
 * 调试日志输出 - 只有在调试模式下才输出
 * @param module 模块名称
 * @param message 日志信息
 * @param args 额外参数
 */
export function debugLog(module: string, message?: any, ...args: any[]): void {
    if (globalDebugMode) {
        if (message === undefined) {
            console.log(`[DEBUG] ${module}`);
        } else {
            console.log(`[DEBUG] [${module}]`, message, ...args);
        }
    }
}

/**
 * 错误日志输出 - 始终输出
 * @param module 模块名称
 * @param message 错误信息
 * @param error 错误对象
 */
export function errorLog(module: string, message?: any, error?: any): void {
    if (message === undefined) {
        console.error(`[ERROR] ${module}`);
    } else if (error === undefined) {
        console.error(`[ERROR] [${module}]`, message);
    } else {
        console.error(`[ERROR] [${module}] ${message}`, error);
    }
}

/**
 * 信息日志输出 - 始终输出
 * @param module 模块名称
 * @param message 信息内容
 * @param args 额外参数
 */
export function infoLog(module: string, message?: any, ...args: any[]): void {
    if (message === undefined) {
        console.log(`[INFO] ${module}`);
    } else {
        console.log(`[INFO] [${module}]`, message, ...args);
    }
}
