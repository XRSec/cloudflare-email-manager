/**
 * 调试相关工具函数
 */

/**
 * 初始化调试模式
 * 注意：调试模式完全由系统设置中的 debug_mode 控制
 */
export async function initDebugMode(env: any): Promise<void> {
    try {
        // 获取系统配置中的调试模式设置
        const { getSystemConfig } = await import('../services/settings');
        const config = await getSystemConfig(env.DB);

        if (config.debug_mode === 1) {
            console.log('[调试模式] 已启用');
        } else {
            console.log('[调试模式] 已禁用');
        }
    } catch (error) {
        console.warn('[调试模式] 初始化失败，默认禁用:', error);
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
