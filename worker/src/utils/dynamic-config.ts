/**
 * 动态配置注入器
 * 在Workers中动态生成前端配置，避免网络请求
 */

import { getSystemConfig } from '../services/settings'

export interface FrontendConfig {
  allow_registration: boolean
  debug_mode: boolean
  supported_domains: string[]
  max_attachment_size: number
  api_base_url: string
  version: string
  build_time: string
}

/**
 * 生成前端配置对象
 */
export async function generateFrontendConfig(db: D1Database): Promise<FrontendConfig> {
  try {
    // 从数据库获取系统配置
    const systemConfig = await getSystemConfig(db)

    return {
      allow_registration: systemConfig.allow_registration || false,
      debug_mode: systemConfig.debug_mode || false,
      supported_domains: systemConfig.supported_domains || ['example.com'],
      max_attachment_size: systemConfig.attachment_max_size || 52428800,
      api_base_url: '/api',
      version: 'dev', // Cloudflare Workers环境变量
      build_time: new Date().toISOString()
    }
  } catch (error) {
    console.error('获取系统配置失败:', error)
    // 返回默认配置
    return {
      allow_registration: false,
      debug_mode: false,
      supported_domains: ['example.com'],
      max_attachment_size: 52428800,
      api_base_url: '/api',
      version: 'dev',
      build_time: new Date().toISOString()
    }
  }
}

/**
 * 生成前端配置脚本
 */
export async function generateConfigScript(db: D1Database): Promise<string> {
  const config = await generateFrontendConfig(db)

  return `
// 前端配置 - 由Workers动态生成
window.CEM_CONFIG = ${JSON.stringify(config, null, 2)};

// 配置管理器
window.ConfigManager = {
  // 获取配置（无需网络请求）
  getConfig() {
    return window.CEM_CONFIG;
  },
  
  // 获取特定配置项
  get(key) {
    return window.CEM_CONFIG?.[key];
  },
  
  // 检查是否允许注册
  isRegistrationAllowed() {
    return window.CEM_CONFIG?.allow_registration || false;
  },
  
  // 检查是否启用调试模式
  isDebugMode() {
    return window.CEM_CONFIG?.debug_mode || false;
  },
  
  // 获取支持的域名
  getSupportedDomains() {
    return window.CEM_CONFIG?.supported_domains || ['example.com'];
  },
  
  // 获取最大附件大小
  getMaxAttachmentSize() {
    return window.CEM_CONFIG?.max_attachment_size || 52428800;
  },
  
  // 刷新配置（重新加载页面）
  refresh() {
    window.location.reload();
  }
};

// 初始化配置
console.log('[ConfigManager] 配置已加载:', window.CEM_CONFIG);
`
}

/**
 * 生成环境变量脚本
 */
export function generateEnvScript(): string {
  return `
// 环境变量 - 由Workers动态生成
window.CEM_ENV = {
  NODE_ENV: 'production',
  API_BASE_URL: '/api',
  VERSION: 'dev',
  BUILD_TIME: '${new Date().toISOString()}',
  IS_DEVELOPMENT: false,
  IS_PRODUCTION: true
};
`
}
