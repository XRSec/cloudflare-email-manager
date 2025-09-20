// 页面配置管理
export interface PageConfig {
  // API配置
  api: {
    method: string
    params?: any
  }
  // 缓存配置
  cache: {
    keyPrefix: string
    ttl: number // 毫秒
  }
  // UI配置
  ui: {
    title: string
    icon: string
    showSearch?: boolean
    showActions?: boolean
  }
  // 刷新配置
  refresh: {
    routeName: string
  }
}

// 页面配置映射
export const PAGE_CONFIGS: Record<string, PageConfig> = {
  // 邮箱相关页面
  'mailboxes': {
    api: {
      method: 'getMailboxes',
      params: { scope: undefined }
    },
    cache: {
      keyPrefix: 'user_mailboxes',
      ttl: 2 * 60 * 1000 // 2分钟
    },
    ui: {
      title: '我的邮箱',
      icon: '📮',
      showSearch: false,
      showActions: false
    },
    refresh: {
      routeName: 'mailboxes'
    }
  },
  'admin-mailboxes': {
    api: {
      method: 'getAllMailboxes',
      params: { scope: 'all' }
    },
    cache: {
      keyPrefix: 'admin_mailboxes',
      ttl: 2 * 60 * 1000 // 2分钟
    },
    ui: {
      title: '邮箱管理',
      icon: '📮',
      showSearch: true,
      showActions: true
    },
    refresh: {
      routeName: 'admin-mailboxes'
    }
  },

  // 邮件相关页面
  'emails': {
    api: {
      method: 'getEmails',
      params: { scope: undefined }
    },
    cache: {
      keyPrefix: 'user_emails',
      ttl: 2 * 60 * 1000 // 2分钟
    },
    ui: {
      title: '我的邮件',
      icon: '📧',
      showSearch: false,
      showActions: false
    },
    refresh: {
      routeName: 'emails'
    }
  },
  'admin-emails': {
    api: {
      method: 'getEmails',
      params: { scope: 'all' }
    },
    cache: {
      keyPrefix: 'admin_emails',
      ttl: 2 * 60 * 1000 // 2分钟
    },
    ui: {
      title: '全部邮件',
      icon: '📨',
      showSearch: false,
      showActions: false
    },
    refresh: {
      routeName: 'admin-emails'
    }
  },

  // 系统设置页面
  'admin-settings': {
    api: {
      method: 'getSystemConfig',
      params: {}
    },
    cache: {
      keyPrefix: 'admin_settings_config',
      ttl: 5 * 60 * 1000 // 5分钟
    },
    ui: {
      title: '系统设置',
      icon: '🛠️',
      showSearch: false,
      showActions: true
    },
    refresh: {
      routeName: 'admin-settings'
    }
  },

  // 安全概览页面
  'admin-security-overview': {
    api: {
      method: 'getSecurityStats',
      params: { days: 7 }
    },
    cache: {
      keyPrefix: 'admin_security_stats',
      ttl: 1 * 60 * 1000 // 1分钟
    },
    ui: {
      title: '安全概览',
      icon: '🛡️',
      showSearch: false,
      showActions: true
    },
    refresh: {
      routeName: 'admin-security-overview'
    }
  },

  // 用户管理页面
  'admin-users': {
    api: {
      method: 'getAllUsers',
      params: {}
    },
    cache: {
      keyPrefix: 'admin_users',
      ttl: 2 * 60 * 1000 // 2分钟
    },
    ui: {
      title: '用户管理',
      icon: '👥',
      showSearch: true,
      showActions: true
    },
    refresh: {
      routeName: 'admin-users'
    }
  },

  // 普通用户转发规则页面
  'forward-rules': {
    api: {
      method: 'getForwardRules',
      params: { scope: undefined }
    },
    cache: {
      keyPrefix: 'user_forward_rules',
      ttl: 2 * 60 * 1000 // 2分钟
    },
    ui: {
      title: '我的转发规则',
      icon: '🔄',
      showSearch: true,
      showActions: true
    },
    refresh: {
      routeName: 'forward-rules'
    }
  },

  // 管理员转发规则页面
  'admin-rules': {
    api: {
      method: 'getForwardRules',
      params: { scope: 'all' }
    },
    cache: {
      keyPrefix: 'admin_forward_rules',
      ttl: 2 * 60 * 1000 // 2分钟
    },
    ui: {
      title: '转发管理',
      icon: '🔄',
      showSearch: true,
      showActions: true
    },
    refresh: {
      routeName: 'admin-rules'
    }
  }
}

// 获取页面配置
export function getPageConfig(routeName: string): PageConfig | null {
  return PAGE_CONFIGS[routeName] || null
}

// 检查是否为管理员页面
export function isAdminPage(routeName: string): boolean {
  return routeName.startsWith('admin-')
}

// 生成缓存键
export function generateCacheKey(routeName: string, ...params: any[]): string {
  const config = getPageConfig(routeName)
  if (!config) return `unknown_${routeName}`

  const paramStr = params.length > 0 ? `_${params.join('_')}` : ''
  return `${config.cache.keyPrefix}${paramStr}`
}
