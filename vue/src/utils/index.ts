import { ElNotification } from 'element-plus'

// 工具函数
export const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

/**
 * 统一的调试日志工具
 * 根据环境变量决定是否输出日志
 */
const isDebugMode = import.meta.env.DEV || import.meta.env.VITE_DEBUG === 'true'

export const debug = {
  log: (...args: any[]) => {
    if (isDebugMode) {
      console.log(...args)
    }
  },
  error: (...args: any[]) => {
    if (isDebugMode) {
      console.error(...args)
    }
  },
  warn: (...args: any[]) => {
    if (isDebugMode) {
      console.warn(...args)
    }
  },
  info: (...args: any[]) => {
    if (isDebugMode) {
      console.info(...args)
    }
  }
}

/**
 * 统一的消息提示工具
 * 使用 ElNotification 提供一致的用户体验
 * z-index 设置为 3000，高于普通模态框但低于加载动画和特殊模态框
 */
export const toast = {
  /**
   * 成功提示
   */
  success: (message: string, title: string = '成功') => {
    debug.log(`[Toast Success] ${title}: ${message}`)
    ElNotification({
      title,
      message,
      type: 'success',
      duration: 3000,
      position: 'top-right',
      zIndex: 3000
    })
  },

  /**
   * 错误提示
   */
  error: (message: string, title: string = '错误') => {
    debug.error(`[Toast Error] ${title}: ${message}`)
    ElNotification({
      title,
      message,
      type: 'error',
      duration: 4000, // 错误提示显示时间稍长
      position: 'top-right',
      zIndex: 3000
    })
  },

  /**
   * 警告提示
   */
  warning: (message: string, title: string = '警告') => {
    debug.warn(`[Toast Warning] ${title}: ${message}`)
    ElNotification({
      title,
      message,
      type: 'warning',
      duration: 3500,
      position: 'top-right',
      zIndex: 3000
    })
  },

  /**
   * 信息提示
   */
  info: (message: string, title: string = '提示') => {
    debug.info(`[Toast Info] ${title}: ${message}`)
    ElNotification({
      title,
      message,
      type: 'info',
      duration: 3000,
      position: 'top-right',
      zIndex: 3000
    })
  }
}

export const formatDate = (date: string | Date) => {
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).format(new Date(date))
}

export const formatFileSize = (bytes: number) => {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

export const validateEmail = (email: string) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return re.test(email)
}

export const validateUsername = (username: string) => {
  const re = /^[a-zA-Z0-9_-]+$/
  return re.test(username)
}

export const generateId = () => {
  return Math.random().toString(36).substr(2, 9)
}

export const debounce = <T extends (...args: any[]) => any>(
  func: T,
  wait: number
): ((...args: Parameters<T>) => void) => {
  let timeout: NodeJS.Timeout
  return (...args: Parameters<T>) => {
    clearTimeout(timeout)
    timeout = setTimeout(() => func(...args), wait)
  }
}

export const throttle = <T extends (...args: any[]) => any>(
  func: T,
  limit: number
): ((...args: Parameters<T>) => void) => {
  let inThrottle: boolean
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args)
      inThrottle = true
      setTimeout(() => (inThrottle = false), limit)
    }
  }
}
