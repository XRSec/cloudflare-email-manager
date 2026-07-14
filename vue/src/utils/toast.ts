import { debug } from './index'

type ToastType = 'success' | 'error' | 'warning' | 'info'

const getNotification = async () => {
  await import('element-plus/es/components/notification/style/css')
  const { ElNotification } = await import('element-plus/es/components/notification/index.mjs')
  return ElNotification
}

const showNotification = (type: ToastType, message: string, title: string, duration: number) => {
  void getNotification().then((ElNotification) => {
    ElNotification({
      title,
      message,
      type,
      duration,
      position: 'top-right',
      zIndex: 3000
    })
  })
}

export const toast = {
  success: (message: string, title = '成功') => {
    debug.log(`[Toast Success] ${title}: ${message}`)
    showNotification('success', message, title, 3000)
  },

  error: (message: string, title = '错误') => {
    debug.error(`[Toast Error] ${title}: ${message}`)
    showNotification('error', message, title, 4000)
  },

  warning: (message: string, title = '警告') => {
    debug.warn(`[Toast Warning] ${title}: ${message}`)
    showNotification('warning', message, title, 3500)
  },

  info: (message: string, title = '提示') => {
    debug.info(`[Toast Info] ${title}: ${message}`)
    showNotification('info', message, title, 3000)
  }
}
