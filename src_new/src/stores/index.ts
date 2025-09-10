/**
 * Store 入口文件
 */
import { createPinia } from 'pinia'

export const pinia = createPinia()

// 导出所有 stores
export { useAuthStore } from './auth'
export { useSystemStore } from './system'
export { useEmailStore } from './emails'
export { useUserStore } from './user'
export { useAdminStore } from './admin'

export default pinia