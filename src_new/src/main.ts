/**
 * Vue 3 应用入口文件
 */
import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import { pinia } from './stores'

// 样式文件
import './assets/css/main.css'

// 创建应用实例
const app = createApp(App)

// 使用插件
app.use(pinia)
app.use(router)

// 全局错误处理
app.config.errorHandler = (err, vm, info) => {
  console.error('Vue error:', err, info)
}

// 挂载应用
app.mount('#app')

// 开发环境下的调试信息
if (import.meta.env?.DEV) {
  console.log('🚀 Vue 3 临时邮箱管理系统已启动')
  console.log('📧 基于 Cloudflare Workers + D1 + R2')
  console.log('⚡ Vue 3 + TypeScript + Pinia + Vue Router')
}