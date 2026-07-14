/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

declare module 'element-plus/es/components/message-box/style/css'
declare module 'element-plus/es/components/message-box/index.mjs'
declare module 'element-plus/es/components/notification/style/css'
declare module 'element-plus/es/components/notification/index.mjs'

// 全局方法类型声明
declare global {
  interface Window {
    $message: any
    showGlobalLoading: (text?: string) => void
    hideGlobalLoading: () => void
  }

  var showGlobalLoading: (text?: string) => void
  var hideGlobalLoading: () => void
}
