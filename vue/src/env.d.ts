/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

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

