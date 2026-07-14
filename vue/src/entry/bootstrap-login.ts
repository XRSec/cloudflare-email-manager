import { createApp, defineComponent, h, type App as VueApp } from 'vue'
import LoginShellView from './LoginShellView.vue'

let loginAppInstance: VueApp<Element> | null = null

const openFullApp = async () => {
  if (loginAppInstance) {
    loginAppInstance.unmount()
    loginAppInstance = null
  }

  const { mountApp } = await import('./bootstrap-app')
  await mountApp()
}

const LoginShell = defineComponent({
  name: 'LoginShell',
  setup() {
    const handleLoginSuccess = async (user: any) => {
      localStorage.setItem('user_info', JSON.stringify(user))
      await openFullApp()
    }

    return () => h(LoginShellView, {
      onLoginSuccess: handleLoginSuccess
    })
  }
})

export async function mountLoginApp() {
  if (loginAppInstance) {
    return loginAppInstance
  }

  const app = createApp(LoginShell)
  app.mount('#app')

  loginAppInstance = app

  window.handleLoginSuccess = async () => {
    await openFullApp()
  }

  try {
    const response = await fetch('/api/users/me', {
      credentials: 'include'
    })
    const result = await response.json()

    if (result.success && result.data) {
      localStorage.setItem('user_info', JSON.stringify(result.data))
      await openFullApp()
    }
  } catch (error) {
    console.warn('登录壳会话检查未命中有效会话')
  }

  return app
}

export function unmountLoginApp() {
  if (!loginAppInstance) {
    return
  }

  loginAppInstance.unmount()
  loginAppInstance = null
}
