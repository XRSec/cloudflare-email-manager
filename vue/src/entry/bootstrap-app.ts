import { createApp, type App as VueApp } from 'vue'
import { createPinia } from 'pinia'
import router from '@/composables/routes'
import App from '@/App.vue'

let appInstance: VueApp<Element> | null = null

export async function mountApp() {
  if (appInstance) {
    return appInstance
  }

  const app = createApp(App)
  app.use(createPinia())
  app.use(router)
  app.mount('#app')
  appInstance = app

  return app
}

export function unmountApp() {
  if (!appInstance) {
    return
  }

  appInstance.unmount()
  appInstance = null
}
