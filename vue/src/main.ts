import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './composables/routes'
import App from './App.vue'

const app = createApp(App)

// 注册 Pinia
app.use(createPinia())

// 注册路由
app.use(router)

// Naive UI 通过 unplugin-vue-components 自动导入，无需全局注册

app.mount('#app')