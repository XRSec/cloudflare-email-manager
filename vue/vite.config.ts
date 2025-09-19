import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { NaiveUiResolver } from 'unplugin-vue-components/resolvers'


export default defineConfig({
  plugins: [
    vue(),
    AutoImport({
      imports: [
        'vue',
        'vue-router',
        'pinia',
        '@vueuse/core'
      ],
      resolvers: [NaiveUiResolver()],
      dts: true
    }),
    Components({
      resolvers: [NaiveUiResolver()],
      dts: true
    })
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src')
    }
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8787',
        changeOrigin: true
      }
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          // 核心框架
          vue: ['vue', 'pinia', 'vue-router'],
          // UI 组件库
          ui: ['naive-ui'],
          // 工具库
          utils: ['@vueuse/core', 'dayjs'],
          // 组件按功能分组
          'components-loading': ['@/layouts/AppLoadingSpinner.vue'],
          'views-login': ['@/layouts/LoginView.vue'],
          'views-main': ['@/layouts/MainLayoutView.vue'],
          'auth': ['@/composables/auth'],
          'api': ['@/composables/api']
        }
      }
    }
  }
})