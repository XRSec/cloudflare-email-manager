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
    host: '127.0.0.1',
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
          'components-loading': ['@/views/shared/components/AppLoadingSpinner.vue'],
          'views-login': ['@/views/auth/LoginView.vue'],
          'views-main': ['@/views/shared/layouts/MainLayout.vue'],
          'auth': ['@/composables/auth'],
          'api': ['@/composables/api']
        }
      }
    }
  }
})