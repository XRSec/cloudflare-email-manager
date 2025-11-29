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
        changeOrigin: true,
        // 保留所有响应头，包括缓存头
        configure: (proxy, _options) => {
          proxy.on('proxyRes', (proxyRes, req, res) => {
            // 确保缓存相关的头部被正确传递
            if (proxyRes.headers['etag']) {
              res.setHeader('ETag', proxyRes.headers['etag']);
            }
            if (proxyRes.headers['last-modified']) {
              res.setHeader('Last-Modified', proxyRes.headers['last-modified']);
            }
            if (proxyRes.headers['cache-control']) {
              res.setHeader('Cache-Control', proxyRes.headers['cache-control']);
            }
            if (proxyRes.headers['vary']) {
              res.setHeader('Vary', proxyRes.headers['vary']);
            }
            // 打印缓存相关信息（调试用）
            if (req.url?.includes('/attachments/') || req.url?.includes('/raw')) {
              console.log('📦 缓存头:', {
                url: req.url,
                status: proxyRes.statusCode,
                etag: proxyRes.headers['etag'],
                cacheControl: proxyRes.headers['cache-control']
              });
            }
          });
        }
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