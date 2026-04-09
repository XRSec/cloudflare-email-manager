import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'

const rolldownCodeSplittingGroups = [
  {
    name: 'vendor-vue',
    test: /node_modules[\\/](?:vue[\\/]|pinia[\\/]|vue-router[\\/]|@vue[\\/])/,
    priority: 100
  },
  {
    name: 'vendor-element',
    test: /node_modules[\\/](?:element-plus[\\/]|@element-plus[\\/]|@floating-ui[\\/]|@popperjs[\\/]|@ctrl[\\/]tinycolor[\\/]|lodash-unified[\\/]|normalize-wheel-es[\\/]|memoize-one[\\/])/,
    priority: 90
  },
  {
    name: 'vendor-utils',
    test: /node_modules[\\/](?:axios[\\/]|dayjs[\\/]|@vueuse[\\/])/,
    priority: 80
  },
  {
    name: 'session-core',
    test: /src[\\/]composables[\\/](?:auth|api-client|api-auth|api-system)\.ts/,
    priority: 60
  },
  {
    name: 'admin-shared',
    test: /src[\\/]composables[\\/](?:api(?:-user|-email|-admin|-tools)?|cache|smartCache|useRequestManager|routeApiManager|useUnifiedPageData|globalRefreshManager|system|useApiManager)\.ts/,
    priority: 50
  },
  {
    name: 'ui-common',
    test: /src[\\/]components[\\/]common[\\/]/,
    priority: 40
  },
  {
    name: 'ui-notify',
    test: /src[\\/]utils[\\/](?:index|toast)\.ts/,
    priority: 30
  }
]


export default defineConfig({
  plugins: [
    vue(),
    AutoImport({
      imports: [
        'vue',
        'vue-router',
        'pinia'
      ],
      dts: true
    }),
    Components({
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
    cssCodeSplit: true,
    sourcemap: true,
    modulePreload: false,
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: rolldownCodeSplittingGroups
        }
      }
    }
  }
})
