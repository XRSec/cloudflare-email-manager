import { defineConfig } from 'vite'
import { resolve } from 'path'

// Cloudflare Workers 构建配置
export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/worker.ts'),
      name: 'worker',
      fileName: 'worker',
      formats: ['es']
    },
    rollupOptions: {
      external: ['hono', 'hono/cors', 'hono/http-exception'],
      output: {
        globals: {
          'hono': 'Hono',
          'hono/cors': 'cors',
          'hono/http-exception': 'HTTPException'
        }
      }
    },
    outDir: 'dist',
    emptyOutDir: false // 不清空目录，保留前端构建文件
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
})