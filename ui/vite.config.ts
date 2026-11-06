import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 产物直接输出到 fpk/app/ui —— 与 fnOS 应用规范一致：
// 应用目录里放 index.html + assets/*.js，NAS 上不需要 Node。
export default defineConfig({
  plugins: [vue()],
  base: './',
  resolve: {
    alias: {
      '@': new URL('./src', import.meta.url).pathname
    }
  },
  build: {
    outDir: '../fpk/app/ui',
    emptyOutDir: false,
    assetsDir: 'assets',
    target: 'es2018',
    cssCodeSplit: false,
    // 产物里不能出现 sourcemap（体积 + 泄露源码）
    sourcemap: false,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        // 固定文件名，方便 fnOS 侧引用稳定
        entryFileNames: 'assets/guard.js',
        chunkFileNames: 'assets/[name].js',
        assetFileNames: (info) => {
          const name = info.names?.[0] || info.name || ''
          if (name.endsWith('.css')) return 'assets/guard.css'
          return 'assets/[name][extname]'
        }
      }
    }
  },
  server: {
    port: 5180,
    proxy: {
      '/api': {
        target: 'http://192.168.110.97:9705',
        changeOrigin: true
      }
    }
  }
})
