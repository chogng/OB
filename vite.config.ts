import { defineConfig } from 'vite'
import { resolve } from 'path'

const host = process.env.TAURI_DEV_HOST

// https://vitejs.dev/config/
export default defineConfig({
  // 1) prevent vite from obscuring rust errors
  clearScreen: false,
  // 2) tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: 'ws',
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3) ignore rust sources
      ignored: ['**/src-tauri/**'],
    },
  },
  resolve: {
    alias: {
      '@tauri-apps/api': resolve(__dirname, 'node_modules/@tauri-apps/api'),
    },
  },
  optimizeDeps: {
    include: ['@tauri-apps/api', '@tauri-apps/plugin-dialog'],
  },
})
