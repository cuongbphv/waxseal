import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Root-absolute asset URLs, and they have to be: the router uses path history
// (see src/router.ts), so `/chains/default` is a real URL the operator can
// refresh. Relative asset paths would resolve against THAT path — the browser
// would ask for `/chains/assets/index-*.js`, and SpaStaticFiles would answer
// the 404 with `index.html`, handing the module loader a web page. A blank
// screen with a parse error, on refresh only.
//
// This is safe because `app.mount("/", SpaStaticFiles(...))` puts the bundle
// at the site root. If it ever moves under a prefix, this value moves with it.
export default defineConfig({
  base: '/',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: '../waxseal_server/static',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/v1': { target: 'http://127.0.0.1:8000', changeOrigin: false },
      '/public': { target: 'http://127.0.0.1:8000', changeOrigin: false },
      '/health': { target: 'http://127.0.0.1:8000', changeOrigin: false },
    },
  },
})
