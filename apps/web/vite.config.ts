import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// Local-first: the dev server binds to localhost and proxies the API so the workbench is never exposed.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5174,
    proxy: {
      '/api': 'http://127.0.0.1:8799',
      '/health': 'http://127.0.0.1:8799',
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
  },
});
