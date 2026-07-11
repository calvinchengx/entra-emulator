import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig(({ mode }) => ({
  plugins: [svelte()],
  base: './',
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    // Dev loop: proxy the API to a running emulator (compat origin).
    proxy: {
      '/admin/api': { target: 'https://localhost:8443', secure: false },
      '/health': { target: 'https://localhost:8443', secure: false },
    },
  },
  // Vitest resolves Svelte's client (browser) build so components mount in jsdom.
  resolve: { conditions: mode === 'test' ? ['browser'] : [] },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./vitest-setup.js'],
    include: ['src/**/*.test.js'],
  },
}));
