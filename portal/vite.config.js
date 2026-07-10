import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
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
});
