import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// https://vite.dev/config/
export default defineConfig({
  // Serve the SPA from any base path. SCL embeds plugin UIs under
  // /plugins/agent-manager/ on the dashboard origin, so all asset URLs must
  // be emitted relative to the document instead of root-absolute.
  base: './',
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:9005',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:9005',
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
