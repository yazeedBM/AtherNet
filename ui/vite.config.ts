import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Tauri serves the built files from dist/ and the dev server from 1420.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    target: 'es2022',
    sourcemap: true,
  },
});
