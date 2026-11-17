import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Tauri serves the built files from dist/ and the dev server from 1420.
export default defineConfig({
  // Assets are referenced relative to the page rather than from the site
  // root, so the built files work wherever they are put: the root of a
  // domain, a subdirectory like /AtherNet/ on GitHub Pages, or inside the
  // Tauri bundle. The default of '/' silently 404s everything the moment
  // the app is not at the top of a host.
  base: './',
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
