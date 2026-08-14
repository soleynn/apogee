import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [svelte()],
  build: {
    // The engine this renders in is whatever WebKitGTK the user's distribution ships, which trails
    // the browsers a default target assumes. 2.38 is the first release carrying the API level the
    // desktop side links against, and safari16 is the syntax level that build understands.
    target: 'safari16',
  },
  server: {
    // The desktop process loads this exact URL in a dev run, so a port already in use has to fail
    // rather than quietly move and leave the window pointed at nothing.
    port: 1420,
    strictPort: true,
  },
  // Rust errors from the desktop side scroll past otherwise.
  clearScreen: false,
});
