import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// The backend (vpn-control) listens on 127.0.0.1:8080 during development.
const backend = "http://127.0.0.1:8080";

/**
 * Backend-owned paths proxied by the dev server. Vite treats keys starting with "^" as regexes and
 * every other key as a plain `startsWith` prefix, so plain keys like "/s" would also capture Vite's
 * own "/src/..." module requests. Every key is therefore an anchored regex that matches a whole
 * path segment only.
 */
export const DEV_PROXY_PATTERNS = [
  "^/api(/|\\?|$)",
  "^/auth(/|\\?|$)",
  "^/s/",
  "^/i/",
  "^/healthz(\\?|$)",
] as const;

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: Object.fromEntries(
      DEV_PROXY_PATTERNS.map((p) => [p, { target: backend, changeOrigin: false, xfwd: false }]),
    ),
  },
  preview: {
    host: "127.0.0.1",
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    // Never inline assets as data: URIs; everything is served as a same-origin file.
    assetsInlineLimit: 0,
    // Do not add the modulepreload polyfill (keeps index.html free of any inline code).
    modulePreload: { polyfill: false },
    target: "es2022",
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
