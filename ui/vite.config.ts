/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The console is served by silo-server under /admin, so every asset URL in
// the build is rooted there. `npm run dev` proxies the JSON gateway and the
// OIDC relay to a locally running server (SILO_DEV_SERVER, default :8080).
const server = process.env.SILO_DEV_SERVER ?? "http://localhost:8080";
// Loopback unless SILO_DEV_HOST says otherwise. The dev container sets it
// to 0.0.0.0, because the editor's port forwarding reaches the container
// from outside its loopback interface.
const host = process.env.SILO_DEV_HOST ?? "localhost";

export default defineConfig({
  base: "/admin/",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 2500,
  },
  server: {
    host,
    // A fixed port, so the forwarded port in devcontainer.json is the one
    // Vite actually serves on. strictPort fails the start instead of
    // drifting to 5174 when 5173 is taken.
    port: 5173,
    strictPort: true,
    proxy: {
      "/admin/api": server,
      "/metrics": server,
      "/RPM-GPG-KEY-silo": server,
      "/pacman-signing-key": server,
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    css: false,
  },
});
