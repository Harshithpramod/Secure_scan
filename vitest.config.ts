import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Deliberately standalone rather than reusing vite.config.ts: that config runs
// the TanStack Start / Lovable plugin stack, which pulls in the whole router
// build and isn't needed to test pure modules.
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    // Node, not jsdom — everything under test is server-side or sandbox code.
    environment: "node",
    include: ["src/**/*.test.ts", "sandbox/**/*.test.js"],
    // The sandbox has its own package.json and no node_modules; its modules are
    // dependency-free ESM, so they import fine from here.
    watch: false,
  },
});
