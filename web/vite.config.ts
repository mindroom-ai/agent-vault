import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const API_TARGET = process.env.VITE_API_URL ?? "http://localhost:14321";

export default defineConfig({
  plugins: [
    {
      name: "development-ui-base-path",
      apply: "serve",
      transformIndexHtml(html) {
        return html
          .replaceAll("__AGENT_VAULT_UI_BASE_HREF__", "/")
          .replaceAll("__AGENT_VAULT_UI_BASE_PATH__", "/");
      },
    },
    react(),
    tailwindcss(),
  ],
  base: "./",
  build: {
    outDir: "../internal/server/webdist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/v1": API_TARGET,
      "/discover": API_TARGET,
      "/health": API_TARGET,
      "/invite": API_TARGET,
    },
  },
});
