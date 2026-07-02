import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { readFileSync } from "fs";
import { resolve } from "path";

const dashboardVersion = (() => {
  try {
    return readFileSync(resolve(__dirname, "VERSION"), "utf-8").trim();
  } catch {
    return "dev";
  }
})();

export default defineConfig({
  define: {
    __DASHBOARD_VERSION__: JSON.stringify(dashboardVersion),
  },
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
