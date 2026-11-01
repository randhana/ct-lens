import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During development the dashboard talks to the FastAPI backend. We proxy
// /api to it so the browser sees a single origin (no CORS needed in dev).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.CT_LENS_API ?? "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});
