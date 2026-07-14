import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects a fixed dev port and builds the frontend into dist/.
const host = "localhost";
const port = 1420;

export default defineConfig({
  plugins: [react()],
  root: "src-ui",
  // Vite outputs to ../dist (Tauri's frontendDist).
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    target: "safari15",
  },
  clearScreen: false,
  server: {
    host,
    port,
    strictPort: true,
  },
});
