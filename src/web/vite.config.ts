import path from "node:path"
import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"

// 本地开发：前端 5173，后端桥(FastAPI) 8792 —— /api、/resolve、/stream 统一反代到后端
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    // host=true 绑 0.0.0.0：手机/局域网设备可用 http://<本机IP>:5174 访问
    //（/api /resolve /stream 由 vite 服务端反代到 127.0.0.1:8792，桥无需暴露）
    host: true,
    port: 5174,
    proxy: {
      "/api": "http://127.0.0.1:8792",
      "/resolve": "http://127.0.0.1:8792",
      "/stream": "http://127.0.0.1:8792",
    },
  },
})
