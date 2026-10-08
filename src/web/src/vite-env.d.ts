/// <reference types="vite/client" />

/**
 * Vite 环境变量类型声明。
 *
 * 之前缺这个文件 → `import.meta.env` 在 `tsc --noEmit` 下报 TS2339。
 * 这里同时把项目自定义变量列出来，避免各处 `as string | undefined` 硬转。
 */
interface ImportMetaEnv {
  /**
   * 后端桥基址。
   *  - 浏览器开发态：不设置 → 走相对路径 → Vite 反代到 127.0.0.1:8792
   *  - 安卓 App 包：`src/app/scripts/build_web.sh` 注入 `http://127.0.0.1:8792`
   *    （Kotlin 侧 JcyBridgeServer 在设备本机监听同一端口）
   */
  readonly VITE_API_BASE?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
