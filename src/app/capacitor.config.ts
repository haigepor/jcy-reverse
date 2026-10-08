import type { CapacitorConfig } from "@capacitor/cli"

// webDir 指向构建产物：scripts/build_web.sh 会把 src/web/dist 同步到 app/www
// 主 API 为明文 HTTP，因此 androidScheme 用 http 并允许 mixed content。
const config: CapacitorConfig = {
  appId: "app.video.guoguo",
  appName: "囧次元",
  webDir: "www",
  android: {
    allowMixedContent: true,
    // libcore.so 为 arm64-v8a，仅支持 ARM64 设备
    // （x86 模拟器需依赖系统 ARM 转译层）
  },
  server: {
    androidScheme: "http",
  },
}

export default config
