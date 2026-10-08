// 播放环境检测：原 App 片源为 H265 MP4（playAddr.vcodec="H265"），
// 浏览器能否直接解取决于平台 HEVC 硬件解码（Chrome 107+ / Edge+扩展 / Safari）。
// 参考：docs/frontend.md 播放器一节、StaZhu/enable-chromium-hevc-hardware-decoding。

export type CodecSupport = "probably" | "maybe" | ""

const PROBE_CODECS = [
  'video/mp4; codecs="hvc1.1.6.L93.B0"', // HEVC Main
  'video/mp4; codecs="hvc1"',
  'video/mp4; codecs="hev1"',
]

let cached: CodecSupport | null = null

/** HEVC 本地播放支持等级（"" = 不可用） */
export function hevcSupport(): CodecSupport {
  if (cached !== null) return cached
  if (typeof document === "undefined") return ""
  const v = document.createElement("video")
  let best: CodecSupport = ""
  for (const c of PROBE_CODECS) {
    const s = v.canPlayType(c) as CodecSupport
    if (s === "probably") {
      best = s
      break
    }
    if (s === "maybe") best = "maybe"
  }
  cached = best
  return best
}

export const hevcOk = () => hevcSupport() !== ""

/** H265 直链在当前浏览器是否可播；不可用时给出用户可理解的提示 */
export function codecWarning(): string | null {
  if (hevcOk()) return null
  return "当前浏览器不支持 H.265/HEVC 硬件解码，可能只有声音没有画面。建议使用 Edge（安装 HEVC 扩展）或 Chrome 107+ 且显卡支持 HEVC 的环境。"
}
