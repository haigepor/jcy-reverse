// ArtPlayer 播放器封装 —— 对应原 App 阿里 ApsaraPlayer 的 Web 替代内核。
// 设计要点（详见 docs/frontend.md）：
//   * 片源 = H265 MP4 渐进直链（经 /stream 代理注入 UA/Referer），m3u8 场景走 hls.js
//   * 多清晰度 = ArtPlayer quality 菜单（playAddr 数组索引语义，无缝续播切换）
//   * 弹幕 = artplayer-plugin-danmuku，复刻原 canvas_danmaku 的滚动/顶部静态 +
//     透明度/显示范围/字号/速度设置面板（插件内置 setting 面板）
//   * 续播 = startTime（本地进度由页面层传入）

import { useEffect, useRef } from "react"
import Artplayer from "artplayer"
import artplayerPluginDanmuku from "artplayer-plugin-danmuku"
import Hls from "hls.js"
import { cn } from "cn"

import type { PlayQuality } from "@/lib/types"
import type { DanmakuSettings } from "@/store/settings"

export interface DanmakuEntry {
  /** 播放秒 */
  time: number
  text: string
  /** 0=滚动 1=顶部 2=底部 */
  mode?: number
}

export interface JcyPlayerProps {
  /** 已代理的播放地址（streamUrl() 产物） */
  url: string
  qualities?: PlayQuality[]
  poster?: string
  startTime?: number
  danmus?: DanmakuEntry[]
  danmaku?: DanmakuSettings
  danmakuOn?: boolean
  /** 变化时重建播放器（换集/换线路） */
  instanceKey?: string
  /** 流卡死自愈：连续 waiting 超 12s 或 video:error 时触发，页面层应重解析换新直链
   *（CDN 签名直链会过期/单连接被限速，干等永远不会恢复） */
  onNeedRefresh?: () => void
  onTimeUpdate?: (time: number) => void
  onEnded?: () => void
  className?: string
}

function isM3u8(url: string) {
  return /\.m3u8(\?|$)/i.test(url)
}

// art.danmuku 由插件运行时挂载，官方类型未暴露 —— 收敛到一个窄接口
interface DanmukuApi {
  load?: (list: { time: number; text: string; mode: 0 | 1 | 2 }[]) => void
  show?: () => void
  hide?: () => void
}
const danmukuOf = (art: Artplayer): DanmukuApi | undefined =>
  (art as unknown as { danmuku?: DanmukuApi }).danmuku

function attachHls(video: HTMLVideoElement, url: string, art: Artplayer) {
  if (Hls.isSupported()) {
    const hls = new Hls()
    hls.loadSource(url)
    hls.attachMedia(video)
    ;(art as unknown as { hls?: Hls }).hls = hls
    art.on("destroy", () => hls.destroy())
  } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
    video.src = url // Safari 原生 HLS（含 AES-128 KEY）
  } else {
    art.notice.show = "当前环境不支持 HLS 播放"
  }
}

export function JcyPlayer({
  url,
  qualities = [],
  poster,
  startTime = 0,
  danmus = [],
  danmaku,
  danmakuOn = true,
  instanceKey,
  onNeedRefresh,
  onTimeUpdate,
  onEnded,
  className,
}: JcyPlayerProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const artRef = useRef<Artplayer | null>(null)
  const urlRef = useRef(url)
  const cbRef = useRef({ onTimeUpdate, onEnded, onNeedRefresh })
  cbRef.current = { onTimeUpdate, onEnded, onNeedRefresh }

  useEffect(() => {
    if (!containerRef.current || !url) return
    const danmukuEntries = danmus.map((d) => ({
      time: d.time,
      text: d.text,
      mode: (d.mode ?? 0) as 0 | 1 | 2,
    }))
    // 注意：本 effect 只随 instanceKey 重建（换集/换线路/换清晰度档）。
    // 仅 url 变化（卡死自愈拿到新直链）走下方丝滑换链 effect，不整器重建。

    const art = new Artplayer({
      container: containerRef.current,
      url,
      poster,
      type: isM3u8(url) ? "m3u8" : "mp4",
      customType: { m3u8: attachHls },
      volume: 0.8,
      muted: false,
      autoplay: false,
      setting: true,
      playbackRate: true,
      aspectRatio: true,
      flip: false,
      fullscreen: true,
      fullscreenWeb: true,
      miniProgressBar: true,
      mutex: true,
      backdrop: true,
      hotkey: true,
      pip: true,
      lang: "zh-cn",
      // ArtPlayer 默认主题色是**纯红 `#f00`**（源码里 `.art-video-player{--art-theme:#f00}`），
      // 与全站品牌橙红打架 —— 症状就是「进度条最左端停着一个孤立红点」（未播放时
      // `.art-progress-indicator` 停在 0%，颜色是 theme）。这里对齐品牌色。
      theme: "#FF5C39",
      moreVideoAttr: { crossOrigin: "anonymous", playsInline: true },
      quality: qualities.length > 1
        ? qualities.map((q, i) => ({
            html: q.name,
            url: q.url,
            default: i === 0,
          }))
        : [],
      plugins: [
        artplayerPluginDanmuku({
          danmuku: danmukuEntries,
          speed: danmaku?.speed ?? 5,
          opacity: danmaku?.opacity ?? 1,
          // 百分比 = 播放器 clientHeight 的占比（插件原生支持，逐帧重算）：
          // 桌面 ~560px 高 ≈ 25px（与旧固定值一致），手机 ~200px 高钳到下限 12px，
          // 平板/全屏/任意宽高自动连续缩放 —— 替代旧的固定 25px。
          fontSize: "4.5%",
          color: "#FFFFFF",
          // 显示范围：full / half / quarter 对应插件 margin 上边距比例
          margin: danmaku?.area === "quarter" ? [10, "75%"]
            : danmaku?.area === "half" ? [10, "50%"] : [10, "25%"],
          antiOverlap: true,
          synchronousPlayback: false,
          // v5 设置面板由 ArtPlayer 本体 setting:true 自动挂载，无需插件侧开关
        }),
      ],
    })

    if (isM3u8(url)) {
      // customType 拿不到 art 引用前不触发；此处兜底注册
    }
    // 续播：ArtPlayer 5 的 Option 已移除 startTime，ready 后 seek
    if (startTime > 3) {
      art.on("ready", () => {
        art.currentTime = Math.floor(startTime)
      })
    }
    const dm = danmukuOf(art)
    if (!danmakuOn) dm?.hide?.()

    art.on("video:timeupdate", () => cbRef.current.onTimeUpdate?.(art.currentTime))
    art.on("video:ended", () => cbRef.current.onEnded?.())

    // ---- 流卡死自愈：waiting 持续 12s 或 video:error → 通知页面重解析换直链 ----
    // CDN 签名 URL 过期或单连接限速时浏览器会永远停在 buffering，重解析是唯一出路。
    // 15s 节流防风暴；新直链改变 instanceKey → 播放器重建，计时器自然复位。
    let stallTimer: ReturnType<typeof setTimeout> | undefined
    let lastRefreshAt = 0
    const fireRefresh = () => {
      if (Date.now() - lastRefreshAt < 15000) return
      lastRefreshAt = Date.now()
      art.notice.show = "播放卡顿，正在自动重新解析直链…"
      cbRef.current.onNeedRefresh?.()
    }
    const armStall = () => {
      clearTimeout(stallTimer)
      stallTimer = setTimeout(fireRefresh, 12000)
    }
    const disarmStall = () => clearTimeout(stallTimer)
    art.on("video:waiting", armStall)
    art.on("video:playing", disarmStall)
    art.on("video:canplay", disarmStall)
    art.on("video:error", () => {
      clearTimeout(stallTimer)
      stallTimer = setTimeout(fireRefresh, 2000)
    })
    art.on("destroy", disarmStall)

    // ---- 播放条自动收起：窗口模式 ArtPlayer 不内置 idle 隐藏，这里自实现 ----
    // 3s 无输入且播放中 → 隐藏 .art-bottom；任何输入/暂停/结束立即恢复；弹幕输入框聚焦时不收
    const root = (art.template as unknown as { $player?: HTMLElement }).$player
    let idleTimer: ReturnType<typeof setTimeout> | undefined
    const armIdle = () => {
      if (!root) return
      root.classList.remove("jcy-idle")
      clearTimeout(idleTimer)
      if (!art.playing) return
      idleTimer = setTimeout(() => {
        const el = document.activeElement
        if (el && root.contains(el) && /^(INPUT|TEXTAREA)$/.test(el.tagName)) return
        root.classList.add("jcy-idle")
      }, 3000)
    }
    const disarmIdle = () => {
      clearTimeout(idleTimer)
      root?.classList.remove("jcy-idle")
    }
    const idleEvents = ["mousemove", "mousedown", "touchstart"] as const
    idleEvents.forEach((e) => root?.addEventListener(e, armIdle, { passive: true }))
    art.on("video:play", armIdle)
    art.on("video:pause", disarmIdle)
    art.on("video:ended", disarmIdle)

    // ---- 缓存指示：百分比 + 大小（总大小经 HEAD Content-Range 探测，按缓冲秒数折算已下字节）----
    // 显隐走 jcy-cache-on 类（非 inline opacity），让 idle 规则(.art-video-player.jcy-idle
    // .jcy-cache 三类选择器)能压住显示态 —— 3s 无操作跟随底部操作栏一起隐藏
    const cacheEl = document.createElement("div")
    cacheEl.className = "jcy-cache"
    cacheEl.style.cssText =
      "position:absolute;right:12px;bottom:64px;z-index:30;pointer-events:none;" +
      "font-size:12px;line-height:18px;color:#fff;background:rgba(0,0,0,.45);" +
      "padding:2px 10px;border-radius:999px;opacity:0;transition:opacity .3s"
    root?.appendChild(cacheEl)
    let totalBytes = 0
    const fmtSize = (b: number) =>
      b >= 1073741824 ? `${(b / 1073741824).toFixed(2)}GB` : `${(b / 1048576).toFixed(1)}MB`
    const probeSize = () => {
      fetch(url, { method: "HEAD" })
        .then((r) => {
          // /stream 对 HEAD 上游发 Range: bytes=0-0 → 206 Content-Range "bytes 0-0/全长"
          const cr = r.headers.get("content-range")
          const m = cr ? /\/(\d+)\s*$/.exec(cr) : null
          totalBytes = m ? Number(m[1]) : Number(r.headers.get("content-length") ?? 0)
        })
        .catch(() => {})
    }
    probeSize()
    art.on("video:loadedmetadata", probeSize) // 换清晰度/换源后重新探测
    const paintCache = () => {
      const v = art.video as HTMLVideoElement | undefined
      if (!v || !v.duration) return
      let end = 0
      for (let i = 0; i < v.buffered.length; i++) {
        if (v.buffered.start(i) <= v.currentTime + 0.5) end = Math.max(end, v.buffered.end(i))
      }
      const pct = Math.min(100, Math.round((end / v.duration) * 100))
      if (pct <= 0 || pct >= 100) {
        cacheEl.classList.remove("jcy-cache-on")
        return
      }
      cacheEl.textContent = totalBytes > 0
        ? `缓存 ${pct}% · ${fmtSize((totalBytes * end) / v.duration)}/${fmtSize(totalBytes)}`
        : `缓存 ${pct}%`
      cacheEl.classList.add("jcy-cache-on")
    }
    art.on("video:timeupdate", paintCache)
    art.on("video:progress", paintCache)

    artRef.current = art
    urlRef.current = url

    return () => {
      clearTimeout(idleTimer)
      clearTimeout(stallTimer)
      idleEvents.forEach((e) => root?.removeEventListener(e, armIdle))
      cacheEl.remove()
      art.destroy(false)
      artRef.current = null
    }
    // 只随 instanceKey 重建（换集/换线路/换清晰度档）；仅 url 变化走丝滑换链 effect
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [instanceKey])

  // ---- 丝滑换链（卡死自愈专用）----
  // 直链更新但 instanceKey 未变：switchUrl 原地切换 + 记忆进度/播放态，canplay 后
  // seek 回原位置继续播 —— 全程无黑屏、无海报闪烁、不从头加载。
  // mp4 渐进直链下冻结窗口 = 新 Range 首包时间（~1s）。
  useEffect(() => {
    const art = artRef.current
    if (!art || urlRef.current === url) return
    urlRef.current = url
    const t = art.currentTime
    const wasPlaying = art.playing
    art.on("video:canplay", function onSeamless() {
      art.off("video:canplay", onSeamless)
      if (t > 1) art.currentTime = t
      if (wasPlaying) void art.play()
    })
    art.switchUrl?.(url)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url])

  // 弹幕数据增量更新（60s 轮询窗口合并后整体 reload）
  useEffect(() => {
    const dm = artRef.current ? danmukuOf(artRef.current) : undefined
    if (!dm) return
    try {
      dm.load?.(danmus.map((d) => ({ time: d.time, text: d.text, mode: (d.mode ?? 0) as 0 | 1 | 2 })))
    } catch {
      // 插件版本差异时静默降级：弹幕仅在重建时加载
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [danmus])

  // 弹幕总开关
  useEffect(() => {
    const dm = artRef.current ? danmukuOf(artRef.current) : undefined
    if (!dm) return
    if (danmakuOn) dm.show?.()
    else dm.hide?.()
  }, [danmakuOn])

  return (
    <div
      className={cn(
        "relative w-full overflow-hidden rounded-lg bg-black",
        // 播放条自动收起过渡 + idle 态隐藏（jcy-idle 由播放器内部 3s 计时挂载）
        "[&_.art-bottom]:transition-opacity [&_.art-bottom]:duration-300",
        "[&_.art-video-player.jcy-idle_.art-bottom]:opacity-0",
        "[&_.art-video-player.jcy-idle]:cursor-none",
        // 窄屏收纳：音量滑条是控制条里最宽的单项，手机用系统音量，腾位给
        // 时间/清晰度/设置/全屏，避免右组按钮被 overflow-hidden 裁掉
        "max-md:[&_.art-control-volume]:hidden",
        // 缓存指示器显隐：jcy-cache-on 显示；idle(3s 无操作) 时三类选择器
        // 压过单类显示态，与底部操作栏同步隐藏
        "[&_.jcy-cache]:opacity-0 [&_.jcy-cache-on]:opacity-100",
        "[&_.art-video-player.jcy-idle_.jcy-cache]:opacity-0",
        className,
      )}
    >
      <div ref={containerRef} className="h-full w-full [&_.art-video-player]:h-full" />
    </div>
  )
}
