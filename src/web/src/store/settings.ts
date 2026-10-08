// 播放器/弹幕设置 —— zustand persist 到 localStorage。
// 游客态服务端 history 返回 50008，续播进度一律走本地存储（key: progress:<vid>）。

import { create } from "zustand"
import { persist } from "zustand/middleware"

export interface DanmakuSettings {
  /** 0~1 */
  opacity: number
  /** 字号缩放 0.5~2 */
  scale: number
  /** 弹幕速度 1~10（越大越快） */
  speed: number
  /** 显示范围（全屏/半屏/1/4屏） */
  area: "full" | "half" | "quarter"
  /** 滚动弹幕开关 */
  scroll: boolean
  /** 顶部静态弹幕开关 */
  top: boolean
}

interface SettingsState {
  danmaku: DanmakuSettings
  danmakuOn: boolean
  /** 清晰度偏好；null = 自动（默认 4K，缺档回退 1080P，见 video.tsx 的匹配链） */
  preferredQuality: string | null
  setDanmaku: (patch: Partial<DanmakuSettings>) => void
  setDanmakuOn: (on: boolean) => void
  setPreferredQuality: (name: string | null) => void
}

export const useSettings = create<SettingsState>()(
  persist(
    (set) => ({
      danmaku: { opacity: 1, scale: 1, speed: 5, area: "full", scroll: true, top: true },
      danmakuOn: true,
      preferredQuality: null,
      setDanmaku: (patch) => set((s) => ({ danmaku: { ...s.danmaku, ...patch } })),
      setDanmakuOn: (on) => set({ danmakuOn: on }),
      setPreferredQuality: (name) => set({ preferredQuality: name }),
    }),
    { name: "jcy-settings" },
  ),
)

/** 本地续播进度（原 App PlayerHistory 的游客态等价物） */
const PROGRESS_KEY = (vid: string | number) => `jcy-progress:${vid}`

export function loadProgress(vid: string | number, part: string | null) {
  try {
    const o = JSON.parse(localStorage.getItem(PROGRESS_KEY(vid)) || "{}")
    if (part && o.part && o.part !== part) return 0
    return typeof o.time === "number" ? o.time : 0
  } catch {
    return 0
  }
}

export function saveProgress(vid: string | number, part: string | null, time: number) {
  try {
    localStorage.setItem(PROGRESS_KEY(vid), JSON.stringify({ part, time, at: Date.now() }))
  } catch {
    // 隐私模式等场景静默失败
  }
}

/** 上次看到的一集（选集自动定位）。与进度分开存：换集即写，不等 timeupdate 节流 */
const LASTPART_KEY = (vid: string | number) => `jcy-lastpart:${vid}`

export function loadLastPart(vid: string | number): string | null {
  try {
    const v = localStorage.getItem(LASTPART_KEY(vid))
    return v ? JSON.parse(v) : null
  } catch {
    return null
  }
}

export function saveLastPart(vid: string | number, part: string) {
  try {
    localStorage.setItem(LASTPART_KEY(vid), JSON.stringify(part))
  } catch {
    // ignore
  }
}
