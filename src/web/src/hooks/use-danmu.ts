// 弹幕增量轮询 —— 复刻原 App 的 60s 毫秒窗口拉取（/app/danmu）。
// 窗口锚定拉取进度（lastEnd），每 60s 向前取 180s 缓冲，按弹幕 id 去重后合并。

import { useEffect, useRef, useState } from "react"

import { api } from "@/lib/api"
import type { DanmakuEntry } from "@/components/player/jcy-player"

interface UseDanmuOptions {
  vid: string | number | null
  play: string | null
  part: string | null
  enabled: boolean
  /** 单窗口长度毫秒（服务端硬上限 60s，超过报 400204 弹幕片段超过最大值） */
  windowMs?: number
  /** 轮询间隔毫秒（原 App 60s；这里 15s 让 seek 补拉最快 15s 内到位，量级仍小） */
  intervalMs?: number
  /** 播放进度探针：锚定播放位置拉弹幕（支持 seek 后按块补拉） */
  getCurrentTime?: () => number
}

const SERVER_WINDOW_LIMIT = 60_000

/** 弹幕 content 是内嵌 JSON：{"color":4294967295,"content":"文本"}；老数据可能纯文本 */
function danmuText(raw: string): string {
  try {
    const o = JSON.parse(raw) as { content?: unknown }
    if (o && typeof o.content === "string") return o.content
  } catch {
    // 纯文本直用
  }
  return raw
}

export function useDanmu({
  vid,
  play,
  part,
  enabled,
  windowMs = SERVER_WINDOW_LIMIT,
  intervalMs = 15_000,
  getCurrentTime,
}: UseDanmuOptions): DanmakuEntry[] {
  const [entries, setEntries] = useState<DanmakuEntry[]>([])
  const seen = useRef<Set<number>>(new Set())
  const lastEnd = useRef(0)
  const probe = useRef(getCurrentTime)
  probe.current = getCurrentTime

  // 换集/换线路：完全重置
  useEffect(() => {
    seen.current = new Set()
    lastEnd.current = 0
    setEntries([])
  }, [vid, play, part])

  useEffect(() => {
    if (!enabled || !vid || !part) return
    let stopped = false

    const tick = async () => {
      try {
        // 目标覆盖到"当前播放位置 + 一个窗口"；seek 超前时按 ≤60s 分块逐段补拉
        const target = Math.floor(((probe.current?.() ?? 0) + windowMs) / 1000) * 1000
        let guard = 0
        while (!stopped && lastEnd.current < target && guard < 5) {
          const start = lastEnd.current
          const end = Math.min(start + SERVER_WINDOW_LIMIT, target)
          const env = await api.danmu(vid, part, play ?? "mp4", start, end)
          if (stopped) return
          const items = env.data?.items ?? []
          const fresh = items.filter((i) => !seen.current.has(i.id) && i.content)
          fresh.forEach((i) => seen.current.add(i.id))
          if (fresh.length) {
            setEntries((prev) =>
              [
                ...prev,
                // time_point 响应为毫秒，插件要秒
                ...fresh.map<DanmakuEntry>((i) => ({
                  time: i.time_point / 1000,
                  text: danmuText(i.content),
                  mode: 0,
                })),
              ].sort((a, b) => a.time - b.time),
            )
          }
          lastEnd.current = end
          guard += 1
        }
      } catch {
        // 弹幕失败不阻塞播放；下一轮继续
      }
    }

    void tick()
    const h = setInterval(tick, intervalMs)
    return () => {
      stopped = true
      clearInterval(h)
    }
  }, [enabled, vid, play, part, windowMs, intervalMs])

  return entries
}
