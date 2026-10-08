// 诊断浮层 —— 真机排障专用。
//
// 为什么需要它：雷电模拟器的 adb 通道打不通（5555 从未监听），一旦取数链路出问题，
// 界面上只剩永远转不完的骨架屏，看不到任何原因。这里把能拿到的现场全部铺在屏幕上，
// 一张截图即可定位到底断在哪一环。
//
// 数据源（按可靠性排序）：
//   1. window.__JCY_DIAG__ —— MainActivity 每秒 evaluateJavascript 注入，**本地桥死了也有**
//   2. GET /diag           —— 桥活着时的全量日志（含 JcyApi 每次请求的收发与耗时）
//   3. GET /probe          —— 逐 action 探测 libcore（check / get_version / api_encrypt …），
//                             桥侧缓存 30 s，每个 action 上限 4 s，不会把线程池耗干
//   4. GET /debug          —— 汇总自检（含端到端 probe_config_code），仅在手动刷新时拉
//
// 入口：右下角悬浮按钮；若 /health 连续 3 次不通则自动展开（这正是「一直骨架屏」的场景）。

import { useCallback, useEffect, useRef, useState } from "react"
import type { ReactNode } from "react"

import { API_BASE, apiUrl } from "@/lib/api"

declare global {
  interface Window {
    __JCY_DIAG__?: string
  }
}

const HEALTH_FAIL_LIMIT = 3

export function DiagOverlay() {
  const [open, setOpen] = useState(false)
  const [health, setHealth] = useState("检测中…")
  const [nativeDiag, setNativeDiag] = useState("")
  const [bridgeDiag, setBridgeDiag] = useState("")
  const [bridgeErr, setBridgeErr] = useState("")
  const [probeJson, setProbeJson] = useState("")
  const [debugJson, setDebugJson] = useState("")
  const fails = useRef(0)
  const autoOpened = useRef(false)

  // 健康轮询：便宜，常驻。连续失败则自动展开浮层。
  useEffect(() => {
    let stop = false
    const tick = async () => {
      try {
        const r = await fetch(apiUrl("/health"), { cache: "no-store" })
        const t = await r.text()
        if (stop) return
        setHealth(`HTTP ${r.status} ${t}`)
        fails.current = 0
      } catch (e) {
        if (stop) return
        fails.current += 1
        setHealth(`不通（第 ${fails.current} 次）: ${String(e)}`)
        if (fails.current >= HEALTH_FAIL_LIMIT && !autoOpened.current) {
          autoOpened.current = true
          setOpen(true)
        }
      }
    }
    void tick()
    const id = window.setInterval(tick, 3000)
    return () => {
      stop = true
      window.clearInterval(id)
    }
  }, [])

  const refresh = useCallback(async (full = false) => {
    setNativeDiag(window.__JCY_DIAG__ ?? "（MainActivity 尚未注入 —— 可能 App 进程刚起或诊断泵未运行）")
    try {
      const r = await fetch(apiUrl("/diag"), { cache: "no-store" })
      setBridgeDiag(await r.text())
      setBridgeErr("")
    } catch (e) {
      setBridgeDiag("")
      setBridgeErr(String(e))
    }
    try {
      const r = await fetch(apiUrl("/probe"), { cache: "no-store" })
      setProbeJson(JSON.stringify(await r.json(), null, 2))
    } catch (e) {
      setProbeJson(`失败: ${String(e)}`)
    }
    if (!full) return
    try {
      const r = await fetch(apiUrl("/debug"), { cache: "no-store" })
      setDebugJson(JSON.stringify(await r.json(), null, 2))
    } catch (e) {
      setDebugJson(`失败: ${String(e)}`)
    }
  }, [])

  useEffect(() => {
    if (!open) return
    void refresh(false)
    const id = window.setInterval(() => void refresh(false), 5000)
    return () => window.clearInterval(id)
  }, [open, refresh])

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        title="诊断面板"
        className="fixed right-2 top-2 z-[9999] rounded-full border border-amber-400/60 bg-amber-100/90 px-2.5 py-1 text-[11px] font-medium text-amber-900 shadow-sm backdrop-blur"
      >
        诊断
      </button>
    )
  }

  return (
    <div className="fixed inset-0 z-[9999] flex flex-col bg-background/98 backdrop-blur">
      <div className="flex items-center gap-2 border-b px-3 py-2">
        <span className="text-sm font-semibold">诊断面板</span>
        <span className="truncate text-[11px] text-muted-foreground">API_BASE = {API_BASE || "(空)"}</span>
        <button
          type="button"
          onClick={() => void refresh(true)}
          className="ml-auto rounded border px-2 py-0.5 text-[11px]"
        >
          全量刷新
        </button>
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="rounded border px-2 py-0.5 text-[11px]"
        >
          重载页面
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="rounded border px-2 py-0.5 text-[11px]"
        >
          关闭
        </button>
      </div>

      <div className="flex-1 select-text overflow-auto px-3 py-2 font-mono text-[11px] leading-[1.45] whitespace-pre-wrap break-all">
        <Sec title="① /health（本地桥存活 + native 会话就绪）">{health}</Sec>
        <Sec title="② window.__JCY_DIAG__（MainActivity 注入，桥死了也有）">
          {nativeDiag || "（空）"}
        </Sec>
        <Sec title="③ GET /diag（桥侧全量日志）">
          {bridgeErr ? `请求失败: ${bridgeErr}` : bridgeDiag || "（空）"}
        </Sec>
        <Sec title="④ GET /probe（逐 action 探测 libcore）">{probeJson || "（空）"}</Sec>
        <Sec title="⑤ GET /debug（汇总自检，仅全量刷新时更新）">{debugJson || "（未拉取）"}</Sec>
      </div>
    </div>
  )
}

function Sec({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mt-3">
      <h3 className="mb-1 border-b border-dashed pb-0.5 font-sans text-[12px] font-semibold">{title}</h3>
      <div>{children}</div>
    </section>
  )
}
