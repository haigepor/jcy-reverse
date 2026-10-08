// BridgeGate —— 在挂载业务路由之前，先确认本机桥已监听。
//
// 为什么必须做这一层：Android 侧的桥（JcyBridgeServer，127.0.0.1:8792）要等
// libcore.so 加载 + init 完成才存在，而 WebView 页面几乎同时就开始渲染。
// 旧实现靠 React Query 的指数退避重试去"熬"这段空窗，但重试次数是有限的：
// 桥晚到 20 s、重试只够 11.6 s 时，查询会永久停在 error 状态不再自愈 ——
// 表现就是「接口请求不成功 / 数据一直加载不出来」。
//
// 这里改成**显式等待**：/health 通了才渲染路由。等待期间给一个明确的状态条，
// 超过上限（约 12 s）则放行 —— 让界面渲染出来，DiagOverlay 才能把原因摊开。

import { useEffect, useState } from "react"
import type { ReactNode } from "react"

import { apiUrl } from "@/lib/api"

/** 轮询间隔（毫秒）。桥起来得很快，500 ms 足够跟手。 */
const POLL_MS = 500
/** 最多轮询次数：500 ms × 24 ≈ 12 s。超时后放行，交给 DiagOverlay 报原因。 */
const MAX_POLLS = 24

export function BridgeGate({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false)
  const [polls, setPolls] = useState(0)
  const [detail, setDetail] = useState("正在连接本机服务…")

  useEffect(() => {
    let stop = false
    let timer: number | undefined

    const tick = async (n: number) => {
      if (stop) return
      try {
        const r = await fetch(apiUrl("/health"), { cache: "no-store" })
        const j = (await r.json()) as { ok?: boolean; core_ready?: boolean }
        if (stop) return
        if (j?.ok) {
          setDetail(j.core_ready ? "" : "桥已就绪，native 会话建立中…")
          setReady(true)
          return
        }
        setDetail(`桥未就绪（HTTP ${r.status}）`)
      } catch (e) {
        if (stop) return
        setDetail(`本机服务未响应（第 ${n + 1} 次）：${String(e)}`)
      }
      setPolls(n + 1)
      if (n + 1 >= MAX_POLLS) {
        // 放行：界面渲染出来后 DiagOverlay 会自动展开，能看到 /diag 与 __JCY_DIAG__
        setDetail("等待本机服务超时，已放行（诊断面板会自动展开）")
        setReady(true)
        return
      }
      timer = window.setTimeout(() => void tick(n + 1), POLL_MS)
    }

    void tick(0)
    return () => {
      stop = true
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [])

  if (ready) return <>{children}</>

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-3 bg-background px-6 text-center">
      <div className="flex items-center gap-2">
        <span className="size-8 animate-pulse rounded-md bg-primary" />
        <span className="text-lg font-semibold">囧次元</span>
      </div>
      <div className="h-1 w-40 overflow-hidden rounded-full bg-muted">
        <div
          className="h-full bg-primary transition-all duration-300"
          style={{ width: `${Math.min(100, (polls / MAX_POLLS) * 100)}%` }}
        />
      </div>
      <p className="max-w-xs text-xs text-muted-foreground">{detail}</p>
    </div>
  )
}
