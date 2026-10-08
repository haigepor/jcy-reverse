// 应用入口 —— QueryClient（弹幕轮询/列表缓存）+ BrowserRouter（对应原 App go_router）。

import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { BrowserRouter, Route, Routes } from "react-router"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"

import { AppShell } from "@/components/layout/app-shell"
import { BridgeGate } from "@/components/bridge-gate"
import { DiagOverlay } from "@/components/diag-overlay"
import Home from "@/pages/home"
import ChannelMore from "@/pages/channel-more"
import SearchPage from "@/pages/search"
import TimeLinePage from "@/pages/time-line"
import VideoPage from "@/pages/video"
import MinePage from "@/pages/mine"
import "./index.css"

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60_000,
      // 双层防护，缺一不可：
      //   1. BridgeGate 保证「桥已监听」才挂载路由 —— 消除冷启动空窗；
      //   2. 这里的退避重试兜住运行期抖动（libcore 首次 api_encrypt 可能较慢、
      //      网络切换、宿主切后台等）。
      // 旧值 `failureCount >= 5` 配 800·2^n（封顶 6 s）只够 ~11.6 s，
      // 而桥在旧启动顺序下要 20 s 才起来 —— 重试耗尽即永久停在骨架屏，不再自愈。
      // 现在放宽到 30 次、封顶 3 s（≈80 s 窗口），并对业务错误立刻放弃。
      retry: (failureCount, error) => {
        // 带业务码 = 服务端已明确答复（40000/50008/…），重试无意义
        const code = (error as { code?: unknown } | null)?.code
        if (typeof code === "number") return false
        return failureCount < 30
      },
      retryDelay: (attempt) => Math.min(500 * 1.7 ** attempt, 3000),
      refetchOnWindowFocus: false,
    },
  },
})

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      {/* 先等本机桥监听，再挂载路由 —— 见 bridge-gate.tsx 顶部注释 */}
      <BridgeGate>
        <BrowserRouter>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<Home />} />
              <Route path="/more/:channelId" element={<ChannelMore />} />
              <Route path="/search" element={<SearchPage />} />
              <Route path="/time-line" element={<TimeLinePage />} />
              <Route path="/video/:vid" element={<VideoPage />} />
              <Route path="/mine" element={<MinePage />} />
              <Route path="*" element={<Home />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </BridgeGate>
      {/* 真机排障浮层：常驻在路由之外，任何页面都能拉起 */}
      <DiagOverlay />
    </QueryClientProvider>
  </StrictMode>,
)
