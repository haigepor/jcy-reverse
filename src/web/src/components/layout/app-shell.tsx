// 应用外壳 —— 桌面侧边栏（对应原 App go_router 的底部四 tab + 频道树），
// 移动端自动降级为底部 tab。
//
// 2026-10 样式重设计要点：
//   1. **取消移动端全局顶栏**。旧版把「搜索番剧…」输入框 + 琥珀色「诊断」胶囊放在
//      AppShell 的 sticky header 里，导致：详情页不沉浸、首页/搜索页各有一个搜索框
//      （同屏两个）、调试入口常驻。现在改为各页自带页头（见 layout/page-header.tsx）。
//   2. 底部 tab 重做：flex-1 均分 + 选中态品牌色 + 顶部指示条 + 图标加粗，
//      替掉旧的 `justify-around` + 单一颜色变化（识别度太弱）。
//   3. 桌面端保留顶栏与侧边栏（大屏才有空间放全局搜索）。

import { Link, Outlet, useLocation } from "react-router"
import { useQuery } from "@tanstack/react-query"
import {
  CalendarDays,
  Clapperboard,
  Compass,
  Heart,
  Palette,
  Search,
  Shapes,
  Tv,
  User,
} from "lucide-react"

import { api } from "@/lib/api"
import { cn } from "cn"
import { Input } from "@/components/ui/input"
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
} from "@/components/ui/sidebar"

const NAV = [
  { to: "/", label: "首页", icon: Compass },
  { to: "/search", label: "搜索", icon: Search },
  { to: "/time-line", label: "排期", icon: CalendarDays },
  { to: "/mine", label: "我的", icon: User },
]

// 频道图标按语义区分（原来是清一色 Heart）：日漫=电视、國漫=调色盘（水墨/国风）、
// 動漫電影=场记板、其他動漫=组合图形；未匹配回落 Heart
function channelIcon(name?: string | null) {
  const n = name ?? ""
  if (n.includes("日")) return Tv
  if (n.includes("國") || n.includes("国")) return Palette
  if (n.includes("電影") || n.includes("电影")) return Clapperboard
  if (n.includes("其他")) return Shapes
  return Heart
}

/** 判断某个底部 tab 是否处于激活态（详情页归属「首页」，频道更多页也归「首页」） */
function isActive(pathname: string, to: string) {
  if (to === "/") return pathname === "/" || pathname.startsWith("/video/") || pathname.startsWith("/more/")
  return pathname === to
}

export function AppShell() {
  const { pathname } = useLocation()
  const channelsQ = useQuery({
    queryKey: ["channels"],
    queryFn: async () => (await api.channels()).data,
    staleTime: 10 * 60_000,
  })
  const channels = Array.isArray(channelsQ.data) ? channelsQ.data : []

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon" className="hidden md:flex">
        <SidebarHeader>
          <Link to="/" className="flex items-center gap-2 px-2 py-1.5">
            <span className="flex size-8 items-center justify-center rounded-lg bg-primary text-base font-bold text-primary-foreground shadow-sm">
              囧
            </span>
            <span className="font-semibold">囧次元</span>
          </Link>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                {NAV.map((n) => (
                  <SidebarMenuItem key={n.to}>
                    <SidebarMenuButton asChild isActive={isActive(pathname, n.to)}>
                      <Link to={n.to}>
                        <n.icon />
                        <span>{n.label}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
          <SidebarGroup>
            <SidebarGroupLabel>频道</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {channels.map((c) => {
                  const Icon = channelIcon(c.name)
                  return (
                    <SidebarMenuItem key={c.id}>
                      <SidebarMenuButton asChild isActive={pathname === `/more/${c.id}`}>
                        <Link to={`/more/${c.id}?name=${encodeURIComponent(c.name ?? `频道${c.id}`)}`}>
                          <Icon />
                          <span>{c.name ?? `频道 ${c.id}`}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  )
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
      </Sidebar>

      <SidebarInset className="min-h-svh pb-app-tabbar md:pb-0">
        {/* 桌面端顶栏（移动端由各页自带页头，避免与页内搜索重复） */}
        <header className="safe-top sticky top-0 z-20 hidden h-app-topbar items-center gap-3 border-b border-border/70 bg-background/85 px-4 backdrop-blur-xl md:flex">
          <form
            className="ml-auto w-full max-w-sm"
            onSubmit={(e) => {
              e.preventDefault()
              const q = new FormData(e.currentTarget).get("key") as string
              if (q?.trim()) window.location.href = `/search?key=${encodeURIComponent(q.trim())}`
            }}
          >
            <Input
              name="key"
              placeholder="搜索番剧…"
              className="h-9 rounded-full border-transparent bg-muted/70 text-foreground"
            />
          </form>
        </header>

        <main className="flex-1 overflow-x-clip md:p-6">
          <Outlet />
        </main>
      </SidebarInset>

      {/* 移动端底部 tab（原 App 形态）—— 高度含手势条安全区，内容再上移一个安全区 */}
      <nav className="safe-bottom fixed inset-x-0 bottom-0 z-40 flex h-app-tabbar items-stretch border-t border-border/70 bg-background/95 pl-[env(safe-area-inset-left)] pr-[env(safe-area-inset-right)] backdrop-blur-xl md:hidden">
        {NAV.map((n) => {
          const active = isActive(pathname, n.to)
          return (
            <Link
              key={n.to}
              to={n.to}
              aria-current={active ? "page" : undefined}
              className={cn(
                "relative flex flex-1 flex-col items-center justify-center gap-1 transition-colors duration-200",
                active ? "text-primary" : "text-muted-foreground",
              )}
            >
              {/* 选中指示条：比单纯变色更容易一眼定位（X / Instagram 的既有范式） */}
              <span
                className={cn(
                  "absolute top-0 h-[3px] rounded-b-full bg-primary transition-all duration-300",
                  active ? "w-8 opacity-100" : "w-0 opacity-0",
                )}
              />
              <n.icon
                className={cn(
                  "size-[22px] transition-transform duration-200",
                  active ? "scale-105 stroke-[2.4]" : "stroke-[1.8]",
                )}
              />
              <span className={cn("text-[11px] leading-none", active && "font-medium")}>
                {n.label}
              </span>
            </Link>
          )
        })}
      </nav>
    </SidebarProvider>
  )
}
