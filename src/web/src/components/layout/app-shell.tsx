// 应用外壳 —— 桌面侧边栏（对应原 App go_router 的底部四 tab + 频道树），
// 移动端自动降级为底部 tab。

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
  SidebarTrigger,
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
            <span className="flex size-8 items-center justify-center rounded-md bg-primary font-bold text-primary-foreground">
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
                    <SidebarMenuButton asChild isActive={pathname === n.to}>
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
        <header className="safe-top sticky top-0 z-20 flex h-app-header items-center gap-3 border-b bg-background/90 px-4 backdrop-blur">
          <SidebarTrigger className="md:hidden" />
          <form
            className="ml-auto w-full max-w-xs"
            onSubmit={(e) => {
              e.preventDefault()
              const q = new FormData(e.currentTarget).get("key") as string
              if (q?.trim()) window.location.href = `/search?key=${encodeURIComponent(q.trim())}`
            }}
          >
            <Input
              name="key"
              placeholder="搜索番剧…"
              className="h-9 rounded-full border-muted-foreground/40 bg-muted/70 text-foreground"
            />
          </form>
        </header>
        <main className="flex-1 overflow-x-clip p-4 md:p-6"><Outlet /></main>
      </SidebarInset>

      {/* 移动端底部 tab（原 App 形态）—— 高度含手势条安全区，内容再上移一个安全区 */}
      <nav className="safe-bottom fixed inset-x-0 bottom-0 z-30 flex h-app-tabbar items-center justify-around border-t bg-background pl-[env(safe-area-inset-left)] pr-[env(safe-area-inset-right)] md:hidden">
        {NAV.map((n) => (
          <Link
            key={n.to}
            to={n.to}
            className={cn(
              "flex flex-col items-center gap-1 text-xs text-muted-foreground",
              pathname === n.to && "text-foreground",
            )}
          >
            <n.icon className="size-5" />
            {n.label}
          </Link>
        ))}
      </nav>
    </SidebarProvider>
  )
}
