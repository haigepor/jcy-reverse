// 搜索 —— 联想词（/app/video/key，防抖）+ 结果分页（/app/video/search，参数名是 key）
//
// 2026-10 样式重设计：
//   1. 旧版页面顶部是「全局搜索栏 + 页内搜索框」两个输入框叠着，现在全局栏已从
//      AppShell 移除，这里只保留**一个**页头搜索框（带返回）。
//   2. **补空态**：旧版只有一句「输入关键词开始搜索」，屏幕 90% 是空白。
//      现在空态 = 搜索历史（localStorage）+ 大家都在搜（热门视频名）+ 热门推荐网格。
//   3. 分页从 PC 式「上一页/下一页」改为**无限滚动**（移动端范式），
//      用 IntersectionObserver 提前 400px 预取。

import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { useNavigate, useSearchParams } from "react-router"
import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { ChevronLeft, Clock3, Flame, Search, Trash2 } from "lucide-react"

import { api } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { VideoCard } from "@/components/video-card"

const PAGE_SIZE = 25
const HISTORY_KEY = "jcy-search-history"
const HISTORY_MAX = 12

function loadHistory(): string[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY)
    const arr = raw ? JSON.parse(raw) : []
    return Array.isArray(arr) ? arr.filter((s) => typeof s === "string").slice(0, HISTORY_MAX) : []
  } catch {
    return []
  }
}

function pushHistory(key: string, cur: string[]): string[] {
  const next = [key, ...cur.filter((k) => k !== key)].slice(0, HISTORY_MAX)
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(next))
  } catch {
    // 隐私模式/配额满：历史功能静默降级
  }
  return next
}

export default function SearchPage() {
  const nav = useNavigate()
  const [sp, setSp] = useSearchParams()
  const key = sp.get("key") ?? ""
  const [input, setInput] = useState(key)
  const [history, setHistory] = useState<string[]>([])

  useEffect(() => setHistory(loadHistory()), [])
  // 从外部（首页搜索胶囊跳转）带 key 进来时同步输入框
  useEffect(() => setInput(key), [key])

  const submit = useCallback(
    (k: string) => {
      const v = k.trim()
      if (!v) return
      setHistory((cur) => pushHistory(v, cur))
      setSp({ key: v })
    },
    [setSp],
  )

  const resultQ = useInfiniteQuery({
    queryKey: ["search", key],
    initialPageParam: 1,
    queryFn: ({ pageParam }) => api.search(key, PAGE_SIZE, pageParam),
    getNextPageParam: (last, all) => {
      const got = all.reduce((n, p) => n + (p.data?.items?.length ?? 0), 0)
      const total = last.data?.total ?? 0
      return got < total ? all.length + 1 : undefined
    },
    enabled: !!key,
    staleTime: 5 * 60_000,
  })

  const items = useMemo(
    () => (resultQ.data?.pages ?? []).flatMap((p) => p.data?.items ?? []),
    [resultQ.data],
  )
  const total = resultQ.data?.pages?.[0]?.data?.total ?? 0

  // 空态数据：热门视频（既当「大家都在搜」的词源，也直接铺成推荐网格）
  const hotQ = useQuery({
    queryKey: ["search-hot"],
    queryFn: () => api.videoList(1, "weight", 12, 1),
    enabled: !key,
    staleTime: 10 * 60_000,
  })
  const hotItems = hotQ.data?.data?.items ?? []

  // 无限滚动：sentinel 进入视口前 400px 就预取下一页
  const sentinelRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = sentinelRef.current
    if (!el || !key) return
    const io = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting && resultQ.hasNextPage && !resultQ.isFetchingNextPage) {
          void resultQ.fetchNextPage()
        }
      },
      { rootMargin: "400px 0px" },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [key, resultQ.hasNextPage, resultQ.isFetchingNextPage, resultQ])

  const searching = !!key && (resultQ.isPending || (resultQ.isFetching && !items.length))

  return (
    <div className="pb-4">
      {/* 页头：唯一的一个搜索框（取消归 AppShell 的全局栏之后） */}
      <header className="safe-top sticky top-0 z-30 border-b border-border/70 bg-background/85 backdrop-blur-xl">
        <div className="flex h-app-topbar items-center gap-2 px-2">
          <button
            type="button"
            onClick={() => (history.length > 1 ? nav(-1) : nav("/"))}
            aria-label="返回"
            className="flex size-9 shrink-0 items-center justify-center rounded-full transition-colors active:bg-muted"
          >
            <ChevronLeft className="size-6" />
          </button>
          <form
            className="flex min-w-0 flex-1 items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              submit(input)
            }}
          >
            <div className="relative min-w-0 flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="搜索番剧、角色、声优"
                enterKeyHint="search"
                className="h-9 w-full rounded-full border border-transparent bg-muted pl-9 pr-3 text-sm outline-none transition-colors placeholder:text-muted-foreground focus:border-primary/60 focus:bg-background"
              />
            </div>
            {input.trim() ? (
              <Button type="submit" size="sm" className="h-9 shrink-0 rounded-full px-4">
                搜索
              </Button>
            ) : null}
          </form>
        </div>
      </header>

      <div className="px-4 pt-4">
        {key ? (
          <>
            <p className="mb-3 text-xs text-muted-foreground">
              「{key}」共 {total} 个结果
            </p>

            {searching ? (
              <div className="grid grid-cols-3 gap-x-2.5 gap-y-4 md:grid-cols-6">
                {Array.from({ length: 9 }).map((_, i) => (
                  <div key={i} className="space-y-1.5">
                    <Skeleton className="aspect-[3/4] rounded-lg" />
                    <Skeleton className="h-3.5 w-4/5" />
                  </div>
                ))}
              </div>
            ) : items.length ? (
              <>
                <div className="grid grid-cols-3 gap-x-2.5 gap-y-4 md:grid-cols-6">
                  {items.map((v, i) => (
                    <VideoCard
                      key={v.id}
                      video={v}
                      style={{ animationDelay: `${Math.min(i % 25, 11) * 40}ms` }}
                    />
                  ))}
                </div>
                <div ref={sentinelRef} className="h-10" />
                {resultQ.isFetchingNextPage ? (
                  <p className="py-2 text-center text-xs text-muted-foreground">加载中…</p>
                ) : !resultQ.hasNextPage ? (
                  <p className="py-4 text-center text-xs text-muted-foreground">没有更多了</p>
                ) : null}
              </>
            ) : (
              <div className="py-16 text-center">
                <p className="text-sm font-medium">没有找到「{key}」</p>
                <p className="mt-1 text-xs text-muted-foreground">换个关键词试试</p>
              </div>
            )}
          </>
        ) : (
          // ---------------- 空态：历史 + 热门词 + 热门推荐 ----------------
          <div className="space-y-6">
            {history.length ? (
              <section className="space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="flex items-center gap-1.5 text-sm font-semibold">
                    <Clock3 className="size-4 text-muted-foreground" />
                    搜索历史
                  </h2>
                  <button
                    type="button"
                    aria-label="清空搜索历史"
                    onClick={() => {
                      setHistory([])
                      try {
                        localStorage.removeItem(HISTORY_KEY)
                      } catch {
                        /* ignore */
                      }
                    }}
                    className="flex items-center gap-1 text-xs text-muted-foreground transition-colors active:text-foreground"
                  >
                    <Trash2 className="size-3.5" />
                    清空
                  </button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {history.map((h) => (
                    <button
                      key={h}
                      type="button"
                      onClick={() => submit(h)}
                      className="max-w-full truncate rounded-full bg-muted px-3.5 py-1.5 text-[13px] text-foreground/90 transition-colors active:bg-accent"
                    >
                      {h}
                    </button>
                  ))}
                </div>
              </section>
            ) : null}

            {hotItems.length ? (
              <section className="space-y-3">
                <h2 className="flex items-center gap-1.5 text-sm font-semibold">
                  <Flame className="size-4 text-primary" />
                  大家都在搜
                </h2>
                <div className="flex flex-wrap gap-2">
                  {hotItems.slice(0, 10).map((v) => (
                    <button
                      key={v.id}
                      type="button"
                      onClick={() => submit(v.name)}
                      className="max-w-full truncate rounded-full border border-border px-3.5 py-1.5 text-[13px] text-foreground/90 transition-colors active:bg-accent"
                    >
                      {v.name}
                    </button>
                  ))}
                </div>
              </section>
            ) : null}

            <section className="space-y-3">
              <h2 className="flex items-center gap-2 text-sm font-semibold">
                <span className="h-3.5 w-[3px] rounded-full bg-primary" />
                热门推荐
              </h2>
              {hotQ.isPending ? (
                <div className="grid grid-cols-3 gap-x-2.5 gap-y-4 md:grid-cols-6">
                  {Array.from({ length: 6 }).map((_, i) => (
                    <div key={i} className="space-y-1.5">
                      <Skeleton className="aspect-[3/4] rounded-lg" />
                      <Skeleton className="h-3.5 w-4/5" />
                    </div>
                  ))}
                </div>
              ) : (
                <div className="grid grid-cols-3 gap-x-2.5 gap-y-4 md:grid-cols-6">
                  {hotItems.slice(0, 6).map((v, i) => (
                    <VideoCard
                      key={v.id}
                      video={v}
                      style={{ animationDelay: `${Math.min(i, 5) * 40}ms` }}
                    />
                  ))}
                </div>
              )}
            </section>
          </div>
        )}
      </div>
    </div>
  )
}
