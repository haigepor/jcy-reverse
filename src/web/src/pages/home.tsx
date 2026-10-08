// 首页 —— 对应原 App「频道」tab（截图结构）：
//   顶部频道 tabs：推荐 | 日漫 | 國漫 | 動漫電影 | 其他動漫（主色下划线激活，横向滚动）
//   搜索胶囊 + 右侧按钮（推荐页=「排期表」→ /time-line；频道页=「列表」→ /more/:id）
//   banner 轮播 = /app/banners/0（实测 6 条，首条 JOJO 第七部，与截图一致）
//   推荐 tab：每频道一条横向轨「推荐·{名}」+ 查看更多（video/list limit=6 sort=weight）
//   频道 tab：「热门推荐」3 列纵向网格 + 加载更多（同接口 limit=18 翻页，角标=完整 continu）
// 渲染优化：频道与 banner 并行请求；各 rail 独立 useQuery 天然并行；staleTime 分级缓存；
//   网格 useInfiniteQuery 翻页；骨架屏；图片 lazy + 固定宽高比防 CLS。

import { useCallback, useEffect, useState } from "react"
import { Link } from "react-router"
import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import useEmblaCarousel from "embla-carousel-react"
import { CalendarDays, ChevronRight, List, Search } from "lucide-react"

import { api } from "@/lib/api"
import type { GChannel } from "@/lib/types"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { VideoCard } from "@/components/video-card"
import { cn } from "@/lib/utils"

// ---------------------------------------------------------------- 频道 tabs

function ChannelTabs({
  tabs,
  active,
  onChange,
}: {
  tabs: { id: number; name: string }[]
  active: number
  onChange: (id: number) => void
}) {
  return (
    <div className="no-scrollbar -mx-4 flex gap-6 overflow-x-auto border-b px-4 md:mx-0 md:px-0 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => onChange(t.id)}
          className={cn(
            "relative shrink-0 pb-2.5 pt-1 text-[15px] font-medium transition-colors",
            active === t.id
              ? "text-primary"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {t.name}
          <span
            className={cn(
              "absolute inset-x-0 bottom-0 h-0.5 rounded-full transition-opacity",
              active === t.id ? "bg-primary opacity-100" : "opacity-0",
            )}
          />
        </button>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------- 搜索行

function SearchRow({
  mode,
  channelId,
  channelName,
}: {
  mode: "timeline" | "list"
  channelId?: number
  channelName?: string
}) {
  return (
    <div className="flex items-center gap-2.5">
      <Link
        to="/search"
        className="flex h-10 flex-1 items-center gap-2 rounded-full bg-muted px-4 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <Search className="size-4 shrink-0" />
        点击搜索视频
      </Link>
      {mode === "timeline" ? (
        <Button asChild className="h-10 shrink-0 rounded-full px-4 font-medium">
          <Link to="/time-line">
            <CalendarDays className="size-4" />
            排期表
          </Link>
        </Button>
      ) : channelId !== undefined ? (
        <Button
          asChild
          variant="secondary"
          className="h-10 shrink-0 rounded-full px-4 font-medium"
        >
          <Link to={`/more/${channelId}?name=${encodeURIComponent(channelName ?? "")}`}>
            <List className="size-4" />
            列表
          </Link>
        </Button>
      ) : null}
    </div>
  )
}

// ---------------------------------------------------------------- banner 轮播

function BannerCarousel() {
  const q = useQuery({
    queryKey: ["banners-home"],
    queryFn: () => api.banners(0),
    staleTime: 10 * 60_000,
  })
  const banners = (q.data?.data ?? []).filter((b) => b.img)
  const [emblaRef, emblaApi] = useEmblaCarousel({ loop: true, align: "start" })
  const [selected, setSelected] = useState(0)

  const onSelect = useCallback(() => {
    if (emblaApi) setSelected(emblaApi.selectedScrollSnap())
  }, [emblaApi])

  useEffect(() => {
    if (!emblaApi) return
    emblaApi.on("select", onSelect)
    onSelect()
    const h = setInterval(() => emblaApi.scrollNext(), 5000)
    return () => {
      emblaApi.off("select", onSelect)
      clearInterval(h)
    }
  }, [emblaApi, onSelect])

  if (q.isPending) {
    return <Skeleton className="h-44 w-full rounded-lg sm:h-52 md:h-64" />
  }
  if (!banners.length) return null

  return (
    <div
      className={cn(
        "space-y-2",
        // banner 加载完成 → 淡入上浮（数据到达时骨架屏交给 shimmer）
        "motion-safe:animate-in motion-safe:fade-in motion-safe:slide-in-from-bottom-2 motion-safe:duration-500",
      )}
    >
      <div className="w-full overflow-hidden rounded-lg" ref={emblaRef}>
        <div className="flex">
          {banners.map((b, i) => (
            <Link
              key={b.id ?? i}
              to={b.vid ? `/video/${b.vid}` : "#"}
              className="relative min-w-0 flex-[0_0_100%]"
            >
              <div className="relative h-44 w-full overflow-hidden rounded-lg bg-muted sm:h-52 md:h-64">
                <img
                  src={b.img}
                  alt={b.vname ?? ""}
                  className="h-full w-full object-cover"
                  loading={i === 0 ? "eager" : "lazy"}
                  referrerPolicy="no-referrer"
                  onError={(e) => {
                    e.currentTarget.style.display = "none"
                  }}
                />
                <div className="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/70 to-transparent p-3 pt-8">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-white">{b.vname}</span>
                    {b.continu ? (
                      <span className="rounded bg-white/20 px-1.5 py-0.5 text-xs text-white backdrop-blur">
                        {b.continu}
                      </span>
                    ) : null}
                  </div>
                </div>
              </div>
            </Link>
          ))}
        </div>
      </div>
      {banners.length > 1 ? (
        <div className="flex justify-center gap-1.5">
          {banners.map((_, i) => (
            <button
              key={i}
              onClick={() => emblaApi?.scrollTo(i)}
              aria-label={`第${i + 1}张`}
              className={cn(
                "h-1.5 rounded-full transition-all",
                i === selected ? "w-5 bg-primary" : "w-1.5 bg-muted-foreground/40",
              )}
            />
          ))}
        </div>
      ) : null}
    </div>
  )
}

// ---------------------------------------------------------------- 横向轨

/** 横向轨卡片宽度：移动 ~3.4 张可见 → 桌面 ~8 张，始终占满整行 */
const RAIL_CARD_W =
  "w-[29%] shrink-0 sm:w-[23%] md:w-[18%] lg:w-[15%] xl:w-[12.5%]"

function ChannelRail({ channelId, name }: { channelId: number; name?: string }) {
  const q = useInfiniteQuery({
    queryKey: ["video-rail", channelId],
    initialPageParam: 1,
    queryFn: ({ pageParam }) => api.videoList(channelId, "weight", 12, pageParam),
    getNextPageParam: (last, all) => {
      const got = all.reduce((n, p) => n + (p.data?.items.length ?? 0), 0)
      const total = last.data?.total ?? 0
      return got < total ? all.length + 1 : undefined
    },
    staleTime: 5 * 60_000,
  })
  const pages = q.data?.pages ?? []
  const items = pages.flatMap((p) => p.data?.items ?? [])

  // 数据不足铺满一行时自动翻页补齐（"少了数据就分页加载"）
  useEffect(() => {
    if (!q.isPending && q.hasNextPage && !q.isFetchingNextPage && items.length < 12) {
      q.fetchNextPage()
    }
  }, [q, items.length])

  const more = `/more/${channelId}?name=${encodeURIComponent(name ?? "")}`
  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold">推荐 · {name ?? channelId}</h2>
        <Link
          to={more}
          className="flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          查看更多 <ChevronRight className="size-4" />
        </Link>
      </div>
      {q.isPending ? (
        <div className="flex gap-3 overflow-hidden">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className={cn(RAIL_CARD_W, "space-y-1.5")}>
              <Skeleton className="aspect-[3/4] rounded-lg" />
              <Skeleton className="h-3.5 w-3/4" />
            </div>
          ))}
        </div>
      ) : items.length ? (
        <div className="no-scrollbar -mx-4 flex snap-x scroll-px-4 gap-3 overflow-x-auto px-4 pb-1 md:mx-0 md:px-0 md:scroll-px-0 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
          {items.map((v) => (
            <VideoCard key={v.id} video={v} variant="rail" />
          ))}
        </div>
      ) : null}
    </section>
  )
}

// ---------------------------------------------------------------- 热门网格

function HotGrid({ channelId, name }: { channelId: number; name?: string }) {
  const q = useInfiniteQuery({
    queryKey: ["video-grid", channelId],
    initialPageParam: 1,
    queryFn: ({ pageParam }) => api.videoList(channelId, "weight", 18, pageParam),
    getNextPageParam: (last, all) => {
      const got = all.reduce((n, p) => n + (p.data?.items.length ?? 0), 0)
      const total = last.data?.total ?? 0
      return got < total ? all.length + 1 : undefined
    },
    staleTime: 2 * 60_000,
  })
  const pages = q.data?.pages ?? []
  const items = pages.flatMap((p) => p.data?.items ?? [])
  const total = pages[0]?.data?.total ?? 0

  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold">
          热门推荐{name ? ` · ${name}` : ""}
        </h2>
        <Link
          to={`/more/${channelId}?name=${encodeURIComponent(name ?? "")}`}
          className="flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          查看更多 <ChevronRight className="size-4" />
        </Link>
      </div>

      {q.isPending ? (
        <div className="grid grid-cols-3 gap-x-3 gap-y-4 md:grid-cols-6">
          {Array.from({ length: 9 }).map((_, i) => (
            <div key={i} className="space-y-1.5">
              <Skeleton className="aspect-[3/4] rounded-lg" />
              <Skeleton className="h-3.5 w-4/5" />
            </div>
          ))}
        </div>
      ) : items.length ? (
        <>
          <div className="grid grid-cols-3 gap-x-3 gap-y-4 md:grid-cols-6">
            {items.map((v, i) => (
              <VideoCard
                key={v.id}
                video={v}
                variant="grid"
                style={{ animationDelay: `${Math.min(i % 18, 11) * 40}ms` }}
              />
            ))}
          </div>
          {q.hasNextPage ? (
            <div className="flex justify-center pt-1">
              <Button
                variant="outline"
                size="sm"
                onClick={() => q.fetchNextPage()}
                disabled={q.isFetchingNextPage}
              >
                {q.isFetchingNextPage
                  ? "加载中…"
                  : `加载更多（${items.length}/${total}）`}
              </Button>
            </div>
          ) : null}
        </>
      ) : (
        <p className="py-10 text-center text-sm text-muted-foreground">
          该频道暂无内容
        </p>
      )}
    </section>
  )
}

// ---------------------------------------------------------------- 页面

export default function HomePage() {
  const channelsQ = useQuery({
    queryKey: ["channels"],
    queryFn: async () => (await api.channels()).data,
    staleTime: 10 * 60_000,
  })
  const channels = (Array.isArray(channelsQ.data) ? channelsQ.data : []).filter(
    (c): c is GChannel & { id: number } => typeof c.id === "number",
  )
  const [tab, setTab] = useState(0) // 0 = 推荐
  const tabs = [{ id: 0, name: "推荐" }].concat(
    channels.map((c) => ({ id: c.id, name: c.name ?? `频道 ${c.id}` })),
  )
  const active = channels.find((c) => c.id === tab)

  return (
    <div className="space-y-5 overflow-x-clip pb-8">
      {channels.length > 1 ? (
        <ChannelTabs tabs={tabs} active={tab} onChange={setTab} />
      ) : null}

      <SearchRow
        mode={tab === 0 ? "timeline" : "list"}
        channelId={tab === 0 ? undefined : tab}
        channelName={active?.name}
      />

      <BannerCarousel />

      {tab === 0 ? (
        <div className="space-y-7">
          {channels.map((c) => (
            <ChannelRail key={c.id} channelId={c.id} name={c.name} />
          ))}
          {channelsQ.isPending
            ? Array.from({ length: 2 }).map((_, i) => (
                <div key={i} className="space-y-3">
                  <Skeleton className="h-5 w-32" />
                  <div className="flex gap-3 overflow-hidden">
                    {Array.from({ length: 4 }).map((_, j) => (
                      <div key={j} className={cn(RAIL_CARD_W, "space-y-1.5")}>
                        <Skeleton className="aspect-[3/4] rounded-lg" />
                        <Skeleton className="h-3.5 w-3/4" />
                      </div>
                    ))}
                  </div>
                </div>
              ))
            : null}
        </div>
      ) : active ? (
        <HotGrid channelId={active.id} name={active.name} />
      ) : null}

      {channelsQ.isError ? (
        <p className="text-sm text-muted-foreground">
          频道加载失败：{String(channelsQ.error)}
        </p>
      ) : null}
    </div>
  )
}
