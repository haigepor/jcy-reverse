// 首页 —— 对应原 App「频道」tab。
//   顶部：品牌标 + 搜索胶囊 + 次级入口（推荐页=排期表；频道页=列表），下一行频道 tabs
//   banner 轮播 = /app/banners/0（实测 6 条，首条 JOJO 第七部，与截图一致）
//   推荐 tab：每频道一条横向轨「推荐·{名}」+ 查看更多（video/list limit=12 sort=weight）
//   频道 tab：「热门推荐」3 列纵向网格 + 加载更多（同接口 limit=18 翻页）
//
// 2026-10 样式重设计（首页是改动最大的页面）：
//   1. **头部从三层压到两层**：旧版 = 全局顶栏搜索框 + 频道 tabs + 页内搜索胶囊行，
//      吃掉约 1/3 首屏，且同屏两个搜索框。现在把「品牌标 + 搜索胶囊 + 次级入口」
//      合并成一行（h-14），频道 tabs 紧随其下（h-11）。
//   2. **Banner 改 16:9 沉浸式**：旧版 h-44（176px）近方形，横向海报被裁得只剩中间，
//      标题两行压在图上还和「8全」角标打架。现在 16:9 + 底部 scrim 渐变 +
//      单行标题 + 集数角标，页码点阵并入右下角（不再单独占一行）。
//   3. rail 标题加品牌色竖条，层级从「灰字小标题」升为「可扫读的分区」。
//
// 渲染优化（保持不变）：频道与 banner 并行请求；各 rail 独立 useQuery 天然并行；
//   staleTime 分级缓存；网格 useInfiniteQuery 翻页；骨架屏；图片 lazy + 固定宽高比防 CLS。

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
import { PageHeader } from "@/components/layout/page-header"
import { cn } from "@/lib/utils"

// ---------------------------------------------------------------- 页头

function HomeHeader({
  tabs,
  active,
  onChange,
  channelId,
  channelName,
}: {
  tabs: { id: number; name: string }[]
  active: number
  onChange: (id: number) => void
  channelId?: number
  channelName?: string
}) {
  return (
    <PageHeader
      className="px-0"
      title={
        <span className="flex items-center gap-2">
          <span className="flex size-7 items-center justify-center rounded-lg bg-primary text-[15px] font-bold text-primary-foreground">
            囧
          </span>
          <span className="text-[17px] font-semibold tracking-tight">囧次元</span>
        </span>
      }
      right={
        channelId !== undefined ? (
          <Link
            to={`/more/${channelId}?name=${encodeURIComponent(channelName ?? "")}`}
            aria-label="列表"
            className="flex size-9 items-center justify-center rounded-full bg-muted text-muted-foreground transition-colors active:bg-accent"
          >
            <List className="size-[18px]" />
          </Link>
        ) : (
          <Link
            to="/time-line"
            aria-label="排期表"
            className="flex size-9 items-center justify-center rounded-full bg-muted text-muted-foreground transition-colors active:bg-accent"
          >
            <CalendarDays className="size-[18px]" />
          </Link>
        )
      }
    >
      {/* 搜索胶囊：整行放在品牌行下方，与频道 tabs 同属页头（避免旧版的「顶栏一个 + 页内一个」） */}
      <div className="px-3 pb-1">
        <Link
          to="/search"
          className="flex h-9 items-center gap-2 rounded-full bg-muted px-3.5 text-sm text-muted-foreground transition-colors active:bg-accent"
        >
          <Search className="size-4 shrink-0" />
          搜索番剧、角色、声优
        </Link>
      </div>

      {tabs.length > 1 ? (
        <div className="no-scrollbar flex gap-5 overflow-x-auto px-3">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => onChange(t.id)}
              className={cn(
                "relative shrink-0 pb-2.5 pt-1.5 text-[15px] transition-colors",
                active === t.id
                  ? "font-semibold text-foreground"
                  : "font-medium text-muted-foreground",
              )}
            >
              {t.name}
              <span
                className={cn(
                  "absolute inset-x-0 bottom-1 mx-auto h-[3px] w-5 rounded-full bg-primary transition-all duration-300",
                  active === t.id ? "opacity-100" : "w-0 opacity-0",
                )}
              />
            </button>
          ))}
        </div>
      ) : null}
    </PageHeader>
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
    return <Skeleton className="aspect-[16/9] w-full rounded-xl" />
  }
  if (!banners.length) return null

  return (
    <div
      className={cn(
        "w-full overflow-hidden rounded-xl",
        "motion-safe:animate-in motion-safe:fade-in motion-safe:duration-500",
      )}
      ref={emblaRef}
    >
      <div className="flex">
        {banners.map((b, i) => (
          <Link
            key={b.id ?? i}
            to={b.vid ? `/video/${b.vid}` : "#"}
            className="relative min-w-0 flex-[0_0_100%]"
          >
            <div className="ring-hairline relative aspect-[16/9] w-full overflow-hidden rounded-xl bg-muted">
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
              {/* 底部渐变遮罩：图与字的过渡层，比旧版 from-black/70 更陡（底部更实、上方全透） */}
              <div className="scrim-bottom absolute inset-x-0 bottom-0 p-3 pt-10">
                <p className="truncate pr-16 text-[15px] font-semibold text-white drop-shadow">
                  {b.vname}
                </p>
              </div>
              {/* 集数角标：右上角，与卡片角标体系呼应（旧版压在标题行右侧，会跟长标题打架） */}
              {b.continu ? (
                <span className="absolute right-2 top-2 rounded-md bg-black/65 px-2 py-1 text-[11px] font-medium leading-none text-white backdrop-blur-sm">
                  {b.continu}
                </span>
              ) : null}
              {/* 页码点阵：并入右下角，省掉旧版 banner 下方那条独立指示行 */}
              {banners.length > 1 ? (
                <div className="absolute bottom-3 right-3 flex gap-1">
                  {banners.map((_, j) => (
                    <span
                      key={j}
                      className={cn(
                        "h-1.5 rounded-full transition-all duration-300",
                        j === selected ? "w-4 bg-primary" : "w-1.5 bg-white/45",
                      )}
                    />
                  ))}
                </div>
              ) : null}
            </div>
          </Link>
        ))}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- 横向轨

/** 横向轨卡片宽度：移动 ~3.4 张可见 → 桌面 ~8 张，始终占满整行 */
const RAIL_CARD_W =
  "w-[29%] shrink-0 sm:w-[23%] md:w-[18%] lg:w-[15%] xl:w-[12.5%]"

/** 分区标题：品牌色竖条 + 标题 + 右侧「查看更多」 */
function SectionTitle({ children, to }: { children: React.ReactNode; to?: string }) {
  return (
    <div className="flex items-center justify-between">
      <h2 className="flex items-center gap-2 text-[15px] font-semibold tracking-tight">
        <span className="h-4 w-[3px] rounded-full bg-primary" />
        {children}
      </h2>
      {to ? (
        <Link
          to={to}
          className="flex items-center gap-0.5 text-xs text-muted-foreground transition-colors active:text-foreground"
        >
          全部 <ChevronRight className="size-3.5" />
        </Link>
      ) : null}
    </div>
  )
}

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
      <SectionTitle to={more}>推荐 · {name ?? channelId}</SectionTitle>
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
        <div className="no-scrollbar -mx-4 flex snap-x scroll-px-4 gap-2.5 overflow-x-auto px-4 pb-1 md:mx-0 md:px-0 md:scroll-px-0">
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
      <SectionTitle>热门推荐{name ? ` · ${name}` : ""}</SectionTitle>

      {q.isPending ? (
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
                variant="grid"
                style={{ animationDelay: `${Math.min(i % 18, 11) * 40}ms` }}
              />
            ))}
          </div>
          {q.hasNextPage ? (
            <div className="flex justify-center pt-1">
              <Button
                variant="secondary"
                size="sm"
                className="rounded-full px-5"
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
        <p className="py-10 text-center text-sm text-muted-foreground">该频道暂无内容</p>
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
    <div className="pb-4">
      <HomeHeader
        tabs={tabs}
        active={tab}
        onChange={setTab}
        channelId={tab === 0 ? undefined : tab}
        channelName={active?.name}
      />

      <div className="space-y-5 px-4 pt-4">
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
    </div>
  )
}
