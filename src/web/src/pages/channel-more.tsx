// 频道更多 —— /more/:channelId，分页网格（对应原 App /more/:channelId）
//
// 2026-10 样式重设计：页头改为统一的 PageHeader（返回 + 频道名 + 总数）；
// 分页从 PC 式「上一页/下一页」改为无限滚动（与搜索页一致，移动端范式）。

import { useEffect, useMemo, useRef } from "react"
import { useParams, useSearchParams } from "react-router"
import { useInfiniteQuery } from "@tanstack/react-query"

import { api } from "@/lib/api"
import { Skeleton } from "@/components/ui/skeleton"
import { VideoCard } from "@/components/video-card"
import { PageHeader } from "@/components/layout/page-header"

const PAGE_SIZE = 24

export default function ChannelMorePage() {
  const { channelId } = useParams()
  const [sp] = useSearchParams()
  const name = sp.get("name") ?? `频道 ${channelId}`

  const q = useInfiniteQuery({
    queryKey: ["video-list-page", channelId],
    initialPageParam: 1,
    queryFn: ({ pageParam }) =>
      api.videoList(Number(channelId!), "weight", PAGE_SIZE, pageParam),
    getNextPageParam: (last, all) => {
      const got = all.reduce((n, p) => n + (p.data?.items?.length ?? 0), 0)
      const total = last.data?.total ?? 0
      return got < total ? all.length + 1 : undefined
    },
    enabled: !!channelId,
    staleTime: 5 * 60_000,
  })

  const items = useMemo(
    () => (q.data?.pages ?? []).flatMap((p) => p.data?.items ?? []),
    [q.data],
  )
  const total = q.data?.pages?.[0]?.data?.total ?? 0

  const sentinelRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = sentinelRef.current
    if (!el) return
    const io = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting && q.hasNextPage && !q.isFetchingNextPage) {
          void q.fetchNextPage()
        }
      },
      { rootMargin: "400px 0px" },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [q.hasNextPage, q.isFetchingNextPage, q])

  return (
    <div className="pb-4">
      <PageHeader
        back
        title={name}
        subtitle={total ? `共 ${total} 部` : undefined}
      />

      <div className="px-4 pt-4">
        {q.isPending ? (
          <div className="grid grid-cols-3 gap-x-2.5 gap-y-4 md:grid-cols-6">
            {Array.from({ length: 12 }).map((_, i) => (
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
            {q.isFetchingNextPage ? (
              <p className="py-2 text-center text-xs text-muted-foreground">加载中…</p>
            ) : !q.hasNextPage ? (
              <p className="py-4 text-center text-xs text-muted-foreground">没有更多了</p>
            ) : null}
          </>
        ) : (
          <p className="py-20 text-center text-sm text-muted-foreground">该频道暂无内容</p>
        )}
      </div>
    </div>
  )
}
