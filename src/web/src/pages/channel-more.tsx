// 频道更多 —— /more/:channelId，分页网格（对应原 App /more/:channelId）

import { Link, useParams, useSearchParams } from "react-router"
import { useQuery, keepPreviousData } from "@tanstack/react-query"

import { api } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { VideoCard } from "@/components/video-card"

const PAGE_SIZE = 24

export default function ChannelMorePage() {
  const { channelId } = useParams()
  const [sp, setSp] = useSearchParams()
  const page = Math.max(1, Number(sp.get("page") ?? 1))
  const name = sp.get("name") ?? `频道 ${channelId}`

  const q = useQuery({
    queryKey: ["video-list-page", channelId, page],
    queryFn: () => api.videoList(Number(channelId!), "weight", PAGE_SIZE, page),
    placeholderData: keepPreviousData,
    enabled: !!channelId,
  })
  const items = q.data?.data?.items ?? []
  const total = q.data?.data?.total ?? 0
  const pages = Math.ceil(total / PAGE_SIZE)

  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">{name}</h1>
        <span className="text-sm text-muted-foreground">共 {total} 部</span>
      </div>

      {q.isPending ? (
        <div className="grid grid-cols-3 gap-3 md:grid-cols-6">
          {Array.from({ length: 12 }).map((_, i) => (
            <Skeleton key={i} className="aspect-[3/4]" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-3 md:grid-cols-6">
          {items.map((v, i) => (
            <VideoCard key={v.id} video={v} style={{ animationDelay: `${Math.min(i % 25, 11) * 40}ms` }} />
          ))}
        </div>
      )}

      {pages > 1 ? (
        <div className="flex items-center justify-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1}
            onClick={() => setSp({ name, page: String(page - 1) })}
          >
            上一页
          </Button>
          <span className="text-sm text-muted-foreground">
            {page} / {pages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= pages}
            onClick={() => setSp({ name, page: String(page + 1) })}
          >
            下一页
          </Button>
        </div>
      ) : null}

      {items.length === 0 && !q.isPending ? (
        <p className="text-sm text-muted-foreground">
          没有数据。回到<Link to="/" className="underline">首页</Link>。
        </p>
      ) : null}
    </div>
  )
}
