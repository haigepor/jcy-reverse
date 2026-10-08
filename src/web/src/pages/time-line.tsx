// 排期（对应原 App /time-line）—— /app/video_update_list/{yyyy-mm-dd}，按周切换查看每日更新。

import { useMemo, useState } from "react"
import { useQuery, keepPreviousData } from "@tanstack/react-query"
import { cn } from "cn"

import { api } from "@/lib/api"
import type { GVideo } from "@/lib/types"
import { Skeleton } from "@/components/ui/skeleton"
import { VideoCard } from "@/components/video-card"

const WEEKDAYS = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"]

function fmt(d: Date) {
  const p = (n: number) => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

/** 本周周一为起点的 7 天（今天高亮，默认选中） */
function weekOf(now: Date) {
  const mon = new Date(now)
  const wd = now.getDay() === 0 ? 7 : now.getDay()
  mon.setDate(now.getDate() - (wd - 1))
  return Array.from({ length: 7 }, (_, i) => {
    const d = new Date(mon)
    d.setDate(mon.getDate() + i)
    return d
  })
}

export default function TimeLinePage() {
  const today = useMemo(() => new Date(), [])
  const week = useMemo(() => weekOf(today), [today])
  const [date, setDate] = useState(fmt(today))

  const q = useQuery({
    queryKey: ["update-list", date],
    queryFn: () => api.updateList(date, 100),
    placeholderData: keepPreviousData,
  })

  // 接口实测字段（/app/video_update_list/{yyyy-mm-dd}）：
  //   { id, vid, remark, date, vod_name, vod_pic, vod_isend, vod_endat }
  // 封面/标题在 vod_pic/vod_name，跳转要用 vid（id 是排期记录自身的主键）
  interface RawUpdateItem {
    id?: number
    vid?: number
    remark?: string
    vod_name?: string
    vod_pic?: string
  }
  const items: GVideo[] = useMemo(() => {
    const d = q.data?.data
    const raw: RawUpdateItem[] = Array.isArray(d)
      ? d
      : d?.items ?? d?.list ?? []
    return raw
      .filter((r) => r.vid || r.id)
      .map((r) => ({
        id: (r.vid ?? r.id) as number,
        cid: 0, // 排期条目无频道字段，卡片不需要
        name: r.vod_name ?? "",
        pic: r.vod_pic,
        continu: r.remark || undefined,
      }))
  }, [q.data])

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">更新排期</h1>
      <div className="flex flex-wrap gap-2">
        {week.map((d) => {
          const ds = fmt(d)
          const active = ds === date
          return (
            <button
              key={ds}
              onClick={() => setDate(ds)}
              className={cn(
                "rounded-md border px-3 py-1.5 text-sm transition-colors",
                active
                  ? "bg-primary text-primary-foreground"
                  : "bg-background hover:bg-accent",
                ds === fmt(today) && !active && "border-primary/50",
              )}
            >
              {WEEKDAYS[d.getDay()]}
              <span className="ml-1 text-xs opacity-70">{ds.slice(5)}</span>
            </button>
          )
        })}
      </div>

      {q.isPending || q.isPlaceholderData ? (
        // 与 VideoCard 同构的骨架：海报块 + 标题行（shimmer 全站统一）
        <div className="grid grid-cols-3 gap-3 md:grid-cols-6">
          {Array.from({ length: 12 }).map((_, i) => (
            <div key={i} className="space-y-1.5">
              <Skeleton className="aspect-[3/4] rounded-lg" />
              <Skeleton className="h-3.5 w-4/5" />
            </div>
          ))}
        </div>
      ) : items.length ? (
        <div className="grid grid-cols-3 gap-3 md:grid-cols-6">
          {items.map((v, i) => (
            <VideoCard
              key={v.id}
              video={v}
              style={{ animationDelay: `${Math.min(i, 11) * 40}ms` }}
            />
          ))}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          {date} 暂无更新（接口空数据）
        </p>
      )}

      <p className="text-xs text-muted-foreground">
        提示：部分番剧的更新时间在“详情页”的连载信息里（如 周三23:15更），排期以服务端
        video_update_list 为准。
      </p>
    </div>
  )
}
