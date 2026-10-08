// 排期（对应原 App /time-line）—— /app/video_update_list/{yyyy-mm-dd}，按周切换查看每日更新。
//
// 2026-10 样式重设计：
//   1. 日期选择从「flex-wrap 3 列网格」改为**单行横向滚动**（旧版 7 个日期换 3 行，
//      占掉大量首屏；且最后一个「周日」孤零零占一行）。
//   2. 去掉页脚那段写给开发者看的接口说明（「排期以服务端 video_update_list 为准」），
//      用户不需要知道数据来源。
//   3. 日期胶囊加「今天」标记（品牌色描边 + 今日文字），命中当天更直观。

import { useMemo, useState } from "react"
import { useQuery, keepPreviousData } from "@tanstack/react-query"
import { cn } from "cn"

import { api } from "@/lib/api"
import type { GVideo } from "@/lib/types"
import { Skeleton } from "@/components/ui/skeleton"
import { VideoCard } from "@/components/video-card"
import { PageHeader } from "@/components/layout/page-header"

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
  const todayStr = fmt(today)
  const [date, setDate] = useState(todayStr)

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
    const raw: RawUpdateItem[] = Array.isArray(d) ? d : d?.items ?? d?.list ?? []
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

  // 排期数据偶有 vod_name 为空的记录（下架/元数据缺失），空标题卡片没有意义，过滤掉
  const visible = items.filter((v) => v.name)

  return (
    <div className="pb-4">
      <PageHeader title="更新排期" subtitle={date === todayStr ? "今天" : date} />

      {/* 日期：单行横向滚动（旧版三行网格） */}
      <div className="no-scrollbar flex gap-2 overflow-x-auto px-4 pt-3 [scrollbar-width:none]">
        {week.map((d) => {
          const ds = fmt(d)
          const active = ds === date
          const isToday = ds === todayStr
          return (
            <button
              key={ds}
              onClick={() => setDate(ds)}
              className={cn(
                "flex shrink-0 flex-col items-center gap-0.5 rounded-xl px-3.5 py-2 transition-colors",
                active
                  ? "bg-primary text-primary-foreground"
                  : isToday
                    ? "border border-primary/60 bg-primary/10 text-foreground"
                    : "bg-muted text-muted-foreground",
              )}
            >
              <span className="text-[13px] font-medium leading-none">
                {WEEKDAYS[d.getDay()]}
                {isToday && !active ? <span className="ml-0.5 text-[10px]">今天</span> : null}
              </span>
              <span
                className={cn(
                  "text-[11px] leading-none tabular-nums",
                  active ? "opacity-90" : "opacity-70",
                )}
              >
                {ds.slice(5)}
              </span>
            </button>
          )
        })}
      </div>

      <div className="px-4 pt-4">
        {q.isPending || q.isPlaceholderData ? (
          <div className="grid grid-cols-3 gap-x-2.5 gap-y-4 md:grid-cols-6">
            {Array.from({ length: 12 }).map((_, i) => (
              <div key={i} className="space-y-1.5">
                <Skeleton className="aspect-[3/4] rounded-lg" />
                <Skeleton className="h-3.5 w-4/5" />
              </div>
            ))}
          </div>
        ) : visible.length ? (
          <div className="grid grid-cols-3 gap-x-2.5 gap-y-4 md:grid-cols-6">
            {visible.map((v, i) => (
              <VideoCard
                key={v.id}
                video={v}
                style={{ animationDelay: `${Math.min(i, 11) * 40}ms` }}
              />
            ))}
          </div>
        ) : (
          <div className="py-20 text-center">
            <p className="text-sm text-muted-foreground">这一天暂无更新</p>
          </div>
        )}
      </div>
    </div>
  )
}
