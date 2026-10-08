// 视频卡片 —— 三形态共用：rail=首页横向轨、grid=频道页热门网格、
// default=搜索/更多/排期页（多一行 年份·地区·类型）。
// continu 实测格式："1|周三23:15更" / "第1集" / "1080P" / "4K" / "10全"
//
// 2026-10 样式重设计：
//   1. **角标体系统一**（旧版是两套各自为政：rail 用底部渐变条、grid 用左上小标签，
//      同屏出现两种语言）。现在统一为「左上=更新状态胶囊，右上=评分」，
//      深色半透明 + backdrop-blur，压在任意海报上都能读。
//   2. 标题统一**两行截断**（旧版单行，中文番剧名长，"归还者的魔法要..." 被砍得看不懂）。
//   3. 海报加 `ring-hairline` 极淡内描边 —— 深底上大量海报的白色边缘会糊在一起。
//   4. 圆角随设计系统（rounded-lg → 12px），hover 微放大保留（桌面）。

import { Link } from "react-router"
import { Star } from "lucide-react"

import type { GVideo } from "@/lib/types"
import { cn } from "@/lib/utils"

/** rail 轨道标题行："1|周三23:15更" → "周三23:15更"，无 "|" 原样返回 */
export function continuLabel(continu?: string | null): string {
  if (!continu) return ""
  const i = continu.indexOf("|")
  return i >= 0 ? continu.slice(i + 1) : continu
}

export function VideoCard({
  video,
  variant = "default",
  className,
  style,
}: {
  video: GVideo
  variant?: "rail" | "grid" | "default"
  className?: string
  /** 传入 animationDelay 可做瀑布式错峰入场 */
  style?: React.CSSProperties
}) {
  const label = video.continu ?? ""
  const short = continuLabel(label)

  return (
    <Link
      to={`/video/${video.id}`}
      style={style}
      className={cn(
        "group flex flex-col gap-1.5 rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-ring",
        // 入场：淡入 + 8px 上浮，仅首挂载播放（翻页追加的新卡片也会依次入场）
        "motion-safe:animate-in motion-safe:fade-in motion-safe:slide-in-from-bottom-2 motion-safe:duration-500",
        variant === "rail" &&
          "w-[29%] shrink-0 snap-start sm:w-[23%] md:w-[18%] lg:w-[15%] xl:w-[12.5%]",
        className,
      )}
    >
      <div className="ring-hairline relative aspect-[3/4] w-full overflow-hidden rounded-lg bg-muted">
        {video.pic ? (
          <img
            src={video.pic}
            alt={video.name}
            loading="lazy"
            decoding="async"
            referrerPolicy="no-referrer"
            onError={(e) => {
              e.currentTarget.style.display = "none"
            }}
            className="h-full w-full object-cover transition-transform duration-300 group-hover:scale-[1.04]"
          />
        ) : (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
            无封面
          </div>
        )}

        {/* 左上：更新状态（统一入口，rail 与 grid 不再各写一套） */}
        {short ? (
          <span className="absolute left-0 top-0 max-w-[88%] truncate rounded-br-lg rounded-tl-lg bg-black/72 px-1.5 py-1 text-[10px] font-medium leading-none text-white backdrop-blur-sm">
            {short}
          </span>
        ) : null}

        {/* 右上：评分 */}
        {video.score ? (
          <span className="absolute right-1 top-1 flex items-center gap-0.5 rounded-md bg-black/72 px-1.5 py-0.5 text-[11px] font-semibold leading-none text-rating backdrop-blur-sm">
            <Star className="size-2.5 fill-current" />
            {video.score}
          </span>
        ) : null}
      </div>

      <p
        className={cn(
          "line-clamp-2 text-[13px] font-medium leading-snug group-hover:text-primary",
          variant === "rail" && "text-xs",
        )}
      >
        {video.name}
      </p>

      {variant === "default" ? (
        <p className="truncate text-xs leading-none text-muted-foreground">
          {[video.year, video.area, video.type?.split(",")[0]].filter(Boolean).join(" · ")}
        </p>
      ) : null}
    </Link>
  )
}
