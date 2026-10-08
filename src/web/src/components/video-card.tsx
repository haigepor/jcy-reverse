// 视频卡片 —— 三形态共用：rail=首页横向轨（海报+底部更新时间+标题）
// grid=频道页热门推荐网格（海报+左上角标+标题） default=搜索/更多页（角标+年份地区类型行）
// continu 实测格式："1|周三23:15更" / "第1集" / "1080P" / "4K" / "10全"

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
      <div className="relative aspect-[3/4] w-full overflow-hidden rounded-lg bg-muted">
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
            className="h-full w-full object-cover transition-transform group-hover:scale-105"
          />
        ) : (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
            无封面
          </div>
        )}

        {video.score ? (
          <span className="absolute left-1.5 top-1.5 flex items-center gap-0.5 rounded bg-black/70 px-1.5 py-0.5 text-[11px] font-medium text-amber-400">
            <Star className="size-3 fill-amber-400" />
            {video.score}
          </span>
        ) : null}

        {variant === "rail" ? (
          short ? (
            <div className="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/80 to-transparent px-1.5 pb-1 pt-4">
              <p className="truncate text-[10px] leading-4 text-white/90">{short}</p>
            </div>
          ) : null
        ) : label ? (
          <span className="absolute left-1.5 top-1.5 max-w-[85%] truncate rounded bg-black/70 px-1.5 py-0.5 text-[10px] text-white">
            {label}
          </span>
        ) : null}
      </div>

      <p
        className={cn(
          "truncate text-[13px] font-medium leading-5 group-hover:text-primary",
          variant === "rail" && "text-xs",
        )}
      >
        {video.name}
      </p>

      {variant === "default" ? (
        <p className="truncate text-xs text-muted-foreground">
          {[video.year, video.area, video.type?.split(",")[0]].filter(Boolean).join(" · ")}
        </p>
      ) : null}
    </Link>
  )
}
