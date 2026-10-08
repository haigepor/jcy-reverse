// 骨架屏 —— 全站统一加载占位（2026-10 重设计）：
//   底色保持轻微呼吸（motion-reduce 降级为纯 animate-pulse），
//   高光层从左到右扫过（shimmer，见 index.css @theme），扫过→短暂停顿→再扫，
//   比单纯的透明度闪烁更接近内容"正在加载"的直觉。所有页面共用本组件，
//   改这里即全站生效。
import { cn } from "cn"

function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      className={cn(
        "relative overflow-hidden rounded-md bg-accent",
        "after:absolute after:inset-0 after:-translate-x-full after:bg-gradient-to-r",
        "after:from-transparent after:via-white/55 after:to-transparent",
        "motion-safe:after:animate-shimmer motion-reduce:animate-pulse",
        className,
      )}
      {...props}
    />
  )
}

export { Skeleton }
