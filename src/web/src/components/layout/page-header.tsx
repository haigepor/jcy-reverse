// 页头 —— 移动端的「各页自带顶栏」。
//
// 背景：旧版把「搜索番剧…」输入框 + 诊断按钮放在 AppShell 的全局 sticky header 里，
// 于是在**所有**页面（含视频详情页）都顶着同一个搜索框，而首页/搜索页各自又有一个
// 搜索入口 —— 同屏两个搜索框，且详情页无法沉浸。
//
// 现在全局顶栏取消，改由各页按需渲染自己的页头：
//   - 首页：品牌标 + 搜索胶囊 + 频道 tabs
//   - 搜索页：搜索框
//   - 排期/更多/我的：纯标题（可带右侧操作）
//   - 详情页：不用本组件（用覆盖在播放器上的沉浸头）
//
// 统一在这里收敛 safe-top（状态栏）与毛玻璃背景，避免各页重复。

import type { ReactNode } from "react"
import { useNavigate } from "react-router"
import { ChevronLeft } from "lucide-react"

import { cn } from "@/lib/utils"

export function PageHeader({
  title,
  subtitle,
  back = false,
  right,
  children,
  className,
  /** 透明头（压在内容/图上时用，如详情页沉浸头） */
  transparent = false,
}: {
  title?: ReactNode
  subtitle?: ReactNode
  /** 显示返回按钮（列表页/详情页） */
  back?: boolean
  right?: ReactNode
  /** 页头下方的附加内容（如频道 tabs），会跟着一起 sticky */
  children?: ReactNode
  className?: string
  transparent?: boolean
}) {
  const nav = useNavigate()

  return (
    <header
      className={cn(
        "safe-top sticky top-0 z-30",
        !transparent && "border-b border-border/70 bg-background/85 backdrop-blur-xl",
        className,
      )}
    >
      <div className="flex h-app-topbar items-center gap-2 px-3">
        {back ? (
          <button
            type="button"
            onClick={() => (history.length > 1 ? nav(-1) : nav("/"))}
            aria-label="返回"
            className="-ml-1.5 flex size-9 shrink-0 items-center justify-center rounded-full text-foreground transition-colors active:bg-muted"
          >
            <ChevronLeft className="size-6" />
          </button>
        ) : null}

        {title !== undefined ? (
          <div className="min-w-0 flex-1">
            <h1 className="truncate text-[17px] font-semibold leading-tight tracking-tight">
              {title}
            </h1>
            {subtitle ? (
              <p className="truncate text-xs text-muted-foreground">{subtitle}</p>
            ) : null}
          </div>
        ) : (
          <div className="min-w-0 flex-1">{null}</div>
        )}

        {right ? <div className="flex shrink-0 items-center gap-1.5">{right}</div> : null}
      </div>
      {children}
    </header>
  )
}
