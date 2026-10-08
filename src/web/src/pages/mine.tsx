// 我的（游客态）—— 服务端 history/users/info 需登录（50008），本地能力优先：
// 弹幕设置 + 清晰度偏好 + 播放记录清空。
//
// 2026-10 样式重设计：
//   1. **文案用户化**：旧版头像卡里直接写「登录态接口（历史/收藏/用户信息）服务端
//      返回 50008」—— 接口错误码不该给用户看。现在只说「播放进度保存在本机」。
//   2. 补统一 PageHeader（旧版这页没有页头，只有全局搜索栏顶着）。
//   3. 诊断入口从「全局顶栏常驻琥珀胶囊」移到本页底部（见 diag-overlay.tsx 注释），
//      派发 jcy:open-diag 事件拉起。
//   4. 设置项图标统一品牌色，卡片圆角随设计系统。

import { useMemo } from "react"
import {
  Database,
  MessageSquareText,
  MonitorPlay,
  Stethoscope,
  Trash2,
} from "lucide-react"

import { Slider } from "@/components/ui/slider"
import { Switch } from "@/components/ui/switch"
import { Button } from "@/components/ui/button"
import { useSettings } from "@/store/settings"
import { PageHeader } from "@/components/layout/page-header"
import { cn } from "cn"

const AREAS: { value: "full" | "half" | "quarter"; label: string }[] = [
  { value: "full", label: "全屏" },
  { value: "half", label: "半屏" },
  { value: "quarter", label: "1/4" },
]
const QUALITIES = ["4K", "1080P", "720P"]

/** 设置卡片：统一圆角/描边/内边距的分组容器 */
function Card({ title, icon: Icon, children }: {
  title: string
  icon: React.ComponentType<{ className?: string }>
  children: React.ReactNode
}) {
  return (
    <section className="rounded-xl border border-border/70 bg-card p-4">
      <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold">
        <Icon className="size-4 text-primary" />
        {title}
      </h2>
      <div className="space-y-4">{children}</div>
    </section>
  )
}

/** 分段选择器：muted 底 + 浮起选中片（选中态用品牌色） */
function Segmented<T extends string>({ value, options, onChange, className }: {
  value: T
  options: { value: T; label: string }[]
  onChange: (v: T) => void
  className?: string
}) {
  return (
    <div className={cn("grid grid-flow-col auto-cols-fr gap-1 rounded-lg bg-muted p-1", className)}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          className={cn(
            "rounded-md py-1.5 text-sm font-medium transition-all",
            value === o.value
              ? "bg-primary text-primary-foreground shadow-sm"
              : "text-muted-foreground active:text-foreground",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

/** 设置行：左标签右控件 */
function Row({ label, hint, children }: {
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="min-w-0">
        <p className="text-sm font-medium">{label}</p>
        {hint ? <p className="truncate text-xs text-muted-foreground">{hint}</p> : null}
      </div>
      {children}
    </div>
  )
}

export default function MinePage() {
  const { danmaku, danmakuOn, preferredQuality, setDanmaku, setDanmakuOn, setPreferredQuality } =
    useSettings()

  const progressCount = useMemo(() => {
    try {
      return Object.keys(localStorage).filter((k) => k.startsWith("jcy-progress:")).length
    } catch {
      return 0
    }
  }, [])

  const clearProgress = () => {
    try {
      const keys = Object.keys(localStorage).filter((k) => k.startsWith("jcy-progress:"))
      if (!keys.length || !confirm(`确定清除 ${keys.length} 条播放记录？`)) return
      keys.forEach((k) => localStorage.removeItem(k))
      alert(`已清除 ${keys.length} 条播放记录`)
      location.reload()
    } catch {
      // ignore
    }
  }

  return (
    <div className="pb-4">
      <PageHeader title="我的" />

      <div className="space-y-4 px-4 pt-4">
        {/* 用户卡 */}
        <div className="flex items-center gap-3.5 rounded-xl border border-border/70 bg-card p-4">
          <div className="flex size-14 shrink-0 items-center justify-center rounded-full bg-primary text-xl font-bold text-primary-foreground shadow-sm">
            囧
          </div>
          <div className="min-w-0 flex-1">
            <p className="font-semibold">游客模式</p>
            <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
              播放进度和偏好设置保存在本机，换设备不同步
            </p>
          </div>
        </div>

        <Card title="弹幕设置" icon={MessageSquareText}>
          <Row label="弹幕开关">
            <Switch checked={danmakuOn} onCheckedChange={setDanmakuOn} aria-label="弹幕开关" />
          </Row>

          <div className={cn("space-y-2 transition-opacity", !danmakuOn && "pointer-events-none opacity-40")}>
            <div className="flex items-baseline justify-between">
              <p className="text-sm font-medium">不透明度</p>
              <span className="text-xs tabular-nums text-muted-foreground">
                {Math.round(danmaku.opacity * 100)}%
              </span>
            </div>
            <Slider
              min={0.1} max={1} step={0.05}
              value={[danmaku.opacity]}
              onValueChange={([v]) => setDanmaku({ opacity: v })}
            />
          </div>

          <div className={cn("space-y-2 transition-opacity", !danmakuOn && "pointer-events-none opacity-40")}>
            <div className="flex items-baseline justify-between">
              <p className="text-sm font-medium">弹幕速度</p>
              <span className="text-xs tabular-nums text-muted-foreground">{danmaku.speed}</span>
            </div>
            <Slider
              min={1} max={10} step={1}
              value={[danmaku.speed]}
              onValueChange={([v]) => setDanmaku({ speed: v })}
            />
          </div>

          <div className={cn("space-y-2 transition-opacity", !danmakuOn && "pointer-events-none opacity-40")}>
            <p className="text-sm font-medium">显示范围</p>
            <Segmented
              value={danmaku.area}
              options={AREAS}
              onChange={(area) => setDanmaku({ area })}
            />
          </div>
        </Card>

        <Card title="清晰度偏好" icon={MonitorPlay}>
          <Segmented
            value={preferredQuality ?? "4K"}
            options={QUALITIES.map((q) => ({ value: q, label: q }))}
            onChange={setPreferredQuality}
          />
          <p className="text-xs leading-relaxed text-muted-foreground">
            默认优先 4K，片源缺档自动回退 1080P，再缺取最优可用档。
          </p>
        </Card>

        <Card title="本地数据" icon={Database}>
          <Row label="播放记录" hint={progressCount ? `${progressCount} 条 · 仅存本机` : "暂无记录"}>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 text-destructive"
              onClick={clearProgress}
              disabled={!progressCount}
            >
              <Trash2 className="size-3.5" />
              清空
            </Button>
          </Row>
        </Card>

        {/* 诊断入口：调试用，低调放在最底部（旧版是常驻顶栏的琥珀胶囊） */}
        <div className="flex justify-center pt-2">
          <button
            type="button"
            onClick={() => window.dispatchEvent(new Event("jcy:open-diag"))}
            className="flex items-center gap-1.5 rounded-full px-3 py-2 text-xs text-muted-foreground/70 transition-colors active:text-foreground"
          >
            <Stethoscope className="size-3.5" />
            诊断面板
          </button>
        </div>
      </div>
    </div>
  )
}
