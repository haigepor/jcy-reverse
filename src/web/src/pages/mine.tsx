// 我的（游客态）—— 原服务端 history/users/info 需登录（50008），本地能力优先：
// 弹幕设置（复刻原 App 设置面板字段）+ 清晰度偏好 + 播放记录清空。
// 2026-10 样式重设计：卡片化分组 + 分段选择器 + 行式布局，替代裸列表。

import { useMemo } from "react"
import { Database, MessageSquareText, MonitorPlay, Trash2 } from "lucide-react"

import { Slider } from "@/components/ui/slider"
import { Switch } from "@/components/ui/switch"
import { Button } from "@/components/ui/button"
import { useSettings } from "@/store/settings"
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
    <section className="rounded-xl border bg-card p-4 shadow-sm sm:p-5">
      <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold">
        <Icon className="size-4 text-primary" />
        {title}
      </h2>
      <div className="space-y-4">{children}</div>
    </section>
  )
}

/** 分段选择器：muted 底 + 浮起选中片，替代松散的独立按钮 */
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
              ? "bg-background text-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

/** 设置行：左标签右控件，弹幕开关用 */
function Row({ label, hint, children }: {
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div>
        <p className="text-sm font-medium">{label}</p>
        {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
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
      if (!keys.length || !confirm(`确定清除 ${keys.length} 条本地播放记录？`)) return
      keys.forEach((k) => localStorage.removeItem(k))
      alert(`已清除 ${keys.length} 条本地播放记录`)
      location.reload()
    } catch {
      // ignore
    }
  }

  return (
    <div className="mx-auto max-w-lg space-y-5 pb-8">
      {/* 头像卡 */}
      <div className="flex items-center gap-4 rounded-xl border bg-card p-5 shadow-sm">
        <div className="flex size-14 shrink-0 items-center justify-center rounded-full bg-primary text-xl font-bold text-primary-foreground">
          囧
        </div>
        <div className="min-w-0">
          <p className="font-semibold">游客模式</p>
          <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
            登录态接口（历史/收藏/用户信息）服务端返回 50008，播放进度保存在本机浏览器
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
          默认 4K，片源缺档自动回退 1080P；再缺取最优可用档。
        </p>
      </Card>

      <Card title="本地数据" icon={Database}>
        <Row label="本地播放记录" hint={`${progressCount} 条 · 仅存本机浏览器`}>
          <Button variant="destructive" size="sm" className="gap-1.5" onClick={clearProgress}>
            <Trash2 className="size-3.5" />
            清空
          </Button>
        </Row>
      </Card>
    </div>
  )
}
