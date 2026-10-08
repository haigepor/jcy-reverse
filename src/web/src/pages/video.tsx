// 视频详情 + 播放页（对应原 App /video/:vid 路由，核心页面）。
// 闭环：detail(parts[].play/part[]) → 选线路/集 → /resolve 多清晰度 → /stream 代理播放
//       → ArtPlayer 弹幕/清晰度菜单 + 本地续播 + HEVC 检测提示 + 下一集自动衔接。
//
// 2026-10 样式重设计：
//   1. **沉浸式**：旧版这页顶着全局「搜索番剧…」栏，播放器被压到第二屏。现在播放器
//      贴顶全出血，返回按钮改成浮在播放器上的半透明圆钮（首次进入也不会迷路）。
//   2. **简介规范化**：原始 content 用全角空格做缩进填充，直接渲染会出现
//      「。　　戴基尔」「之一。    他们」这种断裂。这里折叠连续空白 + 去掉中文标点后空格。
//   3. **元信息 chip 化**：年份/地区/类型从「一句话 Badge 行」拆成独立胶囊，
//      类型按逗号拆成多个（原来是 `奇幻,冒险,异世界,恋爱,漫画改` 一整块）。
//   4. **选集网格化**：旧版是横向滑动单行 + 「展开全部（N 集）」，与上方「选集 N」tab
//      重复表达。现在默认 5 列网格铺 10 个 + 展开全部，标题栏不再重复计数。
//   5. 清晰度提示文案精简（旧版那行小字太长）。

import { useEffect, useMemo, useRef, useState } from "react"
import { useNavigate, useParams } from "react-router"
import { useQuery } from "@tanstack/react-query"
import { ChevronDown, ChevronLeft, ChevronUp, TriangleAlert } from "lucide-react"

import { api, resolvePlay, streamUrl } from "@/lib/api"
import type { PlayQuality } from "@/lib/types"
import { codecWarning } from "@/lib/codec"
import {
  loadLastPart,
  loadProgress,
  saveLastPart,
  saveProgress,
  useSettings,
} from "@/store/settings"
import { useDanmu } from "@/hooks/use-danmu"
import { JcyPlayer } from "@/components/player/jcy-player"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { VideoCard } from "@/components/video-card"
import { cn } from "@/lib/utils"

/** 折叠原始简介里的填充空白：全角空格、连续空格、以及中文标点后的空格 */
function tidyText(s?: string | null): string {
  if (!s) return ""
  return s
    .replace(/[\u3000\s]+/g, " ")
    .replace(/([。！？；：、，]) /g, "$1")
    .trim()
}

/** 逗号分隔字段 → 去重数组（类型 / 演员共用） */
function splitList(s?: string | null): string[] {
  if (!s) return []
  return s
    .split(/[,，、/]/)
    .map((x) => x.trim())
    .filter((x) => x && x !== "0")
}

export default function VideoPage() {
  const { vid = "" } = useParams()
  const nav = useNavigate()
  const { danmaku, danmakuOn, preferredQuality } = useSettings()
  const [lineIdx, setLineIdx] = useState(0)
  const [part, setPart] = useState<string | null>(null)
  const [showAllEps, setShowAllEps] = useState(false)
  const [descOpen, setDescOpen] = useState(false)

  // 换视频时收起展开态，默认单行
  useEffect(() => {
    setShowAllEps(false)
    setDescOpen(false)
    setLineIdx(0)
  }, [vid])

  const detailQ = useQuery({
    queryKey: ["detail", vid],
    queryFn: () => api.videoDetail(vid),
    enabled: !!vid,
  })
  const detail = detailQ.data?.data
  const lines = detail?.parts ?? []
  const line = lines[lineIdx]

  // 详情到达后定位默认线路/集：优先记忆的上次看到的一集（游客态选集续看），
  // 无记忆或该集不在本线路时落回第 1 集
  useEffect(() => {
    if (!lines.length) return
    const li = Math.min(lineIdx, lines.length - 1)
    const parts = lines[li]?.part ?? []
    if (part && parts.includes(part)) return
    const saved = vid ? loadLastPart(vid) : null
    setPart(saved && parts.includes(saved) ? saved : (parts[0] ?? null))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detailQ.data])

  // 换集即记忆（不等 timeupdate 节流），下次进页面自动定位
  useEffect(() => {
    if (vid && part) saveLastPart(vid, part)
  }, [vid, part])

  const resolveQ = useQuery({
    queryKey: ["resolve", vid, line?.play, part],
    queryFn: () => resolvePlay(vid, line?.play ?? "mp4", part),
    enabled: !!vid && !!part,
    // 不覆盖 retry：继承 main.tsx 的退避策略，覆盖 App 冷启动期桥未就绪的情况
    staleTime: 5 * 60_000,
  })
  const urls: PlayQuality[] = resolveQ.data?.urls ?? []

  // 清晰度匹配链：未设偏好 = 默认 4K，缺档回退 1080P，再缺取列表首位（通常最高清）
  const qualityIdx = useMemo(() => {
    if (!urls.length) return 0
    const chain = [preferredQuality ?? "4K", "1080P"]
    for (const p of chain) {
      const i = urls.findIndex((q) => q.name.startsWith(p))
      if (i >= 0) return i
    }
    return 0
  }, [urls, preferredQuality])

  const proxied = useMemo(
    () => urls.map((q) => ({ ...q, url: streamUrl(q.url) })),
    [urls],
  )
  const playUrl = proxied[qualityIdx]?.url ?? ""

  // 弹幕（60s 毫秒窗口轮询，锚定播放进度，seek 后自动补拉）
  const danmus = useDanmu({
    vid: vid || null,
    play: line?.play ?? null,
    part,
    enabled: !!part && danmakuOn,
    getCurrentTime: () => playTimeRef.current,
  })

  const startTime = useMemo(
    () => (vid && part ? loadProgress(vid, part) : 0),
    [vid, part, resolveQ.data], // 拿到直链后再读进度，避免换集残留
  )
  const lastSaved = useRef(0)
  const playTimeRef = useRef(0)
  const onTimeUpdate = (t: number) => {
    playTimeRef.current = t
    if (t - lastSaved.current >= 5 || (t > 0 && lastSaved.current === 0)) {
      lastSaved.current = t
      if (vid) saveProgress(vid, part, t)
    }
  }
  // 换集重置节拍器
  useEffect(() => {
    lastSaved.current = 0
  }, [part, lineIdx])

  const goPart = (p: string) => {
    if (line?.part.includes(p)) setPart(p)
  }
  const onEnded = () => {
    const list = line?.part ?? []
    const i = part ? list.indexOf(part) : -1
    if (i >= 0 && i < list.length - 1) setPart(list[i + 1])
  }

  const hevcWarn = useMemo(() => codecWarning(), [])
  const sameChannelQ = useQuery({
    queryKey: ["more", detail?.cid],
    queryFn: () => api.videoList(Number(detail!.cid), "weight", 6, 1),
    enabled: !!detail?.cid,
  })
  const commentsQ = useQuery({
    queryKey: ["comments", vid],
    queryFn: () => api.comments(vid, 1, 20),
    enabled: !!vid,
  })
  const commentItems =
    commentsQ.data?.data?.items ?? commentsQ.data?.data?.list ?? []

  const goBack = () => (history.length > 1 ? nav(-1) : nav("/"))

  if (detailQ.isPending) {
    // 与真实布局同构：沉浸播放器 + 标题 + 三行简介
    return (
      <div>
        <Skeleton className="aspect-video max-h-[70vh] w-full rounded-none md:rounded-xl" />
        <div className="space-y-3 px-4 pt-4 md:px-0">
          <Skeleton className="h-7 w-2/3" />
          <div className="flex gap-2">
            <Skeleton className="h-6 w-16 rounded-full" />
            <Skeleton className="h-6 w-14 rounded-full" />
            <Skeleton className="h-6 w-14 rounded-full" />
          </div>
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-11/12" />
          <Skeleton className="h-4 w-3/5" />
        </div>
      </div>
    )
  }
  if (detailQ.isError || !detail) {
    return (
      <div className="px-4 pt-16 text-center">
        <p className="text-sm text-muted-foreground">详情加载失败</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={goBack}>
          返回
        </Button>
      </div>
    )
  }

  const episodes = line?.part ?? []
  const types = splitList(detail.type)
  const actors = splitList(detail.actor)
  const desc = tidyText(detail.content)

  return (
    <div className="pb-6 motion-safe:animate-in motion-safe:fade-in motion-safe:duration-500">
      {/* 沉浸浮动返回钮：压在播放器左上角，滚动到任何位置都在 */}
      <div className="safe-top pointer-events-none fixed inset-x-0 top-0 z-40 flex items-start px-2 pt-1.5">
        <button
          type="button"
          onClick={goBack}
          aria-label="返回"
          className="pointer-events-auto flex size-9 items-center justify-center rounded-full bg-black/45 text-white shadow-lg backdrop-blur-md transition-transform active:scale-95"
        >
          <ChevronLeft className="size-6" />
        </button>
      </div>

      <div className="md:px-6 md:pt-6">
        {/* 播放器：移动端贴顶全出血（沉浸），桌面端收进圆角卡片 */}
        <div className="relative">
          {playUrl ? (
            <JcyPlayer
              url={playUrl}
              qualities={proxied}
              poster={detail.pic}
              startTime={startTime}
              danmus={danmus}
              danmaku={danmaku}
              danmakuOn={danmakuOn}
              instanceKey={`${line?.play}:${part}:${qualityIdx}`}
              onNeedRefresh={() => void resolveQ.refetch()}
              onTimeUpdate={onTimeUpdate}
              onEnded={onEnded}
              className="aspect-video max-h-[70vh] rounded-none md:rounded-xl"
            />
          ) : (
            <div className="flex aspect-video max-h-[70vh] w-full items-center justify-center rounded-none bg-black text-sm text-muted-foreground md:rounded-xl">
              {resolveQ.isPending
                ? "正在解析播放直链…"
                : resolveQ.isError
                  ? `解析失败：${String(resolveQ.error)}`
                  : "选择剧集开始播放"}
            </div>
          )}
        </div>

        <div className="space-y-5 px-4 pt-4 md:px-0">
          {hevcWarn ? (
            <Alert>
              <TriangleAlert className="size-4" />
              <AlertTitle>HEVC 硬解提示</AlertTitle>
              <AlertDescription>{hevcWarn}</AlertDescription>
            </Alert>
          ) : null}

          {/* 标题与元信息 */}
          <div className="space-y-2.5">
            <h1 className="text-xl font-semibold leading-tight tracking-tight">
              {detail.name ?? `视频 ${vid}`}
            </h1>

            <div className="flex flex-wrap items-center gap-1.5">
              {detail.score ? (
                <span className="rounded-full bg-rating/15 px-2.5 py-1 text-xs font-semibold text-rating">
                  {detail.score} 分
                </span>
              ) : null}
              {detail.isend === 1 ? (
                <span className="rounded-full bg-primary/15 px-2.5 py-1 text-xs font-medium text-primary">
                  已完结
                </span>
              ) : detail.continu ? (
                <span className="rounded-full bg-primary/15 px-2.5 py-1 text-xs font-medium text-primary">
                  {detail.continu.split("|")[1] ?? detail.continu}
                </span>
              ) : null}
              {[detail.year, detail.area].filter(Boolean).map((v) => (
                <span
                  key={String(v)}
                  className="rounded-full bg-muted px-2.5 py-1 text-xs text-muted-foreground"
                >
                  {v}
                </span>
              ))}
              {types.map((t) => (
                <span
                  key={t}
                  className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground"
                >
                  {t}
                </span>
              ))}
            </div>

            {desc ? (
              <div className="max-w-3xl">
                <p
                  className={cn(
                    "text-sm leading-relaxed text-muted-foreground",
                    !descOpen && "line-clamp-3",
                  )}
                >
                  {desc}
                </p>
                {desc.length > 90 ? (
                  <button
                    type="button"
                    onClick={() => setDescOpen((v) => !v)}
                    className="mt-1 flex items-center gap-0.5 text-xs text-primary"
                  >
                    {descOpen ? (
                      <>
                        收起 <ChevronUp className="size-3.5" />
                      </>
                    ) : (
                      <>
                        展开 <ChevronDown className="size-3.5" />
                      </>
                    )}
                  </button>
                ) : null}
              </div>
            ) : null}

            {actors.length ? (
              <p className="text-xs leading-relaxed text-muted-foreground">
                <span className="text-foreground/70">主演</span>　{actors.join(" / ")}
              </p>
            ) : null}
            {detail.director && detail.director !== "0" ? (
              <p className="text-xs leading-relaxed text-muted-foreground">
                <span className="text-foreground/70">导演</span>　{detail.director}
              </p>
            ) : null}
          </div>

          {/* 选集 / 评论 */}
          {lines.length > 0 || commentItems.length > 0 ? (
            <Tabs defaultValue="episodes">
              <TabsList className="w-full justify-start rounded-full bg-muted p-1">
                <TabsTrigger
                  value="episodes"
                  className="rounded-full px-4 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
                >
                  选集
                </TabsTrigger>
                <TabsTrigger
                  value="comments"
                  className="rounded-full px-4 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
                >
                  评论{commentsQ.data?.data?.total ? ` ${commentsQ.data.data.total}` : ""}
                </TabsTrigger>
              </TabsList>

              <TabsContent value="episodes" className="pt-3">
                {/* 多线路切换 */}
                {lines.length > 1 ? (
                  <div className="no-scrollbar mb-3 flex gap-2 overflow-x-auto">
                    {lines.map((l, i) => (
                      <button
                        key={l.oid ?? i}
                        type="button"
                        onClick={() => setLineIdx(i)}
                        className={cn(
                          "shrink-0 rounded-full px-3.5 py-1.5 text-xs font-medium transition-colors",
                          i === lineIdx
                            ? "bg-primary text-primary-foreground"
                            : "bg-muted text-muted-foreground active:text-foreground",
                        )}
                      >
                        {l.play_zh || l.play || `线路${i + 1}`}
                      </button>
                    ))}
                  </div>
                ) : null}

                {episodes.length ? (
                  <>
                    <div className="grid grid-cols-5 gap-2 md:grid-cols-10">
                      {(showAllEps ? episodes : episodes.slice(0, 10)).map((p) => (
                        <button
                          key={p}
                          type="button"
                          onClick={() => goPart(p)}
                          className={cn(
                            "truncate rounded-lg py-2 text-[13px] font-medium transition-colors",
                            p === part
                              ? "bg-primary text-primary-foreground"
                              : "bg-muted text-foreground/85 active:bg-accent",
                          )}
                        >
                          {p.replace(/^第|集$/g, "") || p}
                        </button>
                      ))}
                    </div>
                    {episodes.length > 10 ? (
                      <button
                        type="button"
                        onClick={() => setShowAllEps((v) => !v)}
                        className="mt-3 flex w-full items-center justify-center gap-1 rounded-lg py-2 text-xs text-muted-foreground transition-colors active:bg-muted"
                      >
                        {showAllEps ? (
                          <>
                            <ChevronUp className="size-3.5" /> 收起
                          </>
                        ) : (
                          <>
                            <ChevronDown className="size-3.5" /> 展开全部 {episodes.length} 集
                          </>
                        )}
                      </button>
                    ) : null}
                  </>
                ) : (
                  <p className="py-6 text-center text-sm text-muted-foreground">
                    该线路暂无剧集
                  </p>
                )}
              </TabsContent>

              <TabsContent value="comments" className="pt-3">
                {commentsQ.isPending ? (
                  <div className="max-w-3xl space-y-4">
                    {Array.from({ length: 3 }).map((_, i) => (
                      <div key={i} className="flex gap-3">
                        <Skeleton className="size-8 shrink-0 rounded-full" />
                        <div className="flex-1 space-y-1.5">
                          <Skeleton className="h-3.5 w-24" />
                          <Skeleton className="h-3.5 w-full" />
                          <Skeleton className="h-3.5 w-2/3" />
                        </div>
                      </div>
                    ))}
                  </div>
                ) : commentItems.length ? (
                  <ul className="max-w-3xl space-y-4">
                    {commentItems.map((c, i) => (
                      <li key={c.id ?? i} className="flex gap-3">
                        <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-muted text-xs">
                          {(c.nickname ?? "匿").slice(0, 1)}
                        </div>
                        <div className="min-w-0 space-y-0.5">
                          <p className="text-sm font-medium">
                            {c.nickname ?? "匿名用户"}
                            <span className="ml-2 text-xs font-normal text-muted-foreground">
                              {c.create_time ?? ""}
                            </span>
                          </p>
                          <p className="break-words text-sm text-muted-foreground">{c.content}</p>
                          {typeof c.likes === "number" && c.likes > 0 ? (
                            <p className="text-xs text-muted-foreground">👍 {c.likes}</p>
                          ) : null}
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="py-6 text-center text-sm text-muted-foreground">暂无评论</p>
                )}
              </TabsContent>
            </Tabs>
          ) : (
            <p className="text-sm text-muted-foreground">该剧集暂无可用线路。</p>
          )}

          {/* 清晰度：只做状态展示，切换在播放器右下角菜单（无缝续播） */}
          {urls.length > 1 ? (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-muted-foreground">清晰度</span>
              {urls.map((q, i) => (
                <span
                  key={q.url}
                  className={cn(
                    "rounded-full px-2.5 py-1 text-xs",
                    i === qualityIdx
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted text-muted-foreground",
                  )}
                >
                  {q.name}
                </span>
              ))}
            </div>
          ) : null}

          {/* 同频道推荐 */}
          {sameChannelQ.data?.data?.items?.length ? (
            <div className="space-y-3 pt-1">
              <h2 className="flex items-center gap-2 text-[15px] font-semibold tracking-tight">
                <span className="h-4 w-[3px] rounded-full bg-primary" />
                相似推荐
              </h2>
              <div className="grid grid-cols-3 gap-x-2.5 gap-y-4 md:grid-cols-6">
                {sameChannelQ.data.data.items
                  .filter((v) => String(v.id) !== vid)
                  .slice(0, 6)
                  .map((v) => (
                    <VideoCard key={v.id} video={v} />
                  ))}
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}
