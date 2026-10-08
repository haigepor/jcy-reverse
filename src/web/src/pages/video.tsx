// 视频详情 + 播放页（对应原 App /video/:vid 路由，核心页面）。
// 闭环：detail(parts[].play/part[]) → 选线路/集 → /resolve 多清晰度 → /stream 代理播放
//       → ArtPlayer 弹幕/清晰度菜单 + 本地续播 + HEVC 检测提示 + 下一集自动衔接。

import { useEffect, useMemo, useRef, useState } from "react"
import { useParams } from "react-router"
import { useQuery } from "@tanstack/react-query"

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
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { VideoCard } from "@/components/video-card"
import { ChevronDown, ChevronUp, TriangleAlert } from "lucide-react"

export default function VideoPage() {
  const { vid = "" } = useParams()
  const { danmaku, danmakuOn, preferredQuality } = useSettings()
  const [lineIdx, setLineIdx] = useState(0)
  const [part, setPart] = useState<string | null>(null)
  const [showAllEps, setShowAllEps] = useState(false)

  // 换视频时收起展开态，默认单行
  useEffect(() => setShowAllEps(false), [vid])

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

  if (detailQ.isPending) {
    // 与真实布局同构：播放器块同样 max-h-[70vh] 封顶（否则宽屏骨架高 ~840px），
    // 标题+徽章行+三行简介，shimmer 全站统一
    return (
      <div className="space-y-4">
        <Skeleton className="aspect-video max-h-[70vh] w-full rounded-lg" />
        <div className="flex flex-wrap items-center gap-2">
          <Skeleton className="h-7 w-1/3" />
          <Skeleton className="h-6 w-16 rounded-full" />
          <Skeleton className="h-6 w-14 rounded-full" />
          <Skeleton className="h-6 w-14 rounded-full" />
        </div>
        <div className="max-w-3xl space-y-2">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-11/12" />
          <Skeleton className="h-4 w-3/5" />
        </div>
      </div>
    )
  }
  if (detailQ.isError || !detail) {
    return <p className="text-sm text-muted-foreground">详情加载失败：{String(detailQ.error)}</p>
  }

  const episodes = line?.part ?? []

  return (
    <div className="space-y-6 motion-safe:animate-in motion-safe:fade-in motion-safe:duration-500">
      {/* 播放器 */}
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
            className="aspect-video max-h-[70vh]"
          />
        ) : (
          <div className="flex aspect-video max-h-[70vh] w-full items-center justify-center rounded-lg bg-black text-sm text-muted-foreground">
            {resolveQ.isPending
              ? "正在解析播放直链…"
              : resolveQ.isError
                ? `解析失败：${String(resolveQ.error)}`
                : "选择剧集开始播放"}
          </div>
        )}
      </div>

      {hevcWarn ? (
        <Alert>
          <TriangleAlert className="size-4" />
          <AlertTitle>HEVC 硬解提示</AlertTitle>
          <AlertDescription>{hevcWarn}</AlertDescription>
        </Alert>
      ) : null}

      {/* 标题与元信息 */}
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-xl font-semibold">{detail.name ?? `视频 ${vid}`}</h1>
          {detail.score ? <Badge variant="secondary">{detail.score} 分</Badge> : null}
          {detail.isend === 1 ? (
            <Badge>已完结</Badge>
          ) : detail.continu ? (
            <Badge variant="outline">{detail.continu.split("|")[1] ?? detail.continu}</Badge>
          ) : null}
          {detail.year ? <Badge variant="outline">{detail.year}</Badge> : null}
          {detail.area ? <Badge variant="outline">{detail.area}</Badge> : null}
          {detail.type ? <Badge variant="outline">{detail.type}</Badge> : null}
        </div>
        {detail.content ? (
          <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{detail.content}</p>
        ) : null}
        {detail.actor ? (
          <p className="text-sm text-muted-foreground">主演：{detail.actor}</p>
        ) : null}
        {detail.director ? (
          <p className="text-sm text-muted-foreground">导演：{detail.director}</p>
        ) : null}
      </div>

      <Separator />

      {/* 选集 / 评论（对应原 App 详情页 Tab 布局） */}
      {lines.length > 0 || commentItems.length > 0 ? (
        <Tabs defaultValue="episodes">
          <TabsList>
            <TabsTrigger value="episodes">
              选集{episodes.length ? ` ${episodes.length}` : ""}
            </TabsTrigger>
            <TabsTrigger value="comments">
              评论{commentsQ.data?.data?.total ? ` ${commentsQ.data.data.total}` : ""}
            </TabsTrigger>
          </TabsList>
          <TabsContent value="episodes" className="pt-3">
            {lines.length > 1 ? (
              <div className="mb-3">
                <Tabs value={String(lineIdx)} onValueChange={(v) => setLineIdx(Number(v))}>
                  <TabsList>
                    {lines.map((l, i) => (
                      <TabsTrigger key={l.oid ?? i} value={String(i)}>
                        {l.play_zh || l.play || `线路${i + 1}`}
                      </TabsTrigger>
                    ))}
                  </TabsList>
                </Tabs>
              </div>
            ) : null}
            <div className="mb-2 flex justify-end">
              <Button
                variant="ghost"
                size="sm"
                className="gap-1 text-xs text-muted-foreground"
                onClick={() => setShowAllEps((v) => !v)}
              >
                {showAllEps ? (
                  <>
                    <ChevronUp className="size-3.5" /> 收起
                  </>
                ) : (
                  <>
                    <ChevronDown className="size-3.5" />
                    展开全部{episodes.length ? `（${episodes.length} 集）` : ""}
                  </>
                )}
              </Button>
            </div>
            {showAllEps ? (
              <div className="flex flex-wrap gap-2 motion-safe:animate-in motion-safe:fade-in motion-safe:slide-in-from-bottom-1 motion-safe:duration-300">
                {episodes.map((p) => (
                  <Button
                    key={p}
                    size="sm"
                    variant={p === part ? "default" : "outline"}
                    onClick={() => goPart(p)}
                  >
                    {p}
                  </Button>
                ))}
              </div>
            ) : (
              <div className="no-scrollbar flex gap-2 overflow-x-auto pb-1 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
                {episodes.map((p) => (
                  <Button
                    key={p}
                    size="sm"
                    variant={p === part ? "default" : "outline"}
                    className="shrink-0"
                    onClick={() => goPart(p)}
                  >
                    {p}
                  </Button>
                ))}
              </div>
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
                        <span className="ml-2 text-xs text-muted-foreground">
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
              <p className="text-sm text-muted-foreground">暂无评论（或该接口游客态受限）。</p>
            )}
          </TabsContent>
        </Tabs>
      ) : (
        <p className="text-sm text-muted-foreground">该剧集暂无可用线路。</p>
      )}

      {/* 清晰度（当前直链清单） */}
      {urls.length > 1 ? (
        <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
          <span>清晰度（切换请用播放器右下角菜单，无缝续播）：</span>
          {urls.map((q, i) => (
            <Badge key={q.url} variant={i === qualityIdx ? "default" : "outline"}>
              {q.name}
            </Badge>
          ))}
        </div>
      ) : null}

      {/* 同频道推荐 */}
      {sameChannelQ.data?.data?.items?.length ? (
        <div className="space-y-3">
          <h2 className="text-base font-medium">频道推荐</h2>
          <div className="grid grid-cols-3 gap-3 md:grid-cols-6">
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
  )
}
