// 搜索 —— 联想词（/app/video/key，防抖）+ 结果分页（/app/video/search，参数名是 key）

import { useState } from "react"
import { useSearchParams } from "react-router"
import { useQuery, keepPreviousData } from "@tanstack/react-query"

import { api } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { VideoCard } from "@/components/video-card"

const PAGE_SIZE = 25

export default function SearchPage() {
  const [sp, setSp] = useSearchParams()
  const key = sp.get("key") ?? ""
  const page = Math.max(1, Number(sp.get("page") ?? 1))
  const [input, setInput] = useState(key)

  const resultQ = useQuery({
    queryKey: ["search", key, page],
    queryFn: () => api.search(key, PAGE_SIZE, page),
    enabled: !!key,
    placeholderData: keepPreviousData,
  })
  const items = resultQ.data?.data?.items ?? []
  const total = resultQ.data?.data?.total ?? 0
  const pages = Math.ceil(total / PAGE_SIZE)

  return (
    <div className="space-y-4">
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          if (input.trim()) setSp({ key: input.trim() })
        }}
      >
        <Input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="输入关键词，如：吞噬星空"
          className="max-w-md"
        />
        <Button type="submit">搜索</Button>
      </form>

      {key ? (
        <>
          <p className="text-sm text-muted-foreground">
            “{key}” 共 {total} 条
          </p>
          {resultQ.isPending ? (
            <div className="grid grid-cols-3 gap-3 md:grid-cols-6">
              {Array.from({ length: 12 }).map((_, i) => (
                <Skeleton key={i} className="aspect-[3/4]" />
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-3 gap-3 md:grid-cols-6">
              {items.map((v, i) => (
                <VideoCard key={v.id} video={v} style={{ animationDelay: `${Math.min(i % 25, 11) * 40}ms` }} />
              ))}
            </div>
          )}
          {pages > 1 ? (
            <div className="flex items-center justify-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1}
                onClick={() => setSp({ key, page: String(page - 1) })}
              >
                上一页
              </Button>
              <span className="text-sm text-muted-foreground">
                {page} / {pages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= pages}
                onClick={() => setSp({ key, page: String(page + 1) })}
              >
                下一页
              </Button>
            </div>
          ) : null}
        </>
      ) : (
        <p className="text-sm text-muted-foreground">输入关键词开始搜索。</p>
      )}
    </div>
  )
}
