// API 客户端：全部走本地后端桥（浏览器里由 Vite dev 反代 /api /stream → 127.0.0.1:8792，
// 安卓 App 里由 Kotlin 侧 JcyBridgeServer 在本机同一端口提供**相同路由**）。
// 后端桥负责签名/加密/解密与视频头注入，前端只见明文 JSON 与代理流。

import type {
  ApiEnvelope,
  BannerItem,
  CommentListData,
  DanmuData,
  GChannel,
  GVideo,
  GVideoDetailData,
  ResolveResult,
  VideoListData,
} from "./types"

/**
 * 后端桥基址。
 *  - 浏览器（`pnpm web:dev`）：留空 → 走相对路径 → Vite dev server 反代到 8792
 *  - 安卓 App：构建时注入 `VITE_API_BASE=http://127.0.0.1:8792`
 *    （WebView 里相对路径会指向 `http://localhost`，那里没有桥）
 */
export const API_BASE = ((import.meta.env.VITE_API_BASE as string | undefined) ?? "").replace(/\/+$/, "")

/** 把桥内路径拼成绝对地址。 */
export const apiUrl = (path: string) => `${API_BASE}${path}`

export class ApiError extends Error {
  code: number
  constructor(code: number, message: string) {
    super(message || `业务错误 ${code}`)
    this.code = code
  }
}

export const OK = (env: ApiEnvelope) => env.code === 20000 || env.code === 200

async function unwrap<T>(res: Response): Promise<ApiEnvelope<T>> {
  const j = (await res.json()) as ApiEnvelope<T> & { message?: string }
  if (!j || typeof j !== "object" || !("code" in j)) {
    throw new Error(`非信封响应（HTTP ${res.status}）`)
  }
  return j
}

async function get<T>(path: string): Promise<ApiEnvelope<T>> {
  const res = await fetch(apiUrl(`/api/${path.replace(/^\//, "")}`))
  return unwrap<T>(res)
}

async function post<T>(path: string, params: unknown = {}): Promise<ApiEnvelope<T>> {
  const res = await fetch(apiUrl(`/api/${path.replace(/^\//, "")}`), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params ?? {}),
  })
  return unwrap<T>(res)
}

// ---------------------------------------------------------------- 业务封装
// 注意：GET 参数必须拼进 path（后端透传时服务端只认 query）

export const api = {
  config: () => get<unknown>("config"),
  channels: () => get<GChannel[]>("channel?top-level=true"),
  banners: (channel: number) => get<BannerItem[]>(`banners/${channel}`),
  videoList: (channel: number, sort = "weight", limit = 6, page = 1) =>
    get<VideoListData>(
      `video/list?channel=${channel}&sort=${sort}&limit=${limit}&page=${page}`,
    ),
  videoDetail: (vid: number | string) =>
    get<GVideoDetailData>(`video/detail?id=${vid}`),
  search: (key: string, limit = 25, page = 1) =>
    get<VideoListData>(
      `video/search?key=${encodeURIComponent(key)}&limit=${limit}&page=${page}`,
    ),
  suggest: (key: string, limit = 10) =>
    get<string[] | { items?: { name?: string }[] }>(
      `video/key?key=${encodeURIComponent(key)}&limit=${limit}&page=1`,
    ),
  updateList: (date: string, limit = 50, page = 1) =>
    get<{ items?: GVideo[]; list?: GVideo[] } | GVideo[]>(
      `video_update_list/${date}?limit=${limit}&page=${page}`,
    ),
  comments: (vid: number | string, page = 1, limit = 20) =>
    get<CommentListData>(
      `vod_comment/getlist?vid=${vid}&limit=${limit}&page=${page}`,
    ),
  /** 弹幕为明文 JSON（仍走桥统一域），毫秒增量窗口；必须带 part */
  danmu: (vid: number | string, part: string, play = "mp4", startMs = 0, endMs = 60000) =>
    get<DanmuData>(
      `danmu?vid=${vid}&play=${encodeURIComponent(play)}&part=${encodeURIComponent(part)}&start_time_point=${startMs}&end_time_point=${endMs}`,
    ),
  /** 播放记录上报（游客态可通，20000） */
  record: () => post<unknown>("video/record", {}),
}

/** 播放解析：vid+线路+集 → 多清晰度直链（服务端完成凭证+解析器签名两跳） */
export async function resolvePlay(
  vid: number | string,
  play = "mp4",
  part?: string | null,
): Promise<ResolveResult> {
  const res = await fetch(apiUrl("/resolve"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ vid, play, part }),
  })
  const j = (await res.json()) as ResolveResult
  if (!j || !Array.isArray(j.urls)) {
    throw new Error(j?.message || "播放解析失败")
  }
  if (j.code !== 20000 && j.urls.length === 0) {
    throw new Error(j.message || `解析失败（code=${j.code}）`)
  }
  return j
}

/** 直链 → 本地流代理地址（浏览器禁设空 UA/Referer，由桥注入） */
export const streamUrl = (direct: string) =>
  apiUrl(`/stream?url=${encodeURIComponent(direct)}`)
