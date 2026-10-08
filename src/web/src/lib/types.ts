// 囧次元业务类型 —— 字段来源：blutter 反编译模型（GVideo/GVideoDetailItem/GPartInfo/
// GDanmakuItem）与 35 接口实测矩阵的真实响应，详见 docs/api/ 与 live-matrix。
// 未知结构的字段一律 Optional + 防御式渲染。

/** 服务端信封：成功码 20000（部分老端点 200）；错误也是 HTTP 200 + 明文 JSON */
export interface ApiEnvelope<T = unknown> {
  code: number
  message?: string
  data: T
}

/** 列表条目（GVideo，/app/video/list、search、update_list 通用） */
export interface GVideo {
  id: number
  cid: number
  name: string
  ename?: string
  area?: string
  year?: string
  /** "14|周三01:50更" / "1|周三23:15更" / "0|10月14日00:30首播" */
  continu?: string
  total?: number
  isend?: number
  pic?: string
  type?: string
  up?: number
  down?: number
  actor?: string
  director?: string
  score?: string
  content?: string
}

export interface VideoListData {
  total: number
  items: GVideo[]
}

/** 频道（/app/channel?top-level=true） */
export interface GChannel {
  id: number
  name?: string
}

/** 线路（GPartInfo，detail.parts[]） */
export interface GPartInfo {
  oid?: number
  /** 格式键（mp4 等）—— 调 /resolve 时传 */
  play: string
  /** 展示名（"线路3"） */
  play_zh?: string
  /** 集名数组（"第1集"…） */
  part: string[]
  single_clarity_display?: number
}

export interface GVideoDetailData extends Partial<GVideo> {
  id: number
  cid?: number
  name?: string
  comment_total?: number
  hits?: number
  parts?: GPartInfo[]
  /** 续播信息（游客态通常为空） */
  history?: { time_point?: number; part?: string } | null
}

/** 播放地址（/resolve 返回的 urls[]，对应 playAddr 数组） */
export interface PlayQuality {
  /** "1080P 高清" / "4K 超清"（旧结构单 URL 时为格式名） */
  name: string
  vcodec?: string | null
  format?: string | null
  url: string
  /** 该直链所需的请求头（空 UA/Referer 规则），由后端 /stream 注入 */
  headers?: Record<string, string>
}

export interface ResolveResult {
  code: number | null
  message?: string
  source: string | null
  playAddr: Record<string, unknown>[]
  urls: PlayQuality[]
}

/** 弹幕（GDanmakuItem，/app/danmu 响应为明文 JSON） */
export interface DanmakuItem {
  id: number
  uid?: number | string
  /** 毫秒（请求窗口 start/end_time_point 同单位；上限 60000ms/窗，超出报 400204） */
  time_point: number
  /** 可能是内嵌 JSON 字符串：{"color":...,"content":"文本"} */
  content: string
}

export interface DanmuData {
  items?: DanmakuItem[]
}

/** 评论（/app/vod_comment/getlist，结构宽松防御渲染） */
export interface CommentItem {
  id?: number
  uid?: number | string
  nickname?: string
  avatar?: string
  content?: string
  create_time?: string
  likes?: number
  replies?: CommentItem[]
}

export interface CommentListData {
  total?: number
  items?: CommentItem[]
  list?: CommentItem[]
}

/** banner（实测 /app/banners/{pid}：img/vname/vid/continu/content） */
export interface BannerItem {
  id?: number
  pid?: number
  oid?: number
  /** 跳转的视频 id */
  vid?: number
  img?: string
  vname?: string
  /** "3|周五16:15更" / "第1集" */
  continu?: string
  content?: string
}
