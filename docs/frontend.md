# Web 前端架构与播放器设计（src/web）

> 状态：**v1 浏览器版已落地**（6 页面全绿，播放闭环实测）。打包路线（Windows / Android）架构已预留，见文末。

## 一、原 App 架构与播放器分析（逆向结论）

来自 blutter 反编译 + jadx + 抓包实证（样本 `apk/base.apk`，com.tudou.tool 1.5.8.0，Flutter 3.27.x / Dart 3.6.0）：

| 项 | 原 App 实现 | Web 复刻对应 |
|---|---|---|
| 框架 | Flutter + riverpod + go_router（25+ 路由） | React 19 + react-router 7 + TanStack Query 5 |
| **播放器内核** | **阿里 ApsaraVideo Player**（`com.aliyun.player.AliPlayer`，libsaasCorePlayer.so + libalivcffmpeg.so），经自研 MethodChannel `com.guoguo/aliyun_player` 桥接 | **ArtPlayer 5 + hls.js**（内核切换枚举无必要，Web 只需 MP4 渐进 + m3u8 两形态） |
| P2P 加速 | flutter_webrtc + `GWebRTCProxyServer`（本地 127.0.0.1 HTTP 代理喂播放器），**P2P 失败自动回落 CDN 直连** | 直接走"回落路径"（CDN 直链 + 服务端流代理），功能无损 |
| 解析脚本 | 端内 Lua VM（liblua-core.so）执行 play 响应下发的解析脚本 | 服务端 Python 复刻（`jcy_api._parse_resolver`，盐 `pzizhsqjjt`） |
| 视频格式 | **H265 MP4 渐进直链**（HTTP Range 206）；历史 HLS m3u8+AES-128 接口已下线 | `<video>` 原生播放（硬解 HEVC）+ hls.js 兜底 m3u8 |
| 弹幕 | canvas_danmaku 自绘，60s 毫秒增量轮询 | artplayer-plugin-danmuku + 60s 毫秒窗口轮询（`use-danmu.ts`） |

### 为什么必须有本地后端桥（4 个硬约束）

1. **E 加密层**：authentication 头与响应 P0.P1 解密依赖 Unicorn 模拟 libcore.so → 只能服务端跑（复用 `research/deliverables/jcy_api.py`）。
2. **直链请求头**：H265 直链要求空 UA + 伪造 Referer（域名白名单规则），浏览器 JS 禁设 → `/stream` 代理注入。
3. **CORS**：主 API 是明文 HTTP 无 CORS 头 → 前端不能直连，Vite dev 反代 `/api` → 8792。
4. **HEVC 硬解**：Chrome 107+ 需硬件解码、Edge 需装 HEVC 扩展 → `lib/codec.ts` 启动检测，不支持时页面顶部告警。

## 二、技术栈与依据

| 层 | 选型 | 依据 |
|---|---|---|
| 构建 | Vite 7 + TypeScript 5.9 | 冷启动毫秒级；原 App 同为"声明式 UI + 热重载"开发模式 |
| UI | React 19 + **shadcn/ui**（new-york-v4，61 组件全量） | 组件源码入仓可改；Tailwind v4 原生变量主题 |
| 状态 | TanStack Query 5（服务端态）+ zustand 5（播放器设置） | 弹幕 60s 轮询、列表缓存天然适配 |
| 播放器 | **ArtPlayer 5** + artplayer-plugin-danmuku 5 + hls.js 1.5 | 弹幕设置面板（透明度/字号/速度/显示范围/防重叠）可 1:1 复刻原 App；质量菜单无缝续播 |
| 后端桥 | FastAPI + httpx（`src/web/server/`） | 直接 import 现成 `jcy_api.JcyApi`，零重复实现 |
| 打包预留 | Tauri v2 | 一套代码 → 浏览器/Windows exe/Android APK；Win 端 FastAPI 做 sidecar |

> 组件安装备注：shadcn 官方 `new-york-v4` 注册表 index 为空（`--all` 拉不到 63 个），已镜像可用注册项到 `src/web/.registry/` 本地安装。

## 三、目录结构

```
src/web/
├── index.html / vite.config.ts / tsconfig.json / components.json
├── public/favicon.svg
├── server/            FastAPI 桥：/api 透传 + /resolve 播放解析 + /stream 流代理（Range 透传）
└── src/
    ├── main.tsx       入口：QueryClient + BrowserRouter（6 路由）
    ├── lib/           api.ts（信封解包/桥封装）、types.ts（GVideo 模型）、codec.ts（HEVC 检测）、utils.ts
    ├── store/         settings.ts（弹幕设置/清晰度偏好/本地续播进度 jcy-progress:<vid>）
    ├── hooks/         use-danmu.ts（60s 毫秒增量窗口轮询，按 id 去重）
    ├── components/
    │   ├── layout/    app-shell（桌面侧边栏+频道树；移动底部四 tab）、page-header（各页自带页头）
    │   ├── player/    jcy-player.tsx（ArtPlayer 封装：质量菜单/弹幕/续播/实例重建）
    │   └── ui/        61 个 shadcn/ui 组件
    └── pages/         home(频道tabs+banner+行推荐) / channel-more(无限滚动) / search(空态+无限滚动)
                      / time-line(周排期) / video(详情+播放闭环,核心) / mine(弹幕设置面板)
```

## 三·补、样式设计系统（2026-10 重设计）

统一 token 全在 `src/web/src/index.css`，页面只引用语义色，不写死颜色。

| 项 | 值 | 说明 |
|---|---|---|
| 品牌色 | `#FF5C39` ＝ `oklch(0.6866 0.2045 33.8)` | 珊瑚橙红；动漫海报普遍偏冷，橙红是其补色，深底上对比强 |
| 主色前景 | 深字 `oklch(0.17 0.03 33)` | 白字压橙底仅 3.07:1，深字 6.85:1，按钮可读性优先 |
| 默认主题 | **深色**（`index.html` 的 `<html class="dark">`） | 视频/番剧场景主流形态；浅色调色板保留完整能力 |
| 卡片层级 | background `0.145` < card `0.19` < popover `0.215` | 三级明度差 ~0.045，肉眼可辨又不脏 |
| 圆角 | `--radius: 0.75rem`（12px） | 比原 0.625rem 更「内容卡片」 |
| 评分色 | `--rating` 琥珀 | 角标体系：左上=更新状态，右上=评分 |

**结构性改动**（不只是换色）：

1. **取消移动端全局顶栏**。旧版 `AppShell` 的 sticky header 里有「搜索番剧…」输入框 +
   琥珀色「诊断」胶囊，**在所有页面**（含详情页）都显示 —— 于是首页/搜索页各自又加一个
   搜索入口，同屏两个搜索框，且详情页无法沉浸。现在改为各页自带 `PageHeader`。
2. **诊断入口收走**：不再常驻悬浮按钮，只保留「/health 连续 3 次不通自动展开」的兜底，
   手动入口移到「我的」页底部（派发 `window` 事件 `jcy:open-diag`）。
3. **底部 tab 重做**：`flex-1` 均分 + 选中态品牌色 + 顶部指示条 + 图标加粗描边，
   替代旧的 `justify-around` + 单一颜色变化。
4. **卡片角标体系统一**：旧版 rail 用「底部渐变条」、grid 用「左上小标签」两套语言，
   现统一为「左上=更新状态胶囊、右上=评分」，深色半透明 + backdrop-blur；标题改两行截断。
5. **详情页沉浸化**：播放器贴顶全出血 + 浮动半透明返回钮；简介规范化（折叠原始数据的
   全角空格填充，去掉中文标点后空格）；年份/地区/类型拆成独立胶囊；选集改 5 列网格。
6. **ArtPlayer 主题色对齐**：其默认 `--art-theme` 是**纯红 `#f00`**，与品牌色打架
   （症状：未播放时进度条最左端停着一个孤立红点）。已在 `JcyPlayer` 设 `theme: "#FF5C39"`。

## 四、播放闭环（video 页核心流程）

```
/app/video/detail?id=vid
  └─ parts[]: { play, play_zh, part[] }          ← 线路 × 选集
       └─ 用户选线路/集 → POST /resolve {vid,play,part}
            └─ 服务端：/app/video/play 凭证 → 解析器(yh.jx.xajtl.com, x-sign1/2)
                 └─ playAddr[] → urls: [{name:"1080P"/"4K", url, headers}]
                      └─ 前端选清晰度（preferredQuality 优先）→ /stream?url=<直链>
                           └─ ArtPlayer 播放（续播=localStorage, 弹幕=useDanmu）
```

- **清晰度切换**：ArtPlayer 右下角质量菜单（同 resolve 结果内多档），无缝续播。
- **线路/选集切换**：换 `play`/`part` → resolve 重建 → `instanceKey` 变化重建播放器；`onEnded` 自动下一集。
- **弹幕**：`useDanmu` 每 60s 拉一个 180s 毫秒窗口（锚定拉取进度），按 id 去重合并 → `art.danmuku.load()`；必须带 `part` 参数（原 App 同款约束）。
- **续播**：服务端 history 游客态 50008 → 本地 `localStorage["jcy-progress:<vid>"]`；>3s 自动 seek。
- **错误形态**：服务端错误也是 HTTP 200 + `code!=20000`，`lib/api.ts` 统一抛 `ApiError`。

## 五、快速启动

```powershell
# 1) 后端桥（端口 8792；首次先装依赖）
pnpm web:server          # 等价 ./.venv/Scripts/python.exe src/web/server/main.py
pip install -r src/web/server/requirements.txt

# 2) 前端 dev（端口 5173，/api /stream 自动反代 8792）
pnpm web:dev

# 3) 生产构建 / 预览
pnpm web:build && pnpm web:preview
```

## 六、已知边界与后续路线

- **弹幕接口实测约束（2026-10-07）**：请求窗口 `start/end_time_point` 为**毫秒**且**单窗上限 60000ms**（超出报 `400204 弹幕片段超过最大值`）；响应 `items[].time_point` 为**毫秒**（前端 ÷1000）；`content` 字段是**内嵌 JSON**（`{"color":4294967295,"content":"文本"}`），需二次解析。`use-danmu` 已按 ≤60s 分块 + 锚定播放进度 + seek 补拉实现。
- **桥接层线程安全（2026-10-07）**：Unicorn×libcore.so 的 E 加密层**非线程安全**（并发触发原生崩溃 BADPC/unmapped），`server/main.py` 用单线程执行器串行全部 JCY 调用（单次 0.2~2s，突发请求排队）。另有**偶发原生崩溃**（输入相关分支），`pnpm web:server` 的监督进程异常退出 3s 后自动拉起（auth 盘缓存热重启）。
- **HEVC 硬解不可用**的机器只给告警不转码（后续可加服务端 ffmpeg 转 H264 档）。
- **登录态接口**（history/users/info/收藏）50008 → 一律游客态降级，`mine` 页提供本地记录清空。
- **bundle 1.27MB（gzip 395KB）**：全量 shadcn 引入所致，后续按路由 `React.lazy` 分包。
- **打包路线**：Windows = Tauri v2 + WebView2 + FastAPI sidecar；Android = Tauri v2 APK，终态 JNI 直调 libcore.so 跑 E（与原 App 同路径）。
- **未实现**（有意）：P2P（原 App 自带 CDN 回落）、广告、DLNA 投屏、多播放器内核切换、play-connect 心跳（参数未还原，不阻塞播放）。
