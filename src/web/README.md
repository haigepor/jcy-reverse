# src/web — jcy-web 前端工作区

囧次元协议能力的 **Web 前端**：浏览器先行，预留 Tauri v2 桌面打包。
技术栈：Vite 7 + React 19 + TypeScript 5.9 + Tailwind CSS 4 + shadcn/ui + ArtPlayer（含弹幕插件）+ hls.js。

## 定位

```
src/web（本目录）          浏览器端 UI：频道/列表/详情/播放
   │  HTTP（/api、/stream，开发期由 vite 反代）
   ▼
server/main.py             后端桥（FastAPI :8792）：/api 透传 + /resolve 播放解析
   │                        + /stream 视频流代理（UA/Referer 注入、Range 转发）
   ▼
research/deliverables/jcy_api.py + src/jcy_protocol   协议能力
```

- 前端**不直接实现协议**；加解密与签名全部走后端桥，保持 `src/` 单向依赖原则。
- `vite.config.ts` 已预留 `/api`、`/stream` → `127.0.0.1:8792` 反代。

## 目录

| 路径 | 内容 |
|---|---|
| `.registry/` | shadcn/ui 组件注册表（工具元数据，不入 README 目录树） |
| `components.json` | shadcn/ui 配置 |
| `index.html` | Vite 入口 |
| `vite.config.ts` | 端口 5173 + 后端桥反代 |
| `server/` | **后端桥**（FastAPI，跑在仓库根 `.venv`）：`main.py` + `requirements.txt` |
| `src/components/ui/` | shadcn/ui 生成组件（61 个） |
| `src/hooks/` | 通用 hooks（`use-mobile.ts`） |
| `src/store/` | zustand 全局状态 |
| `src/lib/` | 工具函数（`utils.ts`） |

## 状态

**脚手架 + 后端桥阶段**：组件库、工程配置与后端桥（`/api` `/resolve` `/stream` `/health`）
就绪；`src/main.tsx` 应用入口与页面路由尚未落码。落码约定见
[`docs/structure-review.md`](../../docs/structure-review.md)。

## 命令

```bash
pnpm web:dev      # 开发服务器（根目录执行，转发到 jcy-web）
pnpm web:build    # tsc --noEmit + vite build
pnpm web:preview  # 预览构建产物

# 后端桥（跑在根 .venv，先装依赖）
./.venv/Scripts/pip install -r src/web/server/requirements.txt
./.venv/Scripts/python.exe src/web/server/main.py     # 127.0.0.1:8792
```
