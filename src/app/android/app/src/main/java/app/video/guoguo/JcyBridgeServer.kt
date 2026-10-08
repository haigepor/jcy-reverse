package app.video.guoguo

import android.util.Log
import fi.iki.elonen.NanoHTTPD
import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream

/**
 * JcyBridgeServer —— 跑在设备本机 127.0.0.1 上的 HTTP 桥。
 *
 * ## 为什么要这一层
 * WebView 里的 React 前端只会 `fetch("/api/xxx")`。在浏览器里这由 Vite 反代到
 * FastAPI 桥（`src/web/server/main.py`）解决；在安卓上没有 Python，于是这里用
 * NanoHTTPD 实现**完全相同的路由契约**，前端只需把 base URL 指向本机端口，
 * 业务代码一行不改。
 *
 * | 路由 | 等价 Python 桥 | 说明 |
 * |---|---|---|
 * | `GET\|POST /api/<真实路径>` | `api_proxy` | 透传到主 API，返回明文信封 JSON |
 * | `POST /resolve` | `resolve` | 播放凭证 + 外链解析器 → urls[] |
 * | `GET\|HEAD /stream?url=` | `stream` | 直链 Range 代理 + UA/Referer 注入 |
 * | `GET /health` | `health` | 存活探针 |
 * | `GET /debug` | `debug` | native 自检（真机排障用） |
 *
 * 与 Python 版的差异：加/解密由 `libcore.so` 直接完成（`JcyApi`），
 * 不再有 Unicorn 标定、c_engine 全局锁、authgen 子进程这些东西。
 */
class JcyBridgeServer(port: Int = PORT) : NanoHTTPD("127.0.0.1", port) {

    companion object {
        const val PORT = 8792
        private const val TAG = "JcyBridge"
        private val JSON_CT = "application/json; charset=utf-8"

        /** native 会话是否已建立（MainActivity 在 init 之后置 true）。/health 会报出去。 */
        @Volatile var coreReady: Boolean = false

        /** init 的原始返回（诊断用）。 */
        @Volatile var initRaw: String = ""

        /** 启动阶段的致命错误（诊断用）。 */
        @Volatile var bootError: String = ""

        /** /debug 内每个 action 的等待上限：必须短，否则请求线程被钉死。 */
        private const val DEBUG_TIMEOUT_MS = 3_000

        /** /probe 内每个 action 的等待上限。 */
        private const val PROBE_TIMEOUT_MS = 4_000

        /** /probe 结果缓存时长。 */
        private const val PROBE_TTL_MS = 30_000L

        /** 探测动作表：先无网络的，后有网络的，便于一眼看出断点。 */
        private val PROBE_ACTIONS: List<Pair<String, JSONObject?>> = listOf(
            "check" to null,
            "get_version" to null,
            "get_abi" to null,
            "get_app_info" to null,
            "get_host_config" to null,
            "get_registries" to null,
            "api_encrypt" to JSONObject().put("data", "{}"),
            "__no_such_action__" to null,
        )

        private val probeRunning = java.util.concurrent.atomic.AtomicBoolean(false)

        @Volatile private var probeCache: String = ""
        @Volatile private var probeCacheAt: Long = 0L

        /** GET 响应短 TTL 缓存（吸收 TanStack Query 重复请求 / 翻页重叠 / StrictMode 双挂）。 */
        private const val TTL_DEFAULT = 30_000L
        private const val TTL_LONG = 300_000L
        private const val TTL_RESOLVE = 60_000L
        private val LONG_TTL_MARKERS = listOf("config", "channel", "banners", "sign_rule", "vip_price")
        private const val CACHE_CAP = 300

        private class Entry(val at: Long, val body: String)

        private val cache = object : LinkedHashMap<String, Entry>(64, 0.75f, true) {
            override fun removeEldestEntry(eldest: Map.Entry<String, Entry>?) = size > CACHE_CAP
        }

        private fun ttlFor(key: String): Long = when {
            key.startsWith("R:") -> TTL_RESOLVE
            LONG_TTL_MARKERS.any { key.contains(it) } -> TTL_LONG
            else -> TTL_DEFAULT
        }

        private fun cacheGet(key: String): String? = synchronized(cache) {
            val e = cache[key] ?: return null
            if (System.currentTimeMillis() - e.at < ttlFor(key)) e.body
            else {
                cache.remove(key)
                null
            }
        }

        private fun cachePut(key: String, body: String) {
            synchronized(cache) { cache[key] = Entry(System.currentTimeMillis(), body) }
        }
    }

    override fun serve(session: IHTTPSession): Response {
        val uri = session.uri ?: "/"
        val method = session.method
        Log.i(TAG, "$method $uri")
        // 只记「有意义的」请求，/health 轮询太密会刷爆环形缓冲
        if (uri != "/health" && uri != "/diag") Diag.line("JcyBridge", "$method $uri")

        // 预检：WebView 从 http://localhost 打 http://127.0.0.1 属跨源，必须先答 OPTIONS
        if (method == Method.OPTIONS) return cors(newFixedLengthResponse(Response.Status.NO_CONTENT, JSON_CT, ""))

        return cors(
            try {
                when {
                    uri == "/health" -> json(200, healthInfo())
                    uri == "/debug" -> json(200, debugInfo())
                    // 逐 action 探测 libcore（短超时，永不阻塞线程池）
                    uri == "/probe" -> json(200, probe())
                    // 纯文本全量诊断：WebView 与外部都能直接读，不受 JSON 嵌套限制
                    uri == "/diag" -> text(200, Diag.dump())
                    uri == "/resolve" -> handleResolve(session)
                    uri == "/stream" -> handleStream(session)
                    uri.startsWith("/api/") -> handleApi(session, uri)
                    else -> json(404, JSONObject().put("code", 404).put("message", "未知路由 $uri"))
                }
            } catch (t: Throwable) {
                Log.e(TAG, "serve 异常", t)
                Diag.err("JcyBridge", "serve($uri) 异常", t)
                json(500, JSONObject().put("code", -2).put("message", "${t.javaClass.simpleName}: ${t.message}"))
            },
        )
    }

    // ---------------------------------------------------------------- 路由

    private fun handleApi(session: IHTTPSession, uri: String): Response {
        val rel = uri.removePrefix("/api/")
        var real = "/app/$rel"
        val q = session.queryParameterString
        if (!q.isNullOrEmpty()) real += "?$q"

        val isGet = session.method == Method.GET
        val cacheKey = "G:$real"
        if (isGet) cacheGet(cacheKey)?.let { return raw(it) }

        val params: JSONObject? = if (isGet) null else readJsonBody(session)
        val res = JcyApi.request(if (isGet) "GET" else "POST", real, params)
        val body = res.toString()
        if (isGet && res.opt("code") in listOf(200, 20000)) cachePut(cacheKey, body)
        return raw(body)
    }

    private fun handleResolve(session: IHTTPSession): Response {
        val body = readJsonBody(session) ?: JSONObject()
        val vid = body.optString("vid", "").trim()
        if (vid.isEmpty()) return json(400, JSONObject().put("code", 40000).put("message", "缺少 vid"))
        val playFmt = body.optString("play", "mp4")
        val part = body.optString("part", "").ifEmpty { null }

        val ck = "R:$vid|$playFmt|${part ?: ""}"
        cacheGet(ck)?.let { hit ->
            // 缓存命中也要续直链域名白名单 TTL —— 否则解析缓存（60s）虽活着，
            // 但白名单条目可能先过期，/stream 会以 403 把播放器挡掉。
            runCatching { JcyApi.registerDynamicHosts(JSONObject(hit)) }
            return raw(hit)
        }

        val r = JcyApi.play(vid, playFmt, part)
        // 与 Python 桥一致：剥掉 lua/play 原文（体积大且前端不用），保留 message
        r.remove("lua")
        (r.opt("play") as? JSONObject)?.optString("message")?.let { r.put("message", it) }
        r.remove("play")
        JcyApi.registerDynamicHosts(r)
        val body2 = r.toString()
        // 对齐 Python：urls 或 playAddr 任一非空即缓存
        val hasUrls = (r.optJSONArray("urls")?.length() ?: 0) > 0
        val hasPlayAddr = (r.optJSONArray("playAddr")?.length() ?: 0) > 0
        if (hasUrls || hasPlayAddr) cachePut(ck, body2)
        return raw(body2)
    }

    private fun handleStream(session: IHTTPSession): Response {
        val url = session.parameters["url"]?.firstOrNull().orEmpty()
        if (url.isEmpty()) return json(400, JSONObject().put("code", 40000).put("message", "缺少 url"))
        if (!JcyApi.isAllowedHost(url)) {
            return json(403, JSONObject().put("code", 403).put("message", "域名不在直链白名单"))
        }

        val isHead = session.method == Method.HEAD
        // Range 语义与 Python 桥逐字对齐：
        //   - 播放器给了 Range（拖动进度条）→ 原样转发；
        //   - 无 Range 且是 HEAD → 注入 bytes=0-0 探测总长度
        //     （上游回 206 + Content-Range: bytes 0-0/<全长>，前端 probeSize() 靠它算缓存百分比）；
        //   - 无 Range 的 GET → 不注入，让上游回 200 + 完整文件。
        val range = session.headers["range"]?.takeIf { it.isNotEmpty() }
            ?: if (isHead) "bytes=0-0" else null

        val upstream: okhttp3.Response = try {
            JcyApi.openStream(url, range)
        } catch (t: Throwable) {
            Log.e(TAG, "上游直链请求失败: $url", t)
            return json(502, JSONObject().put("code", -2).put("message", "CDN 请求失败: ${t.message}"))
        }

        val status = Response.Status.lookup(upstream.code)
        val mime = upstream.header("Content-Type") ?: "video/mp4"
        val len = upstream.header("Content-Length")?.toLongOrNull() ?: -1L
        val body = upstream.body

        val resp: Response = if (isHead || body == null) {
            upstream.close()
            newFixedLengthResponse(status, mime, "")
        } else if (len >= 0) {
            // NanoHTTPD 在响应写完后会关闭该 InputStream，同时连带释放 okhttp 连接
            newFixedLengthResponse(status, mime, body.byteStream(), len)
        } else {
            newChunkedResponse(status, mime, body.byteStream())
        }
        upstream.header("Content-Range")?.let { resp.addHeader("Content-Range", it) }
        resp.addHeader("Accept-Ranges", upstream.header("Accept-Ranges") ?: "bytes")
        resp.addHeader("Cache-Control", "no-store")
        return resp
    }

    // ---------------------------------------------------------------- 辅助

    private fun readJsonBody(session: IHTTPSession): JSONObject? {
        val raw = readBodyUtf8(session) ?: return null
        if (raw.isBlank()) return null
        return try {
            JSONObject(raw)
        } catch (_: Throwable) {
            Diag.line("JcyBridge", "POST body 不是合法 JSON，头 80 = ${raw.take(80)}")
            JSONObject()
        }
    }

    /**
     * 按**原始字节**读 POST body，强制 UTF-8 解码。
     *
     * ⚠ 绝不能直接用 NanoHTTPD 的 `parseBody()`：前端发的是
     * `Content-Type: application/json`（**不带 charset**），NanoHTTPD 会按默认
     * 字符集（非 UTF-8）解码，body 里**每一个**非 ASCII 字节都被换成 U+FFFD。
     *
     * 这是「视频解析链接失败」的根因（2026-10-08 取证）：前端
     * `POST /resolve {"vid":"103558","play":"mp4","part":"第1集"}`，
     * `第1集` 在解码后变成 3 个 U+FFFD，再经 URLEncoder 编码发往服务端就是
     * `part=%EF%BF%BD%EF%BF%BD%EF%BF%BD1%EF%BF%BD%EF%BF%BD%EF%BF%BD`，
     * 服务端查不到该集 → `400404 查询无果`。
     *
     * 对照证据（/diag 的 JcyApi 日志，同一个 vid）：
     *   损坏：`part=%EF%BF%BD%EF%BF%BD%EF%BF%BD1%EF%BF%BD…` → code=400404
     *   正常：`part=%E7%AC%AC1%E9%9B%86`                   → code=20000
     * 后者是 part 由 Java 内部生成（不经 HTTP body）的情况，所以这个 bug
     * 只在「前端显式传中文 part」时暴露 —— 默认播第 1 集一直是好的。
     */
    private fun readBodyUtf8(session: IHTTPSession): String? {
        val len = session.headers["content-length"]?.trim()?.toIntOrNull()
        if (len == null || len <= 0) {
            // 分块传输 / 长度未知：只能退回 NanoHTTPD 自己的解码（非 ASCII 仍会损坏）
            val files = HashMap<String, String>()
            session.parseBody(files)
            return files["postData"]
        }
        return try {
            val buf = ByteArray(len)
            var off = 0
            val ins = session.inputStream
            while (off < len) {
                val n = ins.read(buf, off, len - off)
                if (n < 0) break
                off += n
            }
            String(buf, 0, off, Charsets.UTF_8)
        } catch (t: Throwable) {
            Diag.err("JcyBridge", "读取 POST body 失败（content-length=$len）", t)
            null
        }
    }

    private fun raw(body: String): Response =
        newFixedLengthResponse(Response.Status.OK, JSON_CT, body)

    private fun json(code: Int, obj: JSONObject): Response =
        newFixedLengthResponse(Response.Status.lookup(code), JSON_CT, obj.toString())

    /** 纯文本响应（/diag 用）。 */
    private fun text(code: Int, body: String): Response =
        newFixedLengthResponse(Response.Status.lookup(code), "text/plain; charset=utf-8", body)

    private fun cors(r: Response): Response {
        r.addHeader("Access-Control-Allow-Origin", "*")
        r.addHeader("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
        r.addHeader("Access-Control-Allow-Headers", "*")
        r.addHeader("Access-Control-Expose-Headers", "Content-Range, Accept-Ranges, Content-Length")
        return r
    }

    /** 存活探针：把「桥活着」与「native 会话就绪」分开报告，前端据此决定是否发业务请求。 */
    private fun healthInfo(): JSONObject = JSONObject()
        .put("ok", true)
        .put("bridge", "android-native")
        .put("core_loaded", JcyCore.isLoaded())
        .put("core_ready", coreReady)
        .put("port", listeningPort)

    /**
     * 真机排障：native 加载状态 + 各 action 的原始返回形状。
     *
     * **所有 native 调用一律走短超时**（[DEBUG_TIMEOUT_MS]）。历史教训：
     * 早期这里用默认 60 s，而 `api_encrypt` 在真机上永不回调，导致每次 `/debug`
     * 都把一条 NanoHTTPD 请求线程钉死 60 s —— 浮层每 4 s 打一次，线程池很快耗尽，
     * 连 `/health` 都不再响应。短超时保证 `/debug` 恒定在秒级返回。
     */
    private fun debugInfo(): JSONObject {
        val o = JSONObject()
            .put("loaded", JcyCore.isLoaded())
            .put("core_ready", coreReady)
            .put("init_raw", initRaw)
            .put("boot_error", bootError)
            .put("port", listeningPort)
            .put("host", JcyApi.HOST)
            .put("tcp", JcyCore.DEFAULT_TCP)
            .put("api_base", "http://127.0.0.1:$listeningPort")
            .put("sdk", android.os.Build.VERSION.SDK_INT)
            .put("abis", android.os.Build.SUPPORTED_ABIS.joinToString(","))
            .put("diag_sink", Diag.sinkPath())

        for (action in listOf("get_version", "get_app_info", "check")) {
            runCatching { o.put(action, JcyCore.callRawTimeout(actionJson(action), DEBUG_TIMEOUT_MS).toString().take(400)) }
                .onFailure {
                    o.put("${action}_err", it.toString())
                    Diag.err("JcyBridge", "$action 失败（${DEBUG_TIMEOUT_MS} ms 上限）", it)
                }
        }
        // api_encrypt 的**原始键名**——Kotlin 侧是按"形状"找信封的，这里把真实键名暴露出来
        runCatching {
            val enc = JcyCore.callRawTimeout(
                actionJson("api_encrypt", JSONObject().put("data", "{}")),
                DEBUG_TIMEOUT_MS,
            )
            o.put("api_encrypt_keys", JSONArray(enc.keys().asSequence().toList()))
            o.put("api_encrypt", enc.toString().take(600))
        }.onFailure {
            o.put("api_encrypt_err", it.toString())
            Diag.err("JcyBridge", "api_encrypt 失败（${DEBUG_TIMEOUT_MS} ms 上限）", it)
        }
        // 端到端最小闭环：真调一次最轻的接口，直接暴露取数链路通不通
        runCatching {
            val t0 = System.currentTimeMillis()
            val cfg = JcyApi.request("GET", "/app/config")
            o.put("probe_config_code", cfg.opt("code"))
            o.put("probe_config_ms", System.currentTimeMillis() - t0)
        }.onFailure { o.put("probe_config_err", it.toString()); Diag.err("JcyBridge", "probe /app/config 失败", it) }
        // 缓存与直链白名单现状（/stream 403 排查用）
        runCatching {
            o.put("stream_static_suffixes", JSONArray(JcyApi.STREAM_HOST_SUFFIXES))
            o.put("cache_entries", synchronized(cache) { cache.size })
        }
        return o
    }

    /**
     * `GET /probe` —— 逐个 action 探测 libcore 的可用性。
     *
     * 为什么必须单独做这一层：`api_encrypt` 是**每一个**业务请求的前置（连 GET 都要它
     * 产 ts / authentication 头）。真机实测它永不回调，于是「接口全挂」的现场只剩一个
     * 60 s 超时，无法区分到底是「回调 ABI 写错了」还是「某个 action 自己挂」。
     * 这里把 action 拆开、各给 4 s 上限，逐条给出「是否回调 / 耗时 / 原始返回」。
     *
     * 结果缓存 30 s；同一时刻只允许一次探测在跑（重入直接返回 429 + 上次结果），
     * 避免探测本身把桥的请求线程池耗干。
     */
    private fun probe(): JSONObject {
        val now = System.currentTimeMillis()
        if (probeCache.isNotEmpty() && now - probeCacheAt < PROBE_TTL_MS) {
            return JSONObject(probeCache).put("cached", true)
        }
        if (!probeRunning.compareAndSet(false, true)) {
            val o = JSONObject()
                .put("code", 429)
                .put("message", "探测进行中，请稍后重试")
                .put("cached", false)
            if (probeCache.isNotEmpty()) o.put("last", JSONObject(probeCache))
            return o
        }
        return try {
            val o = JSONObject()
                .put("loaded", JcyCore.isLoaded())
                .put("core_ready", coreReady)
                .put("init_raw", initRaw)
                .put("boot_error", bootError)
                .put("per_action_timeout_ms", PROBE_TIMEOUT_MS)
            val arr = JSONArray()
            for ((action, payload) in PROBE_ACTIONS) arr.put(probeOne(action, payload))
            o.put("actions", arr)
            probeCache = o.toString()
            probeCacheAt = System.currentTimeMillis()
            o
        } finally {
            probeRunning.set(false)
        }
    }

    private fun probeOne(action: String, payload: JSONObject?): JSONObject {
        val t0 = System.currentTimeMillis()
        return try {
            val out = JcyCore.callRawTimeout(actionJson(action, payload), PROBE_TIMEOUT_MS)
            JSONObject()
                .put("action", action)
                .put("ok", true)
                .put("ms", System.currentTimeMillis() - t0)
                .put("result", out.toString().take(600))
        } catch (t: Throwable) {
            JSONObject()
                .put("action", action)
                .put("ok", false)
                .put("ms", System.currentTimeMillis() - t0)
                .put("error", "${t.javaClass.simpleName}: ${t.message}")
        }
    }

    private fun actionJson(action: String, payload: JSONObject? = null): String {
        val args = JSONObject().put("action", action)
        if (payload != null) args.put("payload", payload)
        return args.toString()
    }
}
