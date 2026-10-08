package app.video.guoguo

import android.util.Base64
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * JcyApi —— 囧次元主 API 的 Kotlin 客户端（等价于 Python 侧 `research/deliverables/jcy_api.py`）。
 *
 * ## 与 Python 桥的根本差别
 * Python 侧要自己实现整套密码学（RSA-2048 信封 + 自研 E 分组密码 + authentication 签名），
 * 因为浏览器/PC 上没有 `libcore.so`。
 * **在安卓上不需要** —— 直接调 `libcore.so` 的 `api_encrypt` / `api_decrypt`：
 *   - `api_encrypt` 一次性产出「加密后的请求体 + 全套请求头（ts/authentication/nonce/...）」
 *   - `api_decrypt` 用响应里 RSA 包裹的会话密钥完成 P1 解密
 * 因此这里只是「信封的搬运工」：拿 native 的输出拼 HTTP，拿响应丢回 native 解。
 *
 * ## 并发
 * `libcore.so` 内部是进程单例全局态，并发 `api_encrypt` 会崩（同 Python 桥的 `_CE_LOCK`）。
 * 所有 native 调用统一走 [nativeCall] 上的互斥锁串行化；HTTP 部分仍可并行。
 */
object JcyApi {

    // ---------------------------------------------------------------- 常量
    /** 主 API：明文 HTTP，非标准端口（App 就是这么连的）。 */
    const val HOST = "43.145.33.254"
    const val PORT = 27990

    /** 外链解析器默认参数（V14 收官值；play 响应下发的 Lua 会覆写）。 */
    const val SALT = "pzizhsqjjt"
    const val PARSER = "http://yh.jx.xajtl.com/vo1v03.php?url="
    const val AES_KEY = "rdcibneoapyspqlt"
    const val AES_IV = "fyoofrebaxjwioxn"
    const val APP_VERSION = "1.5.8.0"
    const val PLATFORM = "Android"

    /** 直链 Referer 特例（来自 Lua 的 custom_head 规则）。 */
    private val REFERER_OVERRIDES = linkedMapOf(
        "aliyuncs.com" to "https://www.piccopilot.com",
        "toutiaovod.com" to "",
        "kwimgs.com" to "https://www.kuaishou.com",
        "dcarvod.com" to "https://www.dongchedi.com",
        "douyinvod.com" to "https://www.douyin.com",
    )

    /** 直链域名白名单（静态后缀兜底；resolve 成功后再动态登记）。/debug 也会打印它。 */
    val STREAM_HOST_SUFFIXES = listOf(
        "myqcloud.com", "toutiaovod.com", "douyinvod.com", "bdxiguavod.com",
        "aliyuncs.com", "kwimgs.com", "dcarvod.com", "douyin.com",
        // 解析器/回源域名：yh.jx.xajtl.com（Python 桥 _STREAM_HOST_SUFFIXES 同值）
        "zshtys888.com", "xajtl.com",
    )

    private const val UA = "Dart/3.6 (dart:io)"
    private val JSON_CT = "application/json; charset=utf-8".toMediaType()

    private val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    /** 流媒体专用：长读超时（大文件 Range）。 */
    private val streamHttp: OkHttpClient = http.newBuilder()
        .readTimeout(60, TimeUnit.SECONDS)
        .build()

    private val nativeLock = Any()

    // ---------------------------------------------------------------- native 封装

    /**
     * 串行调用 native（libcore 全局态不可并发）。
     * @throws IllegalStateException 超时或 native 未返回
     */
    private fun nativeCall(action: String, payload: JSONObject?, timeoutMs: Int = 60_000): JSONObject {
        val args = JSONObject().put("action", action)
        if (payload != null) args.put("payload", payload)
        val out = synchronized(nativeLock) {
            JcyCore.callRawTimeout(args.toString(), timeoutMs)
        }
        return out
    }

    // ---------------------------------------------------------------- 请求头

    /** 从 native 返回里取一个字段（大小写不敏感）。 */
    private fun pick(obj: JSONObject, vararg names: String): String? {
        for (n in names) {
            if (obj.has(n)) {
                val v = obj.optString(n, "")
                if (v.isNotEmpty()) return v
            }
        }
        // 退化为忽略大小写扫描
        val keys = obj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            for (n in names) {
                if (k.equals(n, ignoreCase = true)) {
                    val v = obj.optString(k, "")
                    if (v.isNotEmpty()) return v
                }
            }
        }
        return null
    }

    /**
     * 在 payload 里找出信封体 `<P0_b64>.<P1_b64>`。
     *
     * 不写死字段名：native 的返回键名未在静态分析中完全确定（见
     * research/reports/V26_libcore_arch.md），因此按「形状」识别 ——
     * 长度 ≥ 300 且形如 `base64.base64` 的字符串即为信封。
     * 找不到时回落到候选键名，最后把实际键名打进异常便于真机修正。
     */
    private fun findEnvelope(payload: JSONObject): String? {
        for (cand in listOf("body", "data", "cipher", "encrypt", "encrypted", "result", "content", "p", "s")) {
            val v = pick(payload, cand)
            if (v != null && looksLikeEnvelope(v)) return v
        }
        val keys = payload.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            val v = payload.opt(k)
            if (v is String && looksLikeEnvelope(v)) return v
        }
        return null
    }

    private fun looksLikeEnvelope(s: String): Boolean {
        if (s.length < 300) return false
        val dot = s.indexOf('.')
        if (dot <= 0 || dot == s.length - 1) return false
        // 自定义 base64 字母表含 + / = 与全部大小写字母数字
        return s.all { it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' || it == '.' || it == '-' || it == '_' }
    }

    /**
     * 构造一次加密请求。
     *
     * @return Triple(加密后的请求体或 null(GET), 请求头, 明文信封 JSON)
     */
    private fun buildEnvelope(params: JSONObject?, timeoutMs: Int = 60_000): Pair<String?, Map<String, String>> {
        val plain = (params ?: JSONObject()).toString()
        val res = nativeCall("api_encrypt", JSONObject().put("data", plain), timeoutMs)
        val payload = res.optJSONObject("payload") ?: res

        val headers = linkedMapOf(
            "x-version" to (pick(payload, "x-version", "x_version", "version") ?: JcyCore.X_VERSION),
            "user-agent" to UA,
            "appid" to (pick(payload, "appid", "app_id") ?: JcyCore.APPID_HEADER),
            "tcs" to (pick(payload, "tcs") ?: JcyCore.TCS),
            "content-type" to "application/json; charset=utf-8",
            "ts" to (pick(payload, "ts") ?: System.currentTimeMillis().toString()),
            "nonce" to (pick(payload, "nonce") ?: (10000000 + (Math.random() * 89999999).toLong()).toString()),
        )
        pick(payload, "authentication", "Authentication", "auth")?.let { headers["authentication"] = it }

        val body = findEnvelope(payload)
        if (body == null && params != null) {
            throw IllegalStateException(
                "api_encrypt 返回里找不到信封体；实际键 = ${payload.keys().asSequence().toList()}",
            )
        }
        return body to headers
    }

    // ---------------------------------------------------------------- 核心请求

    /**
     * 发一次业务请求并返回**明文 JSON**。
     *
     * @param method GET / POST
     * @param path   形如 `/app/video/list?channel=1&limit=6`（query 直接拼在 path 里）
     * @param params POST 的业务参数；GET 传 null（GET 带 body 会被服务端拒 40000）
     */
    fun request(
        method: String,
        path: String,
        params: JSONObject? = null,
        timeoutMs: Int = 60_000,
    ): JSONObject {
        val m = method.uppercase()
        val t0 = System.currentTimeMillis()
        try {
            // GET 也要 ts/authentication，所以照样走一次 api_encrypt 取头，只是不发这个 body
            val (encBody, headers) = buildEnvelope(if (m == "POST") (params ?: JSONObject()) else null, timeoutMs)
            Diag.line("JcyApi", "$m $path → 信封 ${encBody?.length ?: 0} B，头键 ${headers.keys}")

            val url = "http://$HOST:$PORT" + (if (path.startsWith("/")) path else "/$path")
            val b = Request.Builder().url(url)
            for ((k, v) in headers) b.header(k, v)
            if (m == "POST") {
                b.post((encBody ?: "").toRequestBody(JSON_CT))
            } else {
                b.get()
            }

            val result = http.newCall(b.build()).execute().use { resp ->
                val text = resp.body?.string() ?: ""
                Diag.line("JcyApi", "$m $path ← HTTP ${resp.code}，body ${text.length} B")
                if (text.isEmpty()) {
                    JSONObject().put("code", -1).put("message", "空响应 HTTP ${resp.code}")
                } else if (!looksLikeEnvelope(text)) {
                    // 明文响应（弹幕 / 错误码 30000 / 50008 …）不是 <P0>.<P1> 信封
                    tryParse(text)
                } else {
                    val dec = nativeCall(
                        "api_decrypt",
                        JSONObject().put("data", text).put("path", path),
                        timeoutMs,
                    )
                    val payload = dec.optJSONObject("payload") ?: dec
                    val plain = pick(payload, "data", "body", "result", "content", "plain")
                        ?: (payload.opt("data")?.toString())
                        ?: payload.toString()
                    tryParse(plain)
                }
            }
            Diag.line(
                "JcyApi",
                "$m $path 完成：${System.currentTimeMillis() - t0} ms，code=${result.opt("code")}",
            )
            return result
        } catch (t: Throwable) {
            Diag.err("JcyApi", "$m $path 失败（${System.currentTimeMillis() - t0} ms）", t)
            throw t
        }
    }

    private fun tryParse(s: String): JSONObject = try {
        JSONObject(s)
    } catch (_: Throwable) {
        JSONObject().put("code", -1).put("message", "非 JSON 响应").put("raw", s.take(300))
    }

    // ---------------------------------------------------------------- 业务便捷方法

    fun config(): JSONObject = request("GET", "/app/config")
    fun channels(): JSONObject = request("GET", "/app/channel?top-level=true")
    fun banners(channel: Int = 0): JSONObject = request("GET", "/app/banners/$channel")
    fun updateList(date: String): JSONObject = request("GET", "/app/video_update_list/$date")
    fun videoList(channel: Int = 1, sort: String = "weight", limit: Int = 6, page: Int = 1) =
        request("GET", "/app/video/list?channel=$channel&sort=$sort&limit=$limit&page=$page")

    fun videoDetail(vid: Any) = request("GET", "/app/video/detail?id=$vid")
    fun search(key: String, limit: Int = 25, page: Int = 1) =
        request("GET", "/app/video/search?key=${enc(key)}&limit=$limit&page=$page")

    fun suggest(key: String, limit: Int = 10, page: Int = 1) =
        request("GET", "/app/video/key?key=${enc(key)}&limit=$limit&page=$page")

    fun comments(vid: Any, page: Int = 1, limit: Int = 20) =
        request("GET", "/app/vod_comment/getlist?vid=$vid&limit=$limit&page=$page")

    fun danmu(vid: Any, part: String, play: String = "mp4", startMs: Long = 0, endMs: Long = 60000) =
        request("GET", "/app/danmu?vid=$vid&play=${enc(play)}&part=${enc(part)}&start_time_point=$startMs&end_time_point=$endMs")

    fun record() = request("POST", "/app/video/record", JSONObject())

    private fun enc(s: String) = java.net.URLEncoder.encode(s, "UTF-8")

    // ---------------------------------------------------------------- 播放解析

    /**
     * 播放闭环：`/app/video/play` 取凭证 → 外链解析器 → 多清晰度直链。
     *
     * 与 Python 侧不同，这里**不做 16 块部分解密的快路径** ——
     * native `api_decrypt` 是 ARM64 原生实现（~1.4ms/块 的标定在 C 引擎里已内联），
     * 全解 323 块也在百毫秒量级，没必要引入截断明文的正则抽取。
     */
    fun play(vid: Any, playFmt: String = "mp4", partIn: String? = null): JSONObject {
        var part = partIn
        var fmt = playFmt
        // 编码损坏探针：part 里出现 U+FFFD，说明 POST body 被非 UTF-8 字符集解码过
        // （根因与修复见 JcyBridgeServer.readBodyUtf8）。这里只负责让它立刻可见 ——
        // 否则症状只是服务端一句「400404 查询无果」，极难联想到是本地编码问题。
        if (!part.isNullOrEmpty() && part.indexOf('\uFFFD') >= 0) {
            Diag.line(
                "JcyApi",
                "part 含 U+FFFD（POST body 字符集损坏）：" +
                    part.map { if (it == '\uFFFD') '?' else it }.joinToString("") +
                    " —— 服务端会返回 400404 查询无果",
            )
        }
        if (part.isNullOrEmpty()) {
            val det = videoDetail(vid).opt("data")
            val parts = when (det) {
                is JSONObject -> det.optJSONArray("parts")
                else -> null
            }
            if (parts != null && parts.length() > 0) {
                val first = parts.optJSONObject(0)
                if (first != null) {
                    val arr = first.optJSONArray("part")
                    if (arr != null && arr.length() > 0) part = arr.optString(0)
                    first.optString("play", "").takeIf { it.isNotEmpty() }?.let { fmt = it }
                }
            }
        }
        if (part.isNullOrEmpty()) part = "第1集"

        val q = "/app/video/play?id=$vid&play=${enc(fmt)}&part=${enc(part)}"
        val pj = request("POST", q, JSONObject())

        val out = JSONObject()
            .put("code", pj.opt("code"))
            .put("play", pj)
            .put("playAddr", JSONArray())
            .put("urls", JSONArray())

        val data = pj.opt("data")
        val entries: JSONArray = when {
            data is JSONArray -> data
            data is JSONObject && data.opt("data") is JSONArray -> data.optJSONArray("data")!!
            else -> JSONArray()
        }
        if (entries.length() == 0) return out

        val entry = entries.optJSONObject(0) ?: return out
        val source = entry.optString("url", "").takeIf { it.isNotEmpty() }
        val lua = entry.optString("parse", "")
        out.put("source", source ?: JSONObject.NULL)
        out.put("lua", lua)

        if (source.isNullOrEmpty()) return out

        val (salt, aesKey, aesIv, parser) = luaParams(lua)
        if (!fillAddrs(out, source, salt, aesKey, aesIv, parser) && lua.isEmpty()) {
            // Lua 为空时用类默认参数重试一次（对应 Python 侧的回退分支）
            val d = luaParams("")
            fillAddrs(out, source, d.salt, d.aesKey, d.aesIv, d.parser)
        }
        return out
    }

    private data class LuaParams(val salt: String, val aesKey: String, val aesIv: String, val parser: String)

    private fun luaParams(lua: String): LuaParams {
        fun rx(pat: String, def: String): String =
            Regex(pat).find(lua)?.groupValues?.get(1) ?: def
        val salt = rx("""salt\s*=\s*"([^"]+)"""", SALT)
        val key = rx("""aes_key\s*=\s*"([^"]+)"""", AES_KEY)
        val iv = rx("""aes_iv\s*=\s*"([^"]+)"""", AES_IV)
        val urls = Regex("""https?://[^\s"'\]]+""").findAll(lua).map { it.value }.toList()
        val parser = urls.firstOrNull { it.trimEnd('/').endsWith("=") || it.contains(".php?url=") } ?: PARSER
        return LuaParams(salt, key, iv, parser)
    }

    /** 请求外链解析器并填充 urls。返回是否拿到可用直链。 */
    private fun fillAddrs(
        out: JSONObject, source: String,
        salt: String, aesKey: String, aesIv: String, parser: String,
    ): Boolean {
        val ts = System.currentTimeMillis()
        val s1 = md5(APP_VERSION + salt + ts)
        val s2 = md5(source + salt + ts)
        val prest = parser.substringAfter("://")
        val phost = prest.substringBefore("/")
        val ppath = prest.substringAfter("/", "")

        val ptxt = try {
            val rb = Request.Builder()
                .url("http://$phost/$ppath$source&t=$ts")
                .header("x-time", ts.toString())
                .header("x-form", PLATFORM)
                .header("x-sign1", s1)
                .header("x-sign2", s2)
                .header("user-agent", UA)
                .get()
            http.newCall(rb.build()).execute().use { it.body?.string() ?: "" }
        } catch (e: Exception) {
            out.put("resolverRaw", "解析器请求失败: ${e.message}")
            return false
        }

        val pobj = try {
            parseResolver(ptxt, aesKey, aesIv)
        } catch (e: Exception) {
            out.put("resolverRaw", "解析器响应不可解析: ${e.message}")
            return false
        }
        out.put("resolverRaw", pobj?.toString() ?: ptxt.take(400))

        val pa = pobj?.optJSONObject("data")?.optJSONArray("playAddr")
        if (pa != null && pa.length() > 0) {
            out.put("playAddr", pa)
            val urls = JSONArray()
            for (i in 0 until pa.length()) {
                val it = pa.optJSONObject(i) ?: continue
                val url = it.optString("m3u8FileDomain", "") + it.optString("addr", "")
                urls.put(
                    JSONObject()
                        .put("name", (it.optString("desc", "") + " " + it.optString("title", "")).trim())
                        .put("vcodec", it.opt("vcodec"))
                        .put("format", it.opt("format"))
                        .put("url", url)
                        .put("headers", JSONObject(directHeaders(url) as Map<*, *>)),
                )
            }
            out.put("urls", urls)
            return true
        }
        if (pobj != null && pobj.has("url")) {
            val url = pobj.optString("url")
            val urls = JSONArray().put(
                JSONObject()
                    .put("name", pobj.optString("type", "mp4"))
                    .put("vcodec", JSONObject.NULL)
                    .put("format", pobj.opt("type"))
                    .put("url", url)
                    .put("headers", JSONObject(directHeaders(url) as Map<*, *>)),
            )
            out.put("urls", urls)
            return true
        }
        return false
    }

    /** 解析器响应：明文 JSON 优先，否则按 Lua 兜底走 AES-128-CBC（hex / 自定义b64 / 标准b64）。 */
    private fun parseResolver(ptxt: String, aesKey: String, aesIv: String): JSONObject? {
        try {
            return JSONObject(ptxt)
        } catch (_: Throwable) {
            // fallthrough
        }
        val s = ptxt.trim()
        val candidates = ArrayList<ByteArray>()
        if (s.isNotEmpty() && s.length % 32 == 0 && s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
            runCatching { candidates.add(s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()) }
        }
        runCatching { candidates.add(Base64.decode(s, Base64.DEFAULT)) }
        runCatching {
            // 自定义字母表
            candidates.add(Base64.decode(s.map { CUSTOM_TO_STD[it] ?: it }.joinToString(""), Base64.DEFAULT))
        }
        for (raw in candidates) {
            runCatching {
                val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
                c.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(aesKey.toByteArray(Charsets.UTF_8), "AES"),
                    IvParameterSpec(aesIv.toByteArray(Charsets.UTF_8)),
                )
                return JSONObject(String(c.doFinal(raw), Charsets.UTF_8))
            }
        }
        throw IllegalArgumentException("解析器响应无法解析，头 80 字节: ${s.take(80)}")
    }

    // ---------------------------------------------------------------- 直链头 / 白名单

    /** 自定义 base64 字母表 → 标准（`research/` 里 ALPHABET 的逆映射）。 */
    private const val CUSTOM_ALPHABET = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj"
    private const val STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private val CUSTOM_TO_STD: Map<Char, Char> =
        CUSTOM_ALPHABET.mapIndexed { i, c -> c to STD_ALPHABET[i] }.toMap()

    /** 直链请求头：UA 置空 + 按域伪造 Referer（浏览器禁设，原生可以）。 */
    fun directHeaders(url: String): Map<String, String> {
        val host = runCatching { java.net.URI(url).host ?: "" }.getOrDefault("")
        var referer = url
        for ((dom, ref) in REFERER_OVERRIDES) {
            if (host.endsWith(dom)) {
                referer = ref
                break
            }
        }
        return mapOf("User-Agent" to "", "Referer" to referer)
    }

    private val dynHosts = HashMap<String, Long>()

    fun registerDynamicHosts(payload: JSONObject) {
        val now = System.currentTimeMillis()
        val urls = ArrayList<String>()
        payload.optJSONArray("urls")?.let { arr ->
            for (i in 0 until arr.length()) {
                val u = arr.optJSONObject(i) ?: continue
                for (k in listOf("url", "playAddr")) {
                    val v = u.optString(k, "")
                    if (v.startsWith("http")) urls.add(v)
                }
            }
        }
        payload.optJSONArray("playAddr")?.let { arr ->
            for (i in 0 until arr.length()) {
                val v = arr.optString(i, "")
                if (v.startsWith("http")) urls.add(v)
            }
        }
        synchronized(dynHosts) {
            if (dynHosts.size > 512) dynHosts.clear()
            for (u in urls) {
                val h = runCatching { java.net.URI(u).host?.lowercase() }.getOrNull() ?: continue
                dynHosts[h] = now + 6 * 3600_000L
            }
        }
    }

    fun isAllowedHost(url: String): Boolean {
        val host = runCatching { java.net.URI(url).host?.lowercase() ?: "" }.getOrDefault("")
        if (STREAM_HOST_SUFFIXES.any { host == it || host.endsWith(".$it") }) return true
        synchronized(dynHosts) {
            val exp = dynHosts[host]
            return exp != null && exp > System.currentTimeMillis()
        }
    }

    // ---------------------------------------------------------------- 工具

    fun md5(s: String): String =
        MessageDigest.getInstance("MD5").digest(s.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    /**
     * 供 /stream 使用：带注入头的流式请求。
     *
     * Range 语义必须与 Python 桥（`src/web/server/main.py::stream`）逐字一致：
     *   - 调用方给了 Range（播放器拖动进度条）→ 原样转发；
     *   - 没给 Range → **不加 Range 头**，让上游返回 200 + 完整文件。
     *
     * 绝不能在这里兜底成 `bytes=0-0`：那会让上游返回 206 且只带 1 字节，
     * 播放器拿到残缺响应直接卡死（HEAD 探测总长度是**调用方**的职责，
     * 由 JcyBridgeServer 显式传 `bytes=0-0` 进来）。
     */
    fun openStream(url: String, range: String?): okhttp3.Response {
        val rb = Request.Builder().url(url)
        for ((k, v) in directHeaders(url)) rb.header(k, v)
        if (!range.isNullOrEmpty()) rb.header("Range", range)
        return streamHttp.newCall(rb.build()).execute()
    }
}
