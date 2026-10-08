package app.video.guoguo

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * JcyCore —— libcore.so 的 Kotlin 门面。
 *
 * native 层签名（由 Dart FFI 调用点反推）：
 *   void call(const char* b64, const char* (*cb)(const char* result, void* ctx));
 *   void init(const char* json);
 *
 * 传输层（ffi_utils.dart `__call`）：入参与回调结果均为
 *   base64( AES-128-CBC-PKCS7( json ) )
 *   key = "qPwClBj7j7ZQraSm"   iv = "p3JdVQl3q7WQJIgG"
 *
 * 已确认的 action（来自 ffi_utils.dart）：
 *   check / clear_key / get_app_info / init / get_host_config / get_record /
 *   get_version / get_abi / api_encrypt / api_decrypt / get_registries / reload
 *
 * 关键结论（g_http_client.dart 实证）：
 *   `api_encrypt` 的返回值里**同时**带着请求头和加密后的 body —— 即
 *   APPID / ts / authentication / x-version / tcs / nonce 全部由它产出，
 *   所以 App 侧不需要单独实现 authentication 算法。
 */
object JcyCore {

    init {
        System.loadLibrary("jcy_core")
    }

    private const val KEY = "qPwClBj7j7ZQraSm"
    private const val IV = "p3JdVQl3q7WQJIgG"

    // 协议常量（src/jcy_protocol/auth.py）
    const val CODE_VERSION = "3.0.0.8"
    const val APP_VERSION = "1.5.8.0"
    const val APPID_HEADER = "4150439554430529"
    const val X_VERSION = "2020-09-17"
    const val TCS = "2"
    const val UA = "Dart/3.6 (dart:io)"

    /**
     * init 的 tcp 字段：**真值 `43.145.33.254:8191`**。
     *
     * 来源：2026-10-08 在雷电 14 上用自研 memfind 直接扫描官方 App
     * （`com.tudou.tool`）运行内存，读出它传给 libcore 的原始 JSON：
     *
     *     {"app_id":"4150439554430529","device_id":"f56b8cc9a0b24a3996efe200e9d93bc8",
     *      "code_version":"3.0.0.8","app_version":"1.5.8.0",
     *      "files_path":"/data/user/0/com.tudou.tool/files","tcp":"43.145.33.254:8191"}
     *
     * **注意不是 27990** —— 27990 是 HTTP 业务 API 的端口（抓包链路里看到的那个），
     * 而 init 的 tcp 是 libcore 内部"server"通道的端口，两者不同。
     */
    const val DEFAULT_TCP = "43.145.33.254:8191"

    @JvmStatic external fun nativeLoad(libDir: String?): Boolean
    @JvmStatic external fun nativeInit(json: String?): String?
    @JvmStatic external fun nativeCall(b64: String): String?

    /** 带自定义超时的 call（诊断用）。timeoutMs ≤ 0 或 > 60s 时回落为 60s。 */
    @JvmStatic external fun nativeCallTimeout(b64: String, timeoutMs: Int): String?
    @JvmStatic external fun nativeUnload()

    @Volatile private var loaded = false

    /** 加载 libcore.so；失败抛异常。libDir 取 context.applicationInfo.nativeLibraryDir。 */
    @Synchronized
    fun load(ctx: Context) {
        if (loaded) return
        val dir = ctx.applicationInfo.nativeLibraryDir
        val t0 = System.currentTimeMillis()
        val ok = nativeLoad(dir)
        Diag.line("JcyCore", "nativeLoad(libDir=$dir) -> $ok，${System.currentTimeMillis() - t0} ms")
        check(ok) { "dlopen(libcore.so) 失败（libDir=$dir）" }
        loaded = true
        Diag.fact("libcore_loaded", true)
    }

    fun isLoaded(): Boolean = loaded

    /**
     * 初始化 native 上下文。
     *
     * 已由 libapp.so 的 `FFIUtils.init`（@0x747600）反汇编证实：
     *  - 真实参数集为 6 个字段：app_id / device_id / code_version / app_version / files_path / tcp
     *  - **`files_path` = `<dataDir>/files`**（不是 `<dataDir>/app_flutter/files`）——
     *    2026-10-08 从官方 App 运行内存里读出的原始 JSON 证实
     *  - `tcp` = `43.145.33.254:8191`（见 [DEFAULT_TCP]），不是 HTTP 业务 API 的 27990
     *  - **init 传的是裸 JSON，不经 AES 包装**：该函数用的是 Utf8Encoder(pp+0x380)
     *    + MallocAllocator(pp+0x7140) 走 `toNativeUtf8()`，全程没有 Encrypter/AESMode。
     *    AES 包装只发生在 `call` 路径（dartCallback @0x715844 才是解密侧）。
     *  - init 是独立导出符号，不是 call 的 action（`call({"action":"init"})` 实测返回 code:404）
     *  - **顺序必须是 init 先、call 后**：native 的会话态由 init 建立，
     *    init 之前发 call 会拿到 `10032 未初始化`（早期版本这里用 resolveAppId() 就是踩了这个坑）
     *  - **init 不会回调**：其 Dart 侧类型只有 (dynamic, Pointer&lt;Utf8&gt;) 两个入参、
     *    返回 Void，根本没有回调形参（libcore 0x2fdc24 的 116 B 实现也只读 x0）。
     */
    fun init(
        deviceId: String,
        filesPath: String,
        appId: String? = null,
        tcp: String = DEFAULT_TCP,
        codeVersion: String = CODE_VERSION,
        appVersion: String = APP_VERSION,
    ): String {
        check(loaded) { "先调用 load()" }
        // native 会在 files_path 下读写运行期数据（Flutter 侧该目录由
        // getApplicationDocumentsDirectory() 自动创建，原生侧没人建）。
        // 不建的话 init 本身可能通过，但首次落盘才失败 —— 症状是后续接口
        // 莫名返回 10032/50008，极难定位，所以这里主动补上。
        runCatching { File(filesPath).mkdirs() }
        // 字段集与**顺序**严格对齐官方 App 运行内存里读出的原文：
        //   {"app_id","device_id","code_version","app_version","files_path","tcp"}
        // 不要加 action —— init 不是 call 的 action，多带字段没有意义。
        // app_id 这里**不能**回落到 resolveAppId()：那会先发一次 native call，
        // 而 native 的会话态正是由 init 建立的（顺序颠倒 → 10032 未初始化）。
        val args = JSONObject()
            .put("app_id", appId ?: APPID_HEADER)
            .put("device_id", deviceId)
            .put("code_version", codeVersion)
            .put("app_version", appVersion)
            .put("files_path", filesPath)
            .put("tcp", tcp)
            .toString()
        // 注意：裸 JSON，不做 AES 包装
        val t0 = System.currentTimeMillis()
        val ret = nativeInit(args) ?: ""
        Diag.line(
            "JcyCore",
            "init 完成：耗时 ${System.currentTimeMillis() - t0} ms，返回 ${ret.length} B" +
                (if (ret.isEmpty()) "（空 —— native 未回调或 init 为同步）" else "：${ret.take(160)}"),
        )
        Diag.fact("init_ok", ret.isNotEmpty())
        return ret
    }

    /** 从 native 取真实 app_id（Dart 侧 getAppId() = get_app_info()["app_id"]）。 */
    fun resolveAppId(): String =
        try {
            getAppInfo().optString("app_id").ifEmpty { APPID_HEADER }
        } catch (e: Throwable) {
            APPID_HEADER
        }

    /** 诊断：跑一次 `check`，返回明文 JSON。 */
    fun check(): JSONObject = call("check")

    fun getVersion(): JSONObject = call("get_version")

    fun getAbi(): JSONObject = call("get_abi")

    fun getAppInfo(): JSONObject = call("get_app_info")

    fun clearKey(): JSONObject = call("clear_key")

    /**
     * 加密一个明文请求体。
     * 真实 payload 只有 `data` 一个键（ffi_utils.dart @0x84fe24 实证）；
     * 返回值经 unwrapPayload 取 `payload` 子对象，内含加密后的 body
     * 与请求头（ts / authentication / x-version / tcs / nonce）。
     */
    fun encrypt(plainBody: String): JSONObject =
        unwrapPayload(call("api_encrypt", JSONObject().put("data", plainBody)))

    /** 解密一个加密响应体；payload = {data, path}（@0xbd7acc 实证）。 */
    fun decrypt(encryptedBody: String, path: String): JSONObject =
        unwrapPayload(
            call("api_decrypt", JSONObject().put("data", encryptedBody).put("path", path)),
        )

    /** native 返回 {code, payload:{...}}；Dart 侧对外暴露的是 payload 子对象。 */
    private fun unwrapPayload(res: JSONObject): JSONObject =
        res.optJSONObject("payload") ?: res

    // ------------------------------------------------------------ 通用调用

    /** 透传 action（供插件诊断用）。返回 payload 子对象（若有）。 */
    fun invoke(action: String): JSONObject = unwrapPayload(call(action))

    fun invoke(action: String, payload: JSONObject): JSONObject =
        unwrapPayload(call(action, payload))

    /**
     * 直接用**完整请求 JSON**（`{"action":…,"payload":{…}}`）调 native，返回解包后的 JSON。
     * 供 [JcyApi] 使用 —— 它自己拼 action/payload，不想被这里再包一层。
     */
    fun callRaw(argsJson: String): JSONObject = callRawTimeout(argsJson, 60_000)

    /**
     * 与 [callRaw] 相同，但可指定 native 侧等待回调的上限。
     *
     * 诊断专用：libcore 的部分 action（实测 `api_encrypt`）可能**永不回调**，
     * 默认 60 s 会把桥的请求线程池耗干（每个 /debug 都在等它）。
     */
    fun callRawTimeout(argsJson: String, timeoutMs: Int): JSONObject {
        check(loaded) { "先调用 load()" }
        val action = runCatching { JSONObject(argsJson).optString("action") }.getOrDefault("?")
        val t0 = System.currentTimeMillis()

        val encoded = try {
            nativeCallTimeout(wrap(argsJson), timeoutMs)
        } catch (t: Throwable) {
            Diag.err("JcyCore", "call($action) nativeCall 抛异常（${System.currentTimeMillis() - t0} ms）", t)
            throw t
        } ?: run {
            Diag.err(
                "JcyCore",
                "call($action) native 未返回结果（超时 ${timeoutMs} ms / 崩溃，实际 ${System.currentTimeMillis() - t0} ms）",
            )
            throw IllegalStateException("native call($action) 未返回结果（超时或崩溃）")
        }

        return try {
            val out = unwrap(encoded)
            Diag.line(
                "JcyCore",
                "call($action) ok：${System.currentTimeMillis() - t0} ms，密文 ${encoded.length} B，明文键 ${out.keys().asSequence().toList()}",
            )
            out
        } catch (t: Throwable) {
            Diag.err(
                "JcyCore",
                "call($action) 解包失败（${System.currentTimeMillis() - t0} ms，密文 ${encoded.length} B，头 48=${encoded.take(48)}）",
                t,
            )
            throw t
        }
    }

    private fun call(action: String): JSONObject =
        call(action, null)

    private fun call(action: String, payload: JSONObject?): JSONObject {
        check(loaded) { "先调用 load()" }
        val args = JSONObject().put("action", action)
        if (payload != null) args.put("payload", payload)
        val encoded = nativeCall(wrap(args.toString()))
            ?: throw IllegalStateException("native call($action) 未返回结果（超时或崩溃）")
        return unwrap(encoded)
    }

    // ---- 传输层：base64(AES-128-CBC-PKCS7(x)) ----

    fun wrap(json: String): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(KEY.toByteArray(Charsets.UTF_8), "AES"),
            IvParameterSpec(IV.toByteArray(Charsets.UTF_8)),
        )
        return Base64.encodeToString(cipher.doFinal(json.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    }

    fun unwrap(b64: String): JSONObject {
        if (b64.isEmpty()) return JSONObject()
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(KEY.toByteArray(Charsets.UTF_8), "AES"),
            IvParameterSpec(IV.toByteArray(Charsets.UTF_8)),
        )
        val plain = cipher.doFinal(Base64.decode(b64, Base64.DEFAULT))
        return JSONObject(String(plain, Charsets.UTF_8))
    }
}
