package app.video.guoguo

import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import org.json.JSONObject
import java.io.File
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * JcyCorePlugin —— 暴露给 WebView 中 React 前端的桥。
 *
 * JS 侧用法：
 *   const { JcyCore } = Capacitor.Plugins
 *   await JcyCore.load()
 *   await JcyCore.init({ deviceId: "..." })
 *   await JcyCore.decrypt({ body: "<P0>.<P1>", path: "/app/video/play" })
 *
 * 线程模型：native 侧的解密是 **CPU 密集**（单块 1.0~1.4 ms，一条 lua 响应可跨 300+ 块，
 * 即数百 ms ~ 秒级）。因此所有 native 调用都丢到一条专用后台线程，
 * 绝不在 Capacitor 的插件线程（主线程）上同步执行 —— 否则会触发 ANR。
 * 串行执行同时满足了 libcore.so 内部状态非线程安全的要求。
 */
@CapacitorPlugin(name = "JcyCore")
class JcyCorePlugin : Plugin() {

    /** 专用单线程执行器：串行 + 后台，daemon 以免拖住进程退出。 */
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "jcy-core").apply { isDaemon = true }
    }

    /** 统一的「后台执行 + 主线程回调」包装。 */
    private fun onWorker(call: PluginCall, what: String, block: () -> JSONObject) {
        worker.execute {
            try {
                val out = block()
                call.resolve(JSObject.fromJSONObject(out))
            } catch (t: Exception) {
                // 注意：Capacitor 的 reject(String, Exception) 只接受 Exception，
                // 因此这里捕 Exception（Error 级别的问题不应被吞掉）。
                call.reject("$what 失败: ${t.message}", t)
            }
        }
    }

    private fun ensureLoaded() {
        if (!JcyCore.isLoaded()) JcyCore.load(context)
    }

    /** 默认 files_path 对齐 Dart 侧：`${getApplicationDocumentsDirectory()}/files`。 */
    private fun defaultFilesPath(): String =
        File(context.filesDir, "app_flutter/files").absolutePath

    @PluginMethod
    fun load(call: PluginCall) {
        onWorker(call, "load") {
            ensureLoaded()
            JSONObject().put("ok", true).put("loaded", JcyCore.isLoaded())
        }
    }

    @PluginMethod
    fun status(call: PluginCall) {
        onWorker(call, "status") {
            JSONObject().put("loaded", JcyCore.isLoaded())
        }
    }

    @PluginMethod
    fun init(call: PluginCall) {
        val deviceId = call.getString("deviceId")
            ?: "16613a7076284a15bc723d018bcd67e1"
        val filesPath = call.getString("filesPath") ?: defaultFilesPath()
        val appId = call.getString("appId")
        val tcp = call.getString("tcp") ?: JcyCore.DEFAULT_TCP
        onWorker(call, "init") {
            ensureLoaded()
            val raw = JcyCore.init(
                deviceId = deviceId,
                filesPath = filesPath,
                appId = appId,
                tcp = tcp,
            )
            // native init 不保证返回 JSON（Dart 侧也忽略返回值），做容错解析。
            if (raw.isBlank()) {
                JSONObject().put("ok", true).put("raw", "")
            } else {
                try {
                    JSONObject(raw).put("ok", true).put("raw", raw)
                } catch (_: Throwable) {
                    JSONObject().put("ok", true).put("raw", raw)
                }
            }
        }
    }

    @PluginMethod
    fun decrypt(call: PluginCall) {
        val body = call.getString("body")
        val path = call.getString("path") ?: "/app/video/play"
        if (body.isNullOrEmpty()) {
            call.reject("缺少 body")
            return
        }
        onWorker(call, "decrypt") {
            ensureLoaded()
            JcyCore.decrypt(body, path)
        }
    }

    @PluginMethod
    fun encrypt(call: PluginCall) {
        val body = call.getString("body")
        if (body.isNullOrEmpty()) {
            call.reject("缺少 body")
            return
        }
        onWorker(call, "encrypt") {
            ensureLoaded()
            JcyCore.encrypt(body)
        }
    }

    /** 透传一个 action（check / get_app_info / get_version / get_abi ...），便于真机诊断。 */
    @PluginMethod
    fun invoke(call: PluginCall) {
        val action = call.getString("action")
        if (action.isNullOrEmpty()) {
            call.reject("缺少 action")
            return
        }
        val payload = call.getString("payload")
        onWorker(call, "invoke($action)") {
            ensureLoaded()
            if (payload.isNullOrEmpty()) JcyCore.invoke(action)
            else JcyCore.invoke(action, JSONObject(payload))
        }
    }

    override fun handleOnDestroy() {
        try {
            worker.shutdownNow()
            worker.awaitTermination(1, TimeUnit.SECONDS)
        } catch (_: Throwable) {
            // ignore
        }
        super.handleOnDestroy()
    }
}
