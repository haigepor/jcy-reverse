package app.video.guoguo

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.util.Log
import com.getcapacitor.BridgeActivity
import org.json.JSONObject
import java.io.File

/**
 * MainActivity —— Capacitor 宿主 Activity。
 *
 * 启动顺序很关键：
 *  1. `registerPlugin` 必须在 `super.onCreate` **之前**，否则 JS 侧拿不到 JcyCore 入口；
 *  2. `libcore.so` 要先 `load` + `init`，本地 HTTP 桥才有解密能力；
 *  3. 桥启动在后台线程 —— `init` 里含网络等待，放主线程会 ANR。
 *
 * 桥启动失败不阻塞 App：前端会退化成「接口全 404」，但界面仍能渲染。
 * **真机排障**：所有关键步骤都写进 [Diag]，通过三条出口暴露（见 Diag 注释）——
 * `/diag`、`window.__JCY_DIAG__`、`/sdcard/Pictures/jcy_diag.txt`。
 */
class MainActivity : BridgeActivity() {

    // 后台线程写、主线程读（onDestroy），必须 volatile 保证可见性，
    // 否则 onDestroy 可能读到 null → 桥不停止 → 端口/线程泄漏。
    // 名字避开 BridgeActivity.getBridge()（那是 Capacitor 的 Bridge，用于取 WebView）。
    @Volatile
    private var httpBridge: JcyBridgeServer? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        registerPlugin(JcyCorePlugin::class.java)
        super.onCreate(savedInstanceState)

        Diag.fact("android_sdk", Build.VERSION.SDK_INT)
        Diag.fact("abis", Build.SUPPORTED_ABIS.joinToString(","))
        runCatching {
            Diag.fact("webview_ua", android.webkit.WebSettings.getDefaultUserAgent(this).take(80))
        }

        setupDiagSink()
        startBridge()
        startDiagPump()
    }

    /**
     * 选择诊断落盘位置。
     *
     * 首选公共 Pictures 目录 —— 它与宿主机
     * `C:\Users\haige\Documents\leidian14\Pictures` 双向共享，宿主机可直接读全文。
     * Android 9（API 28，雷电 14 的版本）写这里需要 WRITE_EXTERNAL_STORAGE 运行时授权；
     * 拒绝则回落到 App 私有外置目录（宿主机读不到，但仍走另外两条出口）。
     */
    private fun setupDiagSink() {
        val pub = File(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES),
            "jcy_diag.txt",
        )
        val priv = File(getExternalFilesDir(null) ?: filesDir, "jcy_diag.txt")

        if (Build.VERSION.SDK_INT <= 28 &&
            checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED
        ) {
            runCatching { requestPermissions(arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE), REQ_STORAGE) }
        }

        // 先试公共目录（写一次空内容探测权限），失败则用私有目录
        val pubOk = runCatching { pub.parentFile?.mkdirs(); pub.writeText(""); pub.canWrite() }
            .getOrDefault(false)
        Diag.setSink(if (pubOk) pub else priv)
        Diag.fact("diag_priv_sink", priv.absolutePath)
        if (!pubOk) Diag.line("JcyDiag", "公共 Pictures 目录不可写（未授权？），诊断落到私有目录")
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_STORAGE) {
            Diag.line("JcyDiag", "WRITE_EXTERNAL_STORAGE 授权结果: ${grantResults.joinToString()}")
            setupDiagSink()
        }
    }

    /**
     * 启动顺序：**先把 HTTP 桥立起来，再加载 libcore**。
     *
     * 这是本版最重要的修复。旧顺序是「load → init → 起桥」，而 init 在真机上
     * 要等满 20 s 超时才返回，于是：
     *   t=0.0s  WebView 挂载 → React Query 立刻发首批 /api 请求
     *   t=0..20s 桥还没监听 → 全部 ECONNREFUSED
     *   t≈11.6s React Query 的 5 次指数退避重试（0.8+1.6+3.2+6.0 s）耗尽 → 放弃
     *   t=20s   桥才起来 —— 但已经没人再来问了
     * 结果就是「接口请求不成功 / 数据加载不出来」的永久骨架屏。
     *
     * 现在桥先监听（<50 ms），前端第一批请求就能拿到 200；libcore 的加载与 init
     * 放到同一线程的后半段，就绪后把 [JcyBridgeServer.coreReady] 置 true，
     * /health 与 /debug 都会如实报出这个状态。
     */
    private fun startBridge() {
        Thread({
            // ---- 第一步：立桥。失败也要继续，把错误经 /diag 透出来 ----
            try {
                val s = JcyBridgeServer(JcyBridgeServer.PORT)
                s.start(NanoHTTPD_SOCKET_READ_TIMEOUT, false)
                httpBridge = s
                Diag.fact("bridge_port", s.listeningPort)
                Diag.fact("boot_bridge", "ok")
                Log.i(TAG, "本地桥已启动: http://127.0.0.1:${s.listeningPort}")
            } catch (t: Throwable) {
                Diag.fact("boot_bridge", "FAILED")
                JcyBridgeServer.bootError = "bridge: ${t.javaClass.simpleName}: ${t.message}"
                Diag.err(TAG, "本地桥启动失败", t)
                Log.e(TAG, "本地桥启动失败", t)
            }

            // ---- 第二步：加载 libcore 并建立会话态 ----
            try {
                JcyCore.load(applicationContext)
                // device_id 默认值与抓包样本一致；tcp 见 JcyCore.DEFAULT_TCP
                // （真值由 2026-10-08 从官方 App 运行内存中直接读出，
                //   见 research/reports/V30_init_json_groundtruth.md）
                val raw = JcyCore.init(
                    deviceId = "16613a7076284a15bc723d018bcd67e1",
                    // 必须与官方一致：Flutter 侧传的是 <dataDir>/files，
                    // **不是** <dataDir>/app_flutter/files。libcore 会在这个目录里
                    // 读写运行期状态，路径不对会让它的内部"server"起不来。
                    filesPath = filesDir.absolutePath,
                )
                JcyBridgeServer.initRaw = raw
                JcyBridgeServer.coreReady = true
                Diag.fact("boot_init", "ok")
                Log.i(TAG, "JcyCore 已初始化")
            } catch (t: Throwable) {
                Diag.fact("boot_init", "FAILED")
                JcyBridgeServer.bootError = "init: ${t.javaClass.simpleName}: ${t.message}"
                Diag.err(TAG, "JcyCore 初始化失败（桥仍在，接口将返回错误）", t)
                Log.e(TAG, "JcyCore 初始化失败（桥仍在，接口将返回错误）", t)
            }

            // ---- 第三步：自检一次，结果直接进诊断（省去再点一次 /debug）----
            // 走短超时：native 若挂死也不该把这条启动线程钉 60 s。
            runCatching {
                val cfg = JcyApi.request("GET", "/app/config", timeoutMs = 8_000)
                Diag.fact("selftest_config_code", cfg.opt("code"))
                Diag.fact("selftest_config_msg", cfg.opt("message"))
            }.onFailure { Diag.err(TAG, "自检 /app/config 失败", it) }
        }, "jcy-bridge-boot").apply { isDaemon = true }.start()
    }

    /**
     * 诊断泵：每秒落盘一次，并把全量诊断推进 WebView 的 `window.__JCY_DIAG__`。
     *
     * 推进 WebView 这一步是**最兜底**的出口 —— 即使本地桥完全没起来
     * （WebView 拿不到 `/diag`），前端仍能读到启动阶段的 native 错误。
     */
    private fun startDiagPump() {
        Thread({
            var n = 0
            while (!Thread.currentThread().isInterrupted) {
                runCatching { Diag.flush() }
                if (n % 2 == 0) {
                    val wv = runCatching { getBridge()?.webView }.getOrNull()
                    if (wv != null) {
                        val js = "window.__JCY_DIAG__ = ${JSONObject.quote(Diag.dump())};"
                        runCatching { wv.post { wv.evaluateJavascript(js, null) } }
                    }
                }
                n++
                try {
                    Thread.sleep(1000)
                } catch (_: InterruptedException) {
                    return@Thread
                }
            }
        }, "jcy-diag-pump").apply { isDaemon = true }.start()
    }

    override fun onDestroy() {
        httpBridge?.stop()
        httpBridge = null
        super.onDestroy()
    }

    companion object {
        private const val TAG = "JcyBridge"
        private const val REQ_STORAGE = 1001
        private const val NanoHTTPD_SOCKET_READ_TIMEOUT = 30_000
    }
}
