package app.video.guoguo

import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Date
import java.util.Locale

/**
 * Diag —— 进程级诊断日志。
 *
 * ## 为什么需要它
 * `libcore.so` 的加载/初始化/每次 `call` 失败时只打 logcat；而雷电模拟器的 adb 通道
 * 打不通（5555 未监听），真机上一旦出错就是「首页永远骨架屏」，完全无从定位。
 * 这里把**启动关键路径 + 每次 native 调用 + 每次 HTTP 请求**全部记下来，并开三条
 * 互相独立的出口，任何一条活着都能拿到现场：
 *
 *  1. `GET /diag`（明文文本）—— 桥活着时 WebView 可 fetch；
 *  2. `evaluateJavascript` 写 `window.__JCY_DIAG__` —— **桥死了也能看见**（最兜底）；
 *  3. 落盘 `/sdcard/Pictures/jcy_diag.txt` —— 该目录与宿主机
 *     `C:\Users\haige\Documents\leidian14\Pictures` 双向共享，可直接读全文。
 *
 * 内存里只留最后 [MAX] 行，dump 时再截尾，避免长时间运行吃内存。
 */
object Diag {

    private const val TAG = "JcyDiag"
    private const val MAX = 4000
    private const val DUMP_TAIL = 400

    private val fmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
    private val lines = Collections.synchronizedList(ArrayList<String>())

    /** 启动阶段的结构化事实（dump 时置顶打印，一眼看出卡在哪一步）。 */
    private val facts = Collections.synchronizedMap(LinkedHashMap<String, String>())

    @Volatile private var sink: File? = null

    /** 记录一条结构化事实。 */
    fun fact(key: String, value: Any?) {
        val v = value?.toString() ?: "null"
        facts[key] = v
        line("FACT", "$key = $v")
    }

    /** 记录一行日志（同时进 logcat）。 */
    fun line(tag: String, msg: String) {
        val s = "${fmt.format(Date())} [$tag] $msg"
        Log.i(TAG, s)
        synchronized(lines) {
            lines.add(s)
            if (lines.size > MAX) lines.subList(0, lines.size - MAX).clear()
        }
    }

    fun err(tag: String, msg: String, t: Throwable? = null) {
        val s = "${fmt.format(Date())} [$tag] !! $msg" + (t?.let { " | ${it.javaClass.simpleName}: ${it.message}" } ?: "")
        Log.e(TAG, s, t)
        synchronized(lines) {
            lines.add(s)
            if (lines.size > MAX) lines.subList(0, lines.size - MAX).clear()
        }
    }

    /** 设置落盘目标（可多次调用，后设的生效）。 */
    fun setSink(f: File?) {
        sink = f
        if (f != null) fact("diag_sink", f.absolutePath)
    }

    fun sinkPath(): String? = sink?.absolutePath

    /** 把当前内容写盘（尽力而为，永不抛）。 */
    fun flush() {
        val f = sink ?: return
        runCatching {
            f.parentFile?.mkdirs()
            f.writeText(dump())
        }
    }

    fun dump(): String = buildString(2048) {
        append("=== 启动事实 ===\n")
        synchronized(facts) { facts.forEach { (k, v) -> append(k).append(" = ").append(v).append('\n') } }
        val tail = synchronized(lines) { lines.takeLast(DUMP_TAIL) }
        append("\n=== 日志（共 ").append(synchronized(lines) { lines.size }).append(" 行，显示尾部 ").append(tail.size).append("）===\n")
        tail.forEach { append(it).append('\n') }
    }
}
