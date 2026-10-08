// jcy_core_jni.c — JNI 桥：在 ARM64 上直接加载 libcore.so，暴露 init / call
//
// ============================ 签名（已由 libapp.so 反汇编定案）============================
//
//   void call(const char* b64, const char* (*cb)(void* ctx, const char* result));
//   void init(const char* json, const char* (*cb)(void* ctx, const char* result));
//
// 1) call 的入参是 base64(AES-128-CBC-PKCS7(json))：
//        key "qPwClBj7j7ZQraSm" / iv "p3JdVQl3q7WQJIgG"
//    这两个密钥**只存在于 libapp.so**（Dart 侧），libcore.so 里没有 ——
//    即 AES 包装是 Dart 做的，native 负责解开。证据：
//      libapp.so:0x715844 dartCallback 在 0x715874/0x71588c 从对象池
//      pp+0x1b838 / pp+0x1b840 取这两个串，配合 AESMode 构造 Encrypter。
//
// 2) **回调的参数顺序：(result, ctx)，x0 是载荷。**
//    ⚠ 此处曾是本工程最大的一个坑：libapp.so:0x715af8 的 Dart 侧闭包声明为
//    `(dynamic, Pointer<Utf8>) => Void`，静态看起来像 (ctx, result)，据此写成
//    (ctx, result) 后真机直接 SIGABRT。2026-10-08 用 logcat 实证推翻：
//        callback #1: a0=0x400020ac8eac(b64=0) a1=0x7617dd670000(b64=1,len~96)
//    —— x0 指向的是随机二进制，x1 才是 96 B 的 base64 串。
//    误把 ctx 句柄当字符串交给 NewStringUTF 会立刻 abort：
//        "input is not valid Modified UTF-8: illegal continuation byte 0x3"
//    因此 jcy_callback() **不假设顺序**，两个参数各探一次，
//    谁像 base64 谁就是 result（兼容未来 ABI 变化）。
//
// 3) **回调的返回值必须是合法 JSON。** Dart 侧 dartCallback 的收尾是
//    jsonEncode({"code":400}) → toNativeUtf8 → return（见 0x71593c–0x715974）。
//    返回非 JSON（尤其是野指针）会直接把 native 打崩。
//
// 4) **init 的 JSON 缓冲必须长期有效。** Dart 侧用
//    Utf8Encoder + MallocAllocator（pp+0x380 / pp+0x7140）分配后**从不释放**；
//    而 init 入口 thunk（libcore.so:0x2fdc24）第一条就是
//    `str x0, [x9, x8]` —— 把入参指针**存进全局**。因此不能用
//    GetStringUTFChars + ReleaseStringUTFChars（JNI 缓冲会在 g_init 返回后失效）。
//
// 在 Android 上无需任何 shim：libcore.so 依赖的 bionic 符号系统原生提供。

#include <jni.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <android/log.h>

#define TAG "JcyCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// 回调的两个参数在**静态层面无法定死**：libapp.so 的 Dart 侧声明是
// `(dynamic, Pointer<Utf8>) => Void`（暗示 x0=ctx / x1=result），但 2026-10-08
// 真机实证相反 —— x0 才是 base64 载荷。所以这里如实声明为两个 void*，
// 由 jcy_callback() 在运行时按「谁像 base64 谁就是 result」判定。
// 返回值 x0 会被 native 读取并当作 JSON 解析 —— 必须返回合法 JSON。
typedef const char *(*jcy_cb_fn)(void *a0, void *a1);
typedef void (*jcy_call_fn)(const char *b64, jcy_cb_fn cb);
// init 的第二个参数在 Dart 侧是 #ffiClosure2（void (dynamic, Pointer<Utf8>)）。
// 即使 native 只取一个参数，多传一个也不会被读 —— 但少传一个可能让它去调野指针，
// 所以这里一律传回调（严格更安全）。
typedef void (*jcy_init_fn)(const char *json, jcy_cb_fn cb);

// call 等待回调的上限（毫秒）。超时即返回，绝不无限阻塞（避免 ANR）。
#define CALL_TIMEOUT_MS 60000

static void       *g_handle = NULL;
static jcy_call_fn g_call   = NULL;
static jcy_init_fn g_init   = NULL;

// init 的 JSON 缓冲：malloc 后**永不释放**，与 Dart 侧 toNativeUtf8() 的
// malloc-不-free 行为对齐（libcore 会把该指针存进全局，可能延后读取）。
static char       *g_init_json = NULL;

// 回调对 native 的应答。Dart 侧 dartCallback(0x715844) 与 reloadCallback(0x7484fc)
// 收尾都是同一段机器码：
//     71593c: ldr  x16, [pp+0x9088]   ; 键 "code"
//     715948: mov  x16, #0x190        ; ← 立即数
//     71594c: stur w16, [x0, #0x13]   ; 存进 map 值槽
// **0x190 是压缩指针模式下的 Smi**（Dart kSmiTag=0/kSmiTagSize=1 → 真实值 = imm>>1），
// 即真实值是 **200**，不是 400。两个回调都用同一个立即数 → 它是固定「成功」应答，
// 与载荷无关。早期版本写成 {"code":400} 等于每次都对 native 报失败。
// 返回非 JSON（尤其野指针）会直接把 native 打崩（nlohmann parse_error → abort）。
static const char  g_cb_reply[] = "{\"code\":200}";

// init 等待回调的上限（毫秒）。**0 = 完全不等待**。
//
// 真机（雷电 14 / Android 14 / Houdini 翻译 arm64）三轮冷启动实测：init **从未回调**
// （每轮日志都是 `init 未在 3000 ms 内回调（累计回调 0 次）`）。同一份 JSON 在
// 官方 App 里也是「不回调」的语义（Dart 侧 FFIUtils.init 忽略返回值、不等待），
// 因此 init 实际是**同步建立会话态**，回调只是可选的完成通知。
//
// 历史教训（两次，都是这个常量惹的祸）：
//   20 s 版：桥的启动线程被钉住 20 s，WebView 早已挂载并发出首批 /api 请求 ——
//            那 20 s 内全部 ECONNREFUSED，React Query 的 5 次指数退避重试在
//            ~11.6 s 内耗尽 → 界面永久停在骨架屏且不再自愈。
//    3 s 版：桥能在 ~1.4 s 起来了，但 init 仍占着 g_call_lock 整整 3 s。
//            前端首批请求（t≈+2.1 s 到达）被这把锁挡住，实测
//            `call(api_encrypt) ok：3112 ms` 里 **2854 ms 是在等锁**，
//            即 init 的 3 s 被 1:1 转嫁成首屏延迟（首个 code=20000 在 +6.1 s）。
//
// 现在设为 0：`g_init()` 同步返回即视为会话态就绪，立刻释放锁给前端请求。
#define INIT_TIMEOUT_MS 0

// 一次 native 调用的**全程锁**。
//
// libcore 的回调结果落在全局 g_result/g_done 上，且回调是在 libcore 内部线程里
// 触发的。若两个线程交错执行：
//     A: result_reset()            B: result_reset()
//     A: g_call()  ──┐             B: g_call()
//     A: result_wait() 立刻返回 ────┘  (g_done 已被 B 置 1)
//     A: result_take() → 拿到 **B 的结果**
// 即结果串包。Kotlin 侧 JcyApi 虽有 nativeLock 串行化，但 JcyCore.callRaw 是 public，
// JcyCorePlugin 通道与本机桥可能并发进入，所以这里必须自己兜住。
// 锁覆盖 reset → call → wait → take 全程；回调只需 g_lock（wait 期间已释放），不会死锁。
static pthread_mutex_t g_call_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cond = PTHREAD_COND_INITIALIZER;
static char           *g_result = NULL;
static int             g_done = 0;
static int             g_cb_count = 0;

// 「武装位」：只在 `result_reset()` → `result_take()` 之间为 1。
//
// 起因：INIT_TIMEOUT_MS 改为 0 后，init 不再等待回调就返回并释放锁。万一某个
// 机型/版本的 init **真的**会异步回调（本机实测从不回调，但换机不可假设），
// 那个迟到的回调会写进 g_result/g_done，污染紧随其后的首次 call 的结果。
// 有了这个位，窗口外的回调只记日志、不落结果。
static volatile int    g_armed = 0;

static void result_reset(void) {
    pthread_mutex_lock(&g_lock);
    free(g_result);
    g_result = NULL;
    g_done = 0;
    g_armed = 1;
    pthread_mutex_unlock(&g_lock);
}

static char *result_take(void) {
    pthread_mutex_lock(&g_lock);
    g_armed = 0;                       // 窗口关闭：之后的迟到回调一律丢弃
    char *out = g_result ? strdup(g_result) : NULL;
    pthread_mutex_unlock(&g_lock);
    return out;
}

// 等待回调；返回 0 = 已回调，非 0 = 超时。
static int result_wait(int timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += timeout_ms / 1000;
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }

    int rc = 0;
    pthread_mutex_lock(&g_lock);
    while (!g_done && rc == 0) {
        rc = pthread_cond_timedwait(&g_cond, &g_lock, &ts);
    }
    int done = g_done;
    pthread_mutex_unlock(&g_lock);
    return done ? 0 : (rc ? rc : -1);
}

// 把 native 回传的载荷安全地转成 jstring。
//
// 载荷按协议应是 ASCII base64，但**绝不能**假设如此：NewStringUTF 收到非法
// Modified UTF-8 会直接 SIGABRT 掉整个进程（真机上踩过一次 —— 见 jcy_callback 注释）。
// 这里先校验，只有纯可打印 ASCII 才原样返回；否则退化成空串并记日志，
// 让 Kotlin 侧走「解包失败」分支，而不是让 App 崩掉。
static jstring safe_new_string(JNIEnv *env, const char *s, const char *what) {
    if (!s) return (*env)->NewStringUTF(env, "");
    const unsigned char *p = (const unsigned char *)s;
    size_t n = strlen(s);
    for (size_t i = 0; i < n; i++) {
        if (p[i] < 0x20 || p[i] > 0x7e) {
            LOGE("%s 载荷含非 ASCII 字节（第 %zu B = 0x%02x，总长 %zu B）"
                 "—— 返回空串，避免 NewStringUTF 把进程 abort 掉",
                 what, i, p[i], n);
            return (*env)->NewStringUTF(env, "");
        }
    }
    return (*env)->NewStringUTF(env, s);
}

// 只读探测：判断 p 指向的内存看起来像 base64（用于诊断参数顺序，不参与逻辑）。
static int probe_b64(const char *p, int *out_len) {
    if (!p) return 0;
    int i;
    for (i = 0; i < 96; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c == 0) { if (out_len) *out_len = i; return i > 0; }
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
        if (!ok) { if (out_len) *out_len = i; return 0; }
    }
    if (out_len) *out_len = 96;
    return 1;
}

// 回调**真签名**（2026-10-08 真机实证，**推翻**此前基于 libapp.so 静态推断的 (ctx, result)）：
//
//     const char *cb(const char *result, void *ctx);
//
//   x0 = result —— base64(AES-128-CBC-PKCS7(json))，指向 libcore 内部缓冲；
//   x1 = ctx    —— libcore 侧的不透明句柄，**根本不是字符串**。
//
// 实证（logcat，修复 init 参数后 libcore 首次真正回调）：
//   callback #1: result=0x400020ac8eac(len~0,b64=0) ctx=0x7617dd670000(ctxb64=1,len~96)
//   —— x1 指向的内存前 96 B 全是 base64 字符；x0 指向的却是随机二进制。
// 早期按 (ctx, result) 取值 = 把句柄当字符串丢给 NewStringUTF，直接：
//   "input is not valid Modified UTF-8: illegal continuation byte 0x3" → SIGABRT
//
// 现在两个参数都探一遍，**谁像 base64 谁就是 result**（兼容 ABI 差异，双保险）。
static const char *jcy_callback(void *a0, void *a1) {
    int l0 = -1, l1 = -1;
    int b0 = probe_b64((const char *)a0, &l0);
    int b1 = probe_b64((const char *)a1, &l1);

    const char *result = NULL;
    void *ctx = NULL;
    const char *which = "?";
    if (b0 && !b1)      { result = (const char *)a0; ctx = a1; which = "x0"; }
    else if (b1 && !b0) { result = (const char *)a1; ctx = a0; which = "x1"; }
    else if (b0 && b1)  { result = (const char *)a0; ctx = a1; which = "both->x0"; }
    else                { result = NULL;             ctx = a1; which = "none"; }

    pthread_mutex_lock(&g_lock);
    g_cb_count++;
    int n = g_cb_count;
    int armed = g_armed;
    if (armed) {
        free(g_result);
        g_result = result ? strdup(result) : NULL;
        g_done = 1;
        pthread_cond_signal(&g_cond);
    }
    pthread_mutex_unlock(&g_lock);

    LOGI("callback #%d: 取 %s | a0=%p(b64=%d,len~%d) a1=%p(b64=%d,len~%d) -> reply %s%s",
         n, which, a0, b0, l0, a1, b1, l1, g_cb_reply,
         armed ? "" : "（窗口外，已丢弃）");
    if (result) {
        char head[65];
        int hn = l0 > 64 ? 64 : (l0 < 0 ? 0 : l0);
        if (which[0] == 'x' && which[1] == '1') hn = l1 > 64 ? 64 : (l1 < 0 ? 0 : l1);
        memcpy(head, result, (size_t)hn);
        head[hn] = '\0';
        LOGI("callback #%d 载荷头: %.64s", n, head);
    } else {
        LOGE("callback #%d 两个参数都不像 base64 —— 载荷形态变了，需要重新标定", n);
    }
    return g_cb_reply;
}

// ------------------------------------------------------------------ JNI

// nativeLoad(libDir): libDir 为 context.applicationInfo.nativeLibraryDir，可为 null
JNIEXPORT jboolean JNICALL
Java_app_video_guoguo_JcyCore_nativeLoad(JNIEnv *env, jclass clazz, jstring jlibDir) {
    (void)clazz;
    pthread_mutex_lock(&g_call_lock);
    if (g_handle) {                       // 幂等：已加载直接成功
        pthread_mutex_unlock(&g_call_lock);
        return JNI_TRUE;
    }

    const char *libDir = jlibDir ? (*env)->GetStringUTFChars(env, jlibDir, NULL) : NULL;

    char absPath[1024];
    absPath[0] = '\0';
    if (libDir && libDir[0]) {
        snprintf(absPath, sizeof(absPath), "%s/libcore.so", libDir);
    }

    // 优先按绝对路径加载；失败再退回 soname（依赖 app 默认命名空间的库搜索路径）。
    if (absPath[0]) {
        g_handle = dlopen(absPath, RTLD_NOW | RTLD_LOCAL);
        if (!g_handle) LOGE("dlopen(%s) 失败: %s", absPath, dlerror());
    }
    if (!g_handle) {
        g_handle = dlopen("libcore.so", RTLD_NOW | RTLD_LOCAL);
        if (!g_handle) LOGE("dlopen(libcore.so) 失败: %s", dlerror());
    }
    if (libDir) (*env)->ReleaseStringUTFChars(env, jlibDir, libDir);

    if (!g_handle) {
        pthread_mutex_unlock(&g_call_lock);
        return JNI_FALSE;
    }

    dlerror();
    g_call = (jcy_call_fn)dlsym(g_handle, "call");
    const char *e1 = dlerror();
    g_init = (jcy_init_fn)dlsym(g_handle, "init");
    const char *e2 = dlerror();

    if (!g_call) {
        LOGE("dlsym(call) 失败: %s", e1 ? e1 : "(null)");
        dlclose(g_handle);
        g_handle = NULL;
        pthread_mutex_unlock(&g_call_lock);
        return JNI_FALSE;
    }
    if (!g_init) {
        LOGI("dlsym(init) 未命中: %s（init 非必需）", e2 ? e2 : "(null)");
    }
    LOGI("libcore.so 已加载: handle=%p call=%p init=%p", g_handle, (void *)g_call, (void *)g_init);
    pthread_mutex_unlock(&g_call_lock);
    return JNI_TRUE;
}

// init：传 (json, cb)。
//
// **json 缓冲不能随 JNI 调用结束而失效**：init 入口 thunk（libcore 0x2fdc24）
// 第一条就是 `str x0, [x9, x8]`，把入参指针存进全局。Dart 侧同样用
// MallocAllocator 分配且永不释放。这里 strdup 到堆上并保留到进程结束。
JNIEXPORT jstring JNICALL
Java_app_video_guoguo_JcyCore_nativeInit(JNIEnv *env, jclass clazz, jstring jjson) {
    (void)clazz;
    pthread_mutex_lock(&g_call_lock);
    if (!g_init) {
        pthread_mutex_unlock(&g_call_lock);
        LOGE("init 未找到（dlsym 失败），先调用 nativeLoad()");
        return NULL;
    }

    const char *json = NULL;
    if (jjson) {
        json = (*env)->GetStringUTFChars(env, jjson, NULL);
        if (!json) {                      // 仅内存不足时发生
            pthread_mutex_unlock(&g_call_lock);
            LOGE("init 参数转换失败（OOM）");
            return NULL;
        }
    }

    // 复制到长期缓冲（malloc，永不 free）——与 Dart 侧行为一致。
    free(g_init_json);
    g_init_json = json ? strdup(json) : NULL;
    if (json) (*env)->ReleaseStringUTFChars(env, jjson, json);

    LOGI("init 入参(%zu B): %.200s", g_init_json ? strlen(g_init_json) : 0,
         g_init_json ? g_init_json : "(null)");

    result_reset();
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int cb_before = g_cb_count;
    g_init(g_init_json, jcy_callback);
    // INIT_TIMEOUT_MS == 0：init 是**同步**语义，g_init 返回即会话态就绪，
    // 立刻把 g_call_lock 交还给前端那批已经在排队的 /api 请求。
    // 万一某个机型真的异步回调了，`本次回调 N 次` 会在日志里直接暴露。
    int rc = (INIT_TIMEOUT_MS > 0) ? result_wait(INIT_TIMEOUT_MS) : 0;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (long)(t1.tv_sec - t0.tv_sec) * 1000L + (long)(t1.tv_nsec - t0.tv_nsec) / 1000000L;
    char *res = result_take();

    if (INIT_TIMEOUT_MS <= 0) {
        LOGI("init 同步返回：耗时 %ld ms，本次回调 %d 次（累计 %d 次）—— 不等待，立即交还调用锁",
             ms, g_cb_count - cb_before, g_cb_count);
    } else if (rc != 0) {
        LOGI("init 未在 %d ms 内回调（累计回调 %d 次，耗时 %ld ms）—— 视为同步 init，继续",
             INIT_TIMEOUT_MS, g_cb_count, ms);
    } else {
        LOGI("init 回调完成：耗时 %ld ms，结果 %zu B", ms, res ? strlen(res) : 0);
    }

    jstring out = safe_new_string(env, res, "init");
    free(res);
    pthread_mutex_unlock(&g_call_lock);
    return out;
}

// nativeCall / nativeCallTimeout 的公共实现。
//
// 注意 g_call_lock 覆盖 reset → g_call → wait → take 全程，因此**一次挂死的
// call 会让后续所有 native 调用静默阻塞**（连 "call 入参" 这行日志都打不出来，
// 因为日志在加锁之后）。真机排障时必须记住这一点：看到某次 call 没日志 =
// 它卡在 g_call_lock 上，而不是卡在 libcore 里。
static jstring do_native_call(JNIEnv *env, jstring jb64, int timeout_ms) {
    if (!jb64) {
        LOGE("call 收到 null 参数");
        return NULL;
    }
    pthread_mutex_lock(&g_call_lock);
    if (!g_call) {
        pthread_mutex_unlock(&g_call_lock);
        LOGE("call 未找到，先调用 nativeLoad()");
        return NULL;
    }

    const char *b64 = (*env)->GetStringUTFChars(env, jb64, NULL);
    if (!b64) {                           // 仅内存不足时发生
        pthread_mutex_unlock(&g_call_lock);
        LOGE("call 参数转换失败（OOM）");
        return NULL;
    }

    // call 的入参只在本次调用内被 native 使用（call 是同步执行到回调返回），
    // 但为稳妥起见同样复制一份到堆上，避免 native 内部线程延后读取。
    char *b64_heap = strdup(b64);
    (*env)->ReleaseStringUTFChars(env, jb64, b64);
    if (!b64_heap) {
        pthread_mutex_unlock(&g_call_lock);
        LOGE("call 参数复制失败（OOM）");
        return NULL;
    }
    LOGI("call 入参 %zu B: %.48s… (timeout=%d ms)", strlen(b64_heap), b64_heap, timeout_ms);

    result_reset();
    int cb_before = g_cb_count;
    struct timespec c0, c1;
    clock_gettime(CLOCK_MONOTONIC, &c0);
    g_call(b64_heap, jcy_callback);
    int rc = result_wait(timeout_ms);
    clock_gettime(CLOCK_MONOTONIC, &c1);
    long ms = (long)(c1.tv_sec - c0.tv_sec) * 1000L + (long)(c1.tv_nsec - c0.tv_nsec) / 1000000L;
    char *res = result_take();
    free(b64_heap);

    jstring out;
    if (rc != 0) {
        LOGE("call 超时（%d ms，实际 %ld ms）未收到回调（本次回调 %d 次，累计 %d 次）",
             timeout_ms, ms, g_cb_count - cb_before, g_cb_count);
        out = NULL;
    } else {
        LOGI("call 完成：耗时 %ld ms，回调结果 %zu B", ms, res ? strlen(res) : 0);
        out = safe_new_string(env, res, "call");
    }
    free(res);
    pthread_mutex_unlock(&g_call_lock);
    return out;
}

JNIEXPORT jstring JNICALL
Java_app_video_guoguo_JcyCore_nativeCall(JNIEnv *env, jclass clazz, jstring jb64) {
    (void)clazz;
    return do_native_call(env, jb64, CALL_TIMEOUT_MS);
}

// 带自定义超时的 call —— 诊断用（/probe）。
// 单次探测最多占用 timeoutMs，避免一个挂死的 action 把桥的请求线程池耗干。
JNIEXPORT jstring JNICALL
Java_app_video_guoguo_JcyCore_nativeCallTimeout(JNIEnv *env, jclass clazz, jstring jb64, jint timeout_ms) {
    (void)clazz;
    if (timeout_ms <= 0 || timeout_ms > CALL_TIMEOUT_MS) timeout_ms = CALL_TIMEOUT_MS;
    return do_native_call(env, jb64, timeout_ms);
}

JNIEXPORT void JNICALL
Java_app_video_guoguo_JcyCore_nativeUnload(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    pthread_mutex_lock(&g_call_lock);     // 与在途调用互斥，避免 dlclose 时仍有调用
    pthread_mutex_lock(&g_lock);
    free(g_result);
    g_result = NULL;
    g_done = 0;
    pthread_mutex_unlock(&g_lock);

    // 注意：g_init_json **不释放** —— libcore 持有该指针，卸载后其内部线程
    // 若再读取会造成 use-after-free。进程退出时由内核回收。
    if (g_handle) {
        g_call = NULL;
        g_init = NULL;
        dlclose(g_handle);
        g_handle = NULL;
        LOGI("libcore.so 已卸载");
    }
    pthread_mutex_unlock(&g_call_lock);
}
