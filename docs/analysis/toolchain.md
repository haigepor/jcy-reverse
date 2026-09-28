# 工具链构建手册

## 一、blutter (Flutter AOT 静态还原)

### 1.1 构建 (Windows)

```bat
git clone https://github.com/worawit/blutter
python scripts\init_env_win.py          :: 下载 capstone 4.0.2 + icu4c 73.2 到 external/, dll 到 bin/
:: 需要 VS Build Tools 2022 (MSVC) + cmake + ninja
call "C:\Program Files (x86)\Microsoft Visual Studio\VSBuildTools2022\VC\Auxiliary\Build\vcvarsall.bat" x64
```

**三个坑**:

1. **中文路径崩溃**: 工作区路径含 `囧次元` 时 cmake configure 直接 0xC0000409。
   解法: `mklink /J C:\blutter_w <中文路径>\tools\blutter` (junction)，全程在英文路径下构建。
   (PowerShell: `New-Item -ItemType Junction -Path C:\blutter_w -Target ...`)
2. **CodeAnalyzer 崩溃**: 完整模式对部分 snapshot 断言失败 (上游 issue 同类)。
   解法: 编译 **no-analysis 变体**:
   ```bat
   cmake -GNinja -B C:\blutter_w\build\blutter_noana -DDARTLIB=dartvm3.6.0_android_arm64 ^
     -DNAME_SUFFIX=_noana -DCMAKE_BUILD_TYPE=Release -DHAS_RECORD_TYPE=1 ^
     -DNO_METHOD_EXTRACTOR_STUB=1 -DUNIFORM_INTEGER_ACCESS=1 -DNO_CODE_ANALYSIS=1
   ninja -C C:\blutter_w\build\blutter_noana
   cmake --install C:\blutter_w\build\blutter_noana
   ```
   产物功能: 类/字段/函数地址+大小/对象池/字符串/frida 模板全有，仅无逐指令分析注解。
3. **bat 转义**: printf 写 .bat 会把 `\b`→退格、`\e`→ESC；用 heredoc (cat <<'EOF') 写。

### 1.2 运行

```bat
set PATH=C:\blutter_w\bin;C:\blutter_w\external\capstone;%PATH%
C:\blutter_w\bin\blutter_dartvm3.6.0_android_arm64_noana.exe -i C:\blutter_run\libapp.so -o C:\blutter_run\out
```

- 首次运行 blutter.py 会自动按 snapshot hash 下载对应 Dart SDK 源码并编译 (本例 Dart 3.6.0, ~10 分钟)
- 输入/输出路径也避免中文

### 1.3 产物与用法

```
out_noana/
├── pp.txt            对象池全量 (2.6MB) —— 挖密钥常量的主战场
├── objs.txt          类/对象信息
├── asm/              按库/文件组织的函数索引: "// ** addr: 0x..., size: 0x..."
├── ida_script/       IDA/Ghidra 导入脚本
└── blutter_frida.js  官方 frida hook 模板
```

**地址换算**: blutter 的 addr 是 libapp.so 内虚拟地址；
运行时地址 = `Module.findBaseAddress('libapp.so') + addr`。
与 reFlutter dump offset 的关系: `blutter_addr = 0x4b6b40 + dump_offset`
(0x4b6b40 = `_kDartIsolateSnapshotInstructions` 的 st_value)。

**对象池引用分析** (定位加密常量使用者):

```python
# 反汇编函数, 抓 ldr xN,[x27,#imm] 与 add+ldr 组合, 映射回 pp.txt 条目
# 见 docs 内示例: HeadersInterceptor → bl 0x7eee0c (apiEncrypt) 的发现过程
```

### 1.4 reFlutter dump 配合

```
reflutter base.apk → release.RE.apk (patched libflutter.so)
# Windows 大小写碰撞丢 res 文件 → 手术式重打包: 原 APK 逐条目复制 + 只换 libflutter.so
# 启动后 dump 落在 /data/data/<pkg>/dump.dart (权限 777, adb shell cat 直读)
```

dump 格式: 连续 JSON 对象 `{"method_name","offset","library_url","class_name"}`
offset 为相对 isolate instructions 起点；运行时地址 = base + 0x4b6b40 + offset。

## 二、frida gadget 集成 (无 root)

### 2.1 组合包制作

```
原始 base.apk 逐条目复制 (zip 重写)
├─ lib/arm64-v8a/libflutter.so  ← reFlutter patched (dump 能力)
├─ classes.dex                  ← gadget loader patch (loadLibrary("gadget"))
├─ lib/arm64-v8a/libgadget.so   ← frida gadget
├─ lib/arm64-v8a/libgadget.config.so  ← {"interaction":{"type":"listen","address":"127.0.0.1","port":27042,"on_load":"resume"}}
└── 其余条目原样
→ uber-apk-signer 重签 → 安装
```

脚本: `out/build_gadget_surgery.py`。

### 2.2 连接

```python
import frida
session = frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')
script = session.create_script(js)
```

```bash
adb forward tcp:27042 tcp:27042
```

### 2.3 运维要点 (血泪)

| 现象 | 处理 |
|---|---|
| create_script 超时 | gadget 每进程**仅一轮** script；用完/弄死即 `am crash` 重启 |
| `am force-stop` 无效 | EMUI unconfirm_app 管控态；用 `am crash com.tudou.tool` |
| app 起不来 | crash 后不会自启，需 am start；弹窗会重弹，先处理弹窗 |
| attach 后 libapp 为 null | 冷启动 25 秒内 libapp 未加载；JS 里轮询 findModuleByName |
| EMUI 双弹窗 (风险提示→移入管控) | 每次冷启动必弹；先勾"不再提示"再点"继续使用"/"取消" |
| 视频无网络请求 | 详情/播放有本地缓存，换没看过的视频 |

## 三、Dart 对象内存布局 (arm64, compressed pointers)

```
Dart 堆基址: 0x7100000000, 对象地址形如 0x7101xxxxxx

OneByteString (tags=e0 05 00 00):
  +0  tags (u32)
  +4  hash (u32)
  +8  length Smi (u32, 值 = len << 1)
  +12 (pad)
  +16 data (ASCII/UTF-8)

frida 读取:
  var len = p.add(8).readU32() >>> 1;
  var s   = p.add(16).readByteArray(len);
```

**注意**: 堆前缀判断要覆盖 0x7100–0x712f (曾因 `===0x7100` 漏掉全部真实地址)。

## 四、地址换算速查

| 系统 | 值 | 互转 |
|---|---|---|
| blutter addr | libapp.so 内 vaddr (如 0xa3bc20) | 运行时 = base + addr |
| reFlutter dump offset | 相对 instructions 起点 (如 0x5850e0) | 运行时 = base + 0x4b6b40 + offset |
| ELF 符号 | `_kDartIsolateSnapshotInstructions` @0x4b6b40 | 两者桥梁 |

验证样例: `0xa3bc20 (TokenInterceptor._onRequest) - 0x4b6b40 = 0x5850e0` ✓
