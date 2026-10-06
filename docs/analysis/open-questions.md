# 遗留问题与实验设计

## 1. HTTP 会话 key 的运行时获取 (最接近闭环的一步)

**问题**: P0/P1 用每请求随机会话 key, 静态无公钥无法离线构造; 解密响应需要同 key。

**已尝试**:
- hook `getRandomString @0x715cb0` onLeave → 失败 (返回值不在 x0 常规路径, access violation)
- apiDecrypt 参数 chase → key 不在参数里 (只有密文+URL)
- 堆邻扫描 (URL 对象旁 16 字符串) → 候选未命中

**可行方案 (按成本排序)**:

1. **FFIUtils 静态字段转储**: 会话 key 存于 FFIUtils 静态字段 (completer @0x115c /
   _#ffiCallback0 @0x1164 同区)。通过 frida 读 Dart 静态字段表 (isolate object store)。
2. **apiEncrypt.onEnter 深度 chase** (修好堆前缀 bug 后对 x0-x7 + 栈 400B 扫描):
   key 刚生成时必在寄存器/栈顶附近。
3. **Inline hook getRandomString 的 Random 调用点** (bl 0x5591e8): 在随机数产生处截获。
4. **native api_encrypt 断点**: libcore `call` 分发器 32KB 中 api_encrypt 分支的
   key 提取点 (需先在 32KB 反汇编中定位分支——libcore 数据段无 "api_encrypt" 字符串,
   action 比较可能走 hash/长度, 是个坑)。

## 2. RSA 公钥获取

**现状**: 内嵌搜索全灭 (libapp/libcore/libloader/assets, PEM/DER/b64 全格式)。

**判定**: 公钥由服务器经 `/app/config` 或 `/app/video/key` 下发, 客户端缓存。

**实验 (pm clear 首装)**:

```bash
adb shell pm clear com.tudou.tool     # 清数据 (token/缓存/公钥缓存全清)
adb shell am start -n com.tudou.tool/app.video.guoguo.SplashActivity
# 首装状态第一个 /app/config 请求:
#   - 请求可能明文/初始 key (无会话 key 可用)
#   - 响应含公钥 → 抓到即闭环
```

配合 hook: apiDecrypt (hex 转储) + HttpClient.post。首装响应的解密初始 key
预期为内置 (候选: kFGT 系 / qPwC 系 / config 前置交换)。

## 3. getRandomString 种子规则

play-connect 同参数 5 次 body 相同 ⇒ 随机序列确定。@0x715cb0 反汇编显示调用 Random 系列 stub。
两种可能:
- `Random(seed)` 固定 seed (seed 来自 ts/nonce 组合 → 可复算)
- `Random()` 但同毫秒内同序列 (dart:io Random 默认以时间播种)

实验: 同一秒内发两次同参数请求, body 若相同 → 时间播种 (秒级); 不同 → 固定 seed。

## 4. P1 长度非 16 倍数之谜

P1 长度样本 24/88/96/432/656/876 (均 %16∈{8,12})。可能:
- b64 变体 (URL-safe 无 padding) 造成长度差
- P1 = 长度前缀 + 密文 + 尾部签名
- RC4/ChaCha 流密码 (候选全扫未中, 但候选集可能不含真 key)

在会话 key 到手后自然消解 (明文对可解)。

## 5. 信令通道的完整指令集

目前仅观测 `get_app_info` (本地回调)。libloader call 的 32KB↔5.5KB 分发器中
还有其他 action (对应 FFIUtils 的 check/reload/getRecord/getCoreVersion 等方法)。
逐个触发 (对应 UI 操作) 可绘制完整本地 IPC 协议表。

## 6. 去广告版维护

research/base_adfree_final-aligned-debugSigned.apk 已交付 (15 方法 smali 补丁)。
若 app 升级, 重打流程: ROLLBACK.ps1 恢复基线 → apply_adfree_patch.py。
