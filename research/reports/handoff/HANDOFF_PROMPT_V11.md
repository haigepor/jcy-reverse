# HANDOFF_PROMPT_V11 — 囧次元响应解密：模型定论与剩余工作

> 交接时间: 2026-10-02。接续 HANDOFF_PROMPT_V10。V10 的"K16→(key,iv) 公式"命题
> 已按实验证据**改判**：公式不存在，K16 不是 P1 密钥。本文档给出定论、证据索引、
> 以及唯一可行的剩余路线。纪律照旧（禁伪造结果、未执行要标注、MSYS_NO_PATHCONV=1、
> 大输出落盘只回传摘要）。

## 0. 一句话现状

请求链路完全可用（authgen 离线签名 + 重放 body → HTTP 200）；响应体 `<P0>.<P1>` 中
**P0 离线 100% 可解封出 K16**，但 **P1 的密钥 = 该请求的会话 key/iv（native 每请求
随机生成、只存在于 native key store），历史 134 条抓包离线不可解** —— 这是被 8 组
oracle + 3.7M 窗口内存扫描锁定的负结果，不要再试。

## 1. V11 已证实（全部有实验证据）

| # | 结论 | 证据 |
|---|---|---|
| 1 | 响应 P0 = RSA-2048 PKCS1-v1.5(pub_from_go, K16)，134/134 解封成功；K16 每响应换新 | `crib_scan.py`/`pad_scan.py` 输出 + live 回放 `live_check_resp.txt`(K16=3ME483VJDBQTEHD6) |
| 2 | P1 密钥 ≠ K16 及 rev/md5/md5hex/sha256 变换（CBC-PKCS7/crib-链/ECB/CTR/CFB/OFB/IV前后置/四种padding 全 0 命中） | `decrypt_response.py selftest`（可复跑） |
| 3 | P1 密钥 = 请求会话 key/iv；native 生成 | emu: `api_encrypt` 触发 `RAND_bytes(buf,16)`；key store 空 → `api_decrypt` 纯回显 |
| 4 | key 生成在 native（非 Dart Random） | RAND_bytes 挂钩命中 + 镜像字符串区 `/dev/urandom`；旧"getRandomString 固定种子"假设作废 |
| 5 | key store: pthread_rwlock 保护，`clear_key` 清空 | emu clear_key 前后 api_encrypt 行为翻转（2000 ↔ 空 200） |
| 6 | native api_encrypt 信封 = `{"action":"api_encrypt","payload":{"data":"<params JSON 串>","path":...}}`；data 必须字符串，对象→type_error 且库内无 catch 必崩 | emu `--pshape` 四形状扫描（datakey 通，其余崩） |
| 7 | emu api_encrypt 走完 RAND 后报 `{"code":400,"status":2000}`：缺服务端 RSA 公钥（init 解析器只读 CoreLog/device_id/code_version，无 pub 字段） | `emu_enc_dk*.log` + init 解析器字符串 xref |
| 8 | 镜像内嵌串 'Ee&AVzdgru^$hX%j'/'M0KylhhHyj1HZ&Mi'/'WonrnVkxeIxDcFbv'/'ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv' 不是会话密钥 | 全组合 key×iv×模式 0 命中；三个 `==`-blob 解出自定义 b64 → APK 签名 SHA1（对应 apk_sign 动作） |
| 9 | 内存 dump（pair/p_*.bin, 50MB, 与抓包同会话）不含会话 key | 3.7M 可打印 16B 窗口 × 双块可打印 oracle 0 命中（`pad_oracle_scan.py` v3） |

工具链新增：`emu_unwind.py --action {api_encrypt,get_record,check,get_pid}
--pshape --clear-first --rec N`（rec 附带真实请求头；--clear-first 先调 clear_key）；
map-on-demand 未映射读零页兜底；`strstr` 桩容错（VPN 检测 'tun/ppp/wg' 读未初始化
状态崩溃 → 视为空串）。`get_record` 返回诊断列表（apk_sign/vpn 状态），非会话 key。

## 2. 交付物

- `research/deliverables/decrypt_response.py`（重写为 V11 模型）：
  `unwrap`（P0→K16，离线）/ `decrypt --key --iv`（P1→JSON）/ `pairs`（批量）/
  `selftest`（复跑负结果 oracle）。
- `docs/crypto/http-body.md`：新增 "V11 定论" 章节（模型 + 负结果表 + live 路线）。

## 3. 剩余工作（按优先级）

1. **服务端 RSA 公钥来源**（emu api_encrypt 打通的最后一块）：
   候选 = 服务端下发配置（GSignRuleData，注意 `/app/upgrade` 响应是明文 b64 配置但
   其明文无密钥）、Dart 侧传入 init、或镜像内另有混淆存放。
   打通后：emu 双调用闭环（api_encrypt 抓 key/iv → 真服务器 → api_decrypt 验证
   响应解密），即可在纯 emu 里出「key/iv + 响应明文」完整对。
2. **live hook 配方落地**：真机 frida hook EVP_EncryptInit_ex(+0x387da4) 过滤信封层
   （key==qPwC 跳过），得业务 key/iv → 喂 `decrypt_response.py decrypt`。
   （设备侧 iptables REDIRECT / frida-server / memdump 清理未执行，见 V10 §4.5。）
3. iv 生成点确认：emu 中 api_encrypt 只见一次 RAND(16B)；iv 可能固定/派生/第二次
   RAND（在 RSA 后才触发）。双调用闭环后自然解决。

## 4. 关键文件索引

- 解密器: research/deliverables/decrypt_response.py
- emu: research/toolchain/emu_unwind.py（V10 CFI 回退 + V11 多动作）
- 负结果脚本: research/captures/rsa_scan/{crib_scan,pad_scan,mode_scan,pair_iv,
  keystore_scan,pad_oracle_scan}.py
- emu 日志: research/captures/rsa_scan/emu_enc_*.log / emu_getrec2.log / emu_hdr_run.log
- live 回放: research/captures/rsa_scan/live_check.py + live_check_resp.txt
- 文档: docs/crypto/http-body.md（V11 定论节）
