# V13 响应加密方案定性（2026-10-03）

## 结论

```
响应体 P0.P1:
  P0 = RSA-2048 PKCS1-v1.5(pub_from_go, K16)   # 344 字符 custom-b64, priv_from_go.pem 离线可解
  P1 = CBC-E_b(key=K16raw, iv=reverse(K16), PKCS7-to-8B(明文JSON))   # custom-b64, f=恒等
```

- E_b：**8 字节块自研分组密码**，OLSVM 虚拟机解释执行（管线 0x304eb0，热点块
  0x2c6b48/0x2cdc80/0x2d2f0c/0x2e2f60-0x2e4144）。
- PKCS7 块大小=8：实证 205B JSON + `\x03`×3 = 208B（16B 块应 pad 11×`\x0b`）。
- K16 每响应独立随机（RSA P0 分发），key=K16 原文、iv=reverse(K16)。

## 证据

1. **块级配对**：pt287（`{"code":20000,...,"message":"","data":"DSXRV4G6…TVA"}` 205B+\x03×3）
   ↔ hit21 密文（K16=X8TEUA3DEXZNW2TN），E 预言机 `enc(pt, K16, rev(K16))` 输出与真实密文
   **前 64B（8×8B 块）逐块全等**。64B 后分叉系两种响应共享信封前缀、`"message"` 字段差异所致
   （`""` vs `"V6HZX"`，首差异字节 ≈69 落在块 8），非结构性分块。
2. **填充**：内存解密缓冲尾部 `\x03\x03\x03` → PKCS7-8（块 8）。
3. **真机 api_decrypt 解密实证**：frida 内存扫到返回信封
   `{"action":null,"code":200,"payload":{"data":"{\"code\":20000,…\"U9BYN5VR\"…}","status":0}}`。
4. **api_decrypt 真实入参**（watch_action_in/hits.jsonl）：
   `{<10 个随机 16 字符诱饵 kv>,"action":"api_decrypt","payload":{"data":"<P0.P1>","path":"<同data>"}}`。

## 排除清单（勿重试）

- 标准密码：AES-128/SM4/DES/3DES/Blowfish/CAST5/RC2/RC4（CBC/ECB ×
  K16raw/lower/rev/md5/md5hex16/sha256[:16]/通道钥/auth 钥 全 0 命中）。
- Blowfish 表扫描：镜像+堆+全 emu 内存（101MB）× 16 种布局变体（P/S 端序、块端序、交换）全 0 命中；
  导出 BF_set_key/BF_encrypt 挂钩 0 触发（管线内联自有实现）。libcore 0x200620 的 π 表属 BoringSSL。
- emu api_decrypt：同 handler 只回显/null、零密码学执行（RSA/EVP/E 管线钩全 0）；
  分叉区 ≈0x335544-0x337490（OLLVM 间接调用）。诱饵 kv 非决定因素。

## 剩余缺口

E_b 的逆（离线解密）。两条路：
1. 提升 0x304eb0 VM 里的 8B 块函数（工作量最大、一劳永逸）。
2. emu 强制进入解密分支（0x335xxx 分叉条件未明）。

替代方案（可用）：真机设备在环——内存 watcher 抓明文（15s GC 窗口），
或让 App 自解（relay 原样转发响应即可）。

## 工具

- E 加密预言机：`research/captures/rsa_scan/e_oracle.py`
- watcher：`research/toolchain/watch_plain.py` / `watch_action.py` / `watch_action_in.py`
- 配对数据：`tmp_pairs.json`（13 P0→K16）、`tmp_plains.json`（6 明文）、
  `tmp_proxybodies.json`（180 代理体）、`tmp_real_env.json`（真机完整入参信封）
