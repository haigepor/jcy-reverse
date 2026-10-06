# out/v9/brute/ 证据索引（V9 第三波 暴力代理）

判据修正（本波核心结论）：
- O = raw[16:112]（567/567 样本验证，位流等价）
- 但 char21∈T16(16字符表)/char149∈T4(4字符表) 使 O 的头 4bit（10/16 取值）与尾 2bit（{0,3}，1:3）被表量化
  （T4 组成预测 1/4:3/4 与观测 117:426 吻合）
- 故有效判据 = body 762bit 精确匹配（c[0]&0xF ‖ c[1:95] ‖ c[95]>>2）；全 96B 相等另记 full96=1
- 确定性：22 组重复 (ts,nonce) → 完全相同 O/b64；跨两条不同路径同 (ts,nonce) → 同 O
  ⇒ O = F(ts, nonce; key)，path 不参与，无每次调用随机性

文件：
- O_corpus.json          任务1：567 样本 O(96B hex)+f1/f2+char21/149+ts/nonce
- samples20.json / samples.bin  任务2 用 20 样本（norm 且有 nonce 的前 20）
- keys.bin / keys.txt / pp_strings.json  80,200 键候选（16,168 引号串+70,593 token+固定串，去重）
- brute.c / brute.exe    任务2 第一轮引擎（AES-NI+SM4+ChaCha20+SHA族+HMAC+HKDF；自测 11/11；阳性对照 4/4）
- brute_run.log          第一轮：2,742,983,390 组合，0 命中，406s
- brute2.c / brute2.exe  第二轮：+hex 字符串 KDF 5 形态、nonce 整数形态 IV、RC4/XXTEA/XTEA
- brute2_run.log / hits2.txt  第二轮：2,691,847,600 组合，0 命中，465s
  （两轮合计 5,434,830,990 组合，0 命中）
- brute_resp.c/.exe / resp_run.log  任务3：同池密钥 × AES-128/256 × ECB/CBC-iv0/CBC-ivC0/CTR-iv0
  × 15 个响应体；首块含'{'且可打印≥15/16 筛，全文可打印≥90% 确认；353,067,210 组合，144 筛通过全被拒，0 命中
- brute_mem.c/.exe / mem_run.log    任务4：dumps_mine3 4.58MB 滑窗 16B/32B × 模板A1 × 20 样本
  183,074,160 组合，0 命中
- resp_*.bin             resp_bodies.txt 解出的响应体（resp_5=27990 的 896B 主靶标）
- resp_config.bin        cap9.pcap frame206 (175.178.11.16:7862) data 字段 96B（b64 128ch，
  实测 128ch 非 108ch，首 8B 3b873f7e04377953）
- control.cjs / control_expected.json  端到端阳性对照（node 注入 4 键 → C 引擎 4/4 命中）
- f206_payload.hex       tshark 提取的 frame206 TCP 载荷
- crypt_common.h         共享已验证密码学原语（含 AES 等价逆密码解密）

自测向量：MD5/SHA1/SHA256/SHA512(abc)、HMAC-SHA256/512(RFC4231-TC2)、AES-128/256(FIPS-197)、
AES-CTR 进位、ChaCha20(RFC7539 §2.4.2)、SM4(GB/T 32907)、AES 解密往返(FIPS-197)
