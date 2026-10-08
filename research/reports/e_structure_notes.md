# 自研分组密码 E 轮结构静态重建与同轮函数可逆性评估

- 目标：`research/tmp_img.bin`（libcore.so 运行时镜像 8MB，基址 0x400024a00000，ARM64，OLLVM 混淆）
- 方法：capstone 静态反汇编 + OLLVM 派发链数值解析 + 布尔汤（MBA 布尔表达式）寄存器级机器仿真
- 仿真器：纯寄存器布尔汤解释器（mov/movk/and/orr/eor/bic/orn/mvn/add/lsl/lsr/bfxil），已在 4 个独立汤上交叉验证
- 所有"未证实"项均为静态不可判定或未读完，见 §7

## 1. 总体轮结构（指令级证实）

轮驱动 `0x2da498`（由 E 主体 0x2d6f78 经 Loop2 调用）：

```
0x2da4e4  f(sched, 0)            ; 取 key[0]（idx 0x72e8 → 0x2da918）
0x2da524  ARK(state, key0)       ; idx 0x72f0 → 0x2d52e0
0x2da52c  w27 = 1
循环 1..9（0x2da55c-0x2da624，cmp w27,#9）:
  0x2da580  SB(state)            ; idx 0x72f8 → 0x2d1f80
  0x2da5a8  SR(state)            ; idx 0x7300 → 0x2d2498
  0x2da5d0  MC(state)            ; idx 0x7308 → 0x2d30c4
  0x2da5e8  f(sched, r) → key[r] ; idx 0x72e8
  0x2da604  ARK(state, key[r])
最终轮（0x2da628-0x2da6c0）:
  0x2da64c  SB(state)
  0x2da674  SR(state)
  0x2da68c  f(sched, 0xa) → key[10]
  0x2da6c0  br x3 = ARK(state, key10)   ; 尾调用
```

**10 轮、11 个轮密钥，最终轮无 MixColumns —— 标准 AES-128 SPN 形态。**
所有轮函数经 `ldr xN,[0x671650]; ldr xM,[xN,idx]; add xM,xM,off; blr xM` 进入（off=0x7ade20b24d10fa7c）。

状态布局：4 行 × 4 字节；行对象为 std::string（24B），行访问器 0x2cf2a4 = `ldr x8,[x0]; mov w9,#0x18; madd x0,x1,x9,x8`（data+i*24），字节访问器 0x2ce58c/0x2cdc88 = `ldr x8,[x0]; add x0,x8,x1`（row.data+j）。

## 2. 轮函数四件套

### 2.1 SubBytes 0x2d1f80（语义已钉死）
```
0x2d2078  f(state, i)            ; 行选择
0x2d20a0  f(row, j) → &s[i][j]
0x2d20a8  ldrb w9, [x0]          ; b = s[i][j]
0x2d20bc  f(T, w9>>4)            ; T 的第 b>>4 行（x24 = arg0 = 密钥相关表 T）
0x2d2108  f(row_hi, w9&0xf) → &T[hi][lo]
0x2d2114  ldrb w23, [x0]         ; T[b>>4][b&0xf]
0x2d213c  strb w23, [x0]         ; s[i][j] = T[b]
```
**s[i][j] = T[s[i][j]]，普通 256 字节按全字节索引替换**（nibble 拆分即 16×16 行/列选择）。T = E 的 arg0 = KSA 输出表（§3）。

### 2.2 ShiftRows 0x2d2498（全展开，双射）
以列 j 为单位沿第一索引循环上移（0x2d24e0-0x2d2668 列1：s[0][1]←s[1][1]←s[2][1]←s[3][1]←旧s[0][1]；0x2d266c+ 列2 移 2；列 3 移 3；j=0 不动）：
`s'[i][j] = s[(i+j)%4][j]`。

### 2.3 MixColumns 0x2d30c4（部分证实）
外循环列 c=0..3（0x2d30f8 cset gt），每列读 s[c][0..3]（0x2d31c4/0x2d3208/0x2d3238/0x2d3284 ldrb），GF 调用 `F(ctx, 2, s0)`（0x2d32a8）、`F(ctx, 3, s1)`（0x2d32d0，ctx=arg0，idx 0x35f6），随后 4 个输出字节各由一个巨型 MBA 布尔汤算出，strb 写回点 0x2d36f8 / 0x2d3b2c / 0x2d3da8 / 0x2d42bc。
- 汤1（0x2d32d4-0x2d36bc，约 1000 条）：**穷举 256 验证 = 恒等(w19)** → 输出字节0 = F(ctx,2,s0) 的返回值
- 汤2（0x2d3744-0x2d3b28）内嵌一次 blr GF 调用；汤3/汤4 类似 —— 精确组合公式未证实
- GF 乘 0x2d2f20：Russian peasant（w20 累加器/w24 计数/w23=b 右移/tst w23,#1 条件进入累加汤；累加汤 0x2d303c-0x2d30c0 **65536 全验证 = acc^a**）；每轮 a = F(ctx,a)（0x2d2fe0 blr，经运行时填充派发表 [0x671510]）
- **xtime 双变体**：0x2d2f0c = `eor w0, w8(0x1b), w1, lsl #1`（无条件 ^0x1b，仅对 a≥0x80 正确）；0x2d2f18 = `lsl w0, w1, #1`（无约减）。全镜像 **bl 直调 0、条件分支 0、adrp+add 0、movk 物化 0、字面量池 0** —— 经运行时填充的派发表间接进入，静态不可判定走哪个（见 §7-1）

### 2.4 AddRoundKey 0x2d52e0（已证实）
两段：先 tmp[i][j] = rk[4i+j]（0x2d5418-0x2d5480，f(rk, w27+w25*4) 后 strb 到 tmp 行），再 state[i][j] ^= tmp[i][j]（0x2d55fc-0x2d5688 布尔汤，**65536 全验证 = XOR**，0x2d5688 strb w8,[x0]）。

## 3. KSA 0x2cd8b0（完整解码，Python 可直接复现）

```
0x2cd8d4  adr x9, #0x1dfc00            ; 源表 = 标准 AES S-box（256/256 吻合）
0x2cd8e8-0x2cd954  NEON ldp/stp 全 256B 拷到栈 sp+0x10，并写入 arg1（输出表）
loop1 0x2cd97c:  Kbuf(sp+0x110)[i] = key[i % keylen]
loop2 0x2cda90-0x2cdc44（i = w23, 0..0x100）:
  0x2cdad0  f(S, i) → &S[i]; ldrb → S[i]
  0x2cdaf0  f(Kbuf, i) → &K[i]; ldrb → K[i]
  0x2cdb08  j(w25) = S[i] + j_prev + K[i]（0x2cdb18 and x21, w25, #0xff → j）
  0x2cdb58  swap(&Kbuf[i], &S[j])        ; idx 0x51f5 → 0x2cdca0
             ; 0x2cdca0 = ldrb/strb 对换 —— 与标准 RC4 的 swap(S[i],S[j]) 不同！
  0x2cdb74  ldrb w8 = S[j]（交换后的新值）
  0x2cdb78-0x2cdc14  g-布尔汤（256 全验证）
  0x2cdc20  strb w8 → S[j] = g(S[j])
```
- **g(x) = x ⊕ 0x66**（双射仿射：g[0]=0x66、低/高半字节各 ^6、bit7 线性；机器仿真 256/256 + 结构验证）。*此前会话手推的"g 非双射 16 值坍缩"结论错误，已被机器仿真推翻。*
- 循环头 0x2cda68 仅首入执行（尾部 dispatch 直接回 0x2cda90），j 累加保持；j 模 256 与标准 RC4 等价。
- **T 非置换（决定性）**：按上述语义 Python 仿真，500/500 个随机 16B 密钥的输出表 distinct ∈ [220,229] < 256（测试密钥 'X8TEUA3DEXZNW2TN' → 221）。原因：swap(Kbuf[i], S[j]) 把密钥字节注入 S、把 S 值挤出到 Kbuf，多值碰撞不可避免。

## 4. 可逆性结论（任务4）

| 组件 | 双射性 | 证据 |
|---|---|---|
| SubBytes (T) | **非单射** | T = KSA 输出，500/500 密钥非置换（§3） |
| ShiftRows | 双射 | 0x2d2498 循环移位结构 |
| MixColumns | 条件未证实 | GF 乘是否双射取决于 xtime 分支（§7-1）；矩阵公式未读完 |
| AddRoundKey | 双射 | XOR，65536 全验证 |

**结论：E 的同轮函数结构上不可逆** —— 决定性因素是 SubBytes 的替换表 T 非单射（KSA 的 Kbuf↔S[j] 交换变体所致），与镜像内无解密代码、逆 S 盒零引用一致。注意：T 非单射不妨碍"E_{K'}(y)=x"式密钥变换解密（tmp_keyrel.py 的 Feistel 判据仍可运行），但**不存在**逐字节可直接求逆的 D。

附带发现：0x1e03b0 并非完整逆 S-box —— 仅前 16 字节与标准逆盒吻合，其余全零（distinct=108），为残表/占位；镜像内唯一的完整逆盒是 BoringSSL 自用的 0x1ea5d8（E 未引用）。

## 5. 指针搜索（任务2）

全镜像 0x0-0x800000 搜 8 字节小端绝对指针：
- `0x400024abe3b0`（逆 S 盒 0x1e03b0）：**0 命中**
- `0x400024abdc00`（正 S 盒 0x1dfc00）：**0 命中**
- rel32 0x001e03b0：0 命中；rel32 0x001dfc00：1 命中 @0x179eab，上下文 `…00010400 [00fc1d00] 00000000…`，前后条目为 0x1dfb00/0x1dfc00/0x1dfd00 的 0x100 步进页元数据序列（页表巧合，非代码引用）

**不存在"逆表指针表"，无任何 E 解密路径证据。**

## 6. 纯 Python D 重建所需动态参数清单

已完备（可直接复现）：
1. 轮数 10；轮密钥 11 个（r=0 初始 + 1..9 + 10）
2. KSA 全语义 → T = KSA(key)（§3，含 g=x^0x66 与 swap 变体）
3. SubBytes：s[i][j] = T[s[i][j]]；ShiftRows：s'[i][j] = s[(i+j)%4][j]；AddRoundKey：state[i][j] ^= rk[4i+j]
4. 输入块提取 0x2d9ad4：blockidx*16（lsl w25,w9,#4）+ 0x55 填充；块数公式 0x2d8750（已部分解码）

未证实/需动态确认：
5. **xtime 分支**（0x2d2f0c vs 0x2d2f18）→ 决定 GF 乘语义与 MixColumns 可逆性
6. MixColumns 汤2-4 的精确组合公式（汤1 已穷举 = 恒等(w19)）
7. 轮密钥材料布局：0x2d9010 输出（size+0x40 字节：g2 变换拷贝 + memset 0x55 填充 + 0x1e0120[i] 派生 8B 项 + (i+buf[i%size])%7==0 重置 + 校验和链）与 0x2da918 取指的对应关系
8. 输入预处理 Loop1（0x2d7068-0x2d7394，state32[i&0x1f] = obf_mix(state32[i&0x1f], obj[i], i)）的精确混淆式
9. 输出链 0x2da6c4（4×4 转置式重排）/0x2d19ec（链接）/0x2cdeb4 的组包格式

**可行性评估：3-5 组已知 (P,C) + Unicorn 轨迹验证 = 可行且推荐。**
oracle（0x304eb0）已存在；一次 Unicorn 运行 hook 四个轮函数入口（0x2d1f80/0x2d2498/0x2d30c4/0x2d52e0）dump (state, T, rk) 即可同时闭合 §6-5/6/7/8/9 全部未证实项，随后纯 Python 复现 E 并与 oracle 对拍。

## 7. 未证实项与残余缺口

1. xtime 分支目标：静态不可判定（派发表运行时填充，快照槽位 0x671510/0x671528 为未填充/加密值）。两种情形的含义：走 0x2d2f0c（无条件 ^0x1b）→ GF 乘非双射（a 与 a^0x80 碰撞），MixColumns 亦非双射；走条件选择（a&0x80 区分）→ 标准 GF(2^8)，配合 MDS 矩阵则 MixColumns 双射。两变体共存本身暗示存在按 bit7 选择的两路派发。
2. MixColumns 汤2-4 公式、4 输出字节与 AES [2 3 1 1; …] 矩阵的对应关系未逐项验证。
3. 0x2da1c8 的 4×4 重排精确映射、0x2d19ec 链接格式、0x2d8750 块数公式细节、0x2da918 轮密钥取指内部 —— 均未逐条读完。
4. KSA 仿真未经 oracle 实测对拍（本任务只读镜像约束）；建议作为 Unicorn 验证第一步。
5. 0x21dc 处存在第二个 SubBytes 型函数（表在 arg0+0x48，带额外布尔汤），调用方未定位。

## 8. 关键地址速查

| 地址 | 角色 |
|---|---|
| 0x2d6f78 | E 主体（sub sp,#0x180 唯一帧） |
| 0x2cdeb4 | E 末段 glue（3-4 次调用 0x2ceb00 后 br 0x2cdfc4） |
| 0x2cd8b0 | KSA（S=AES Sbox@0x1dfc00；swap(Kbuf[i],S[j])；g=x^0x66） |
| 0x2da498 | 轮驱动（ARK0 → 9×[SB,SR,MC,ARK] → SB,SR,ARK10） |
| 0x2d1f80 / 0x2d2498 / 0x2d30c4 / 0x2d52e0 | SubBytes / ShiftRows / MixColumns / AddRoundKey |
| 0x2d2f0c / 0x2d2f18 / 0x2d2f20 | xtime(^0x1b) / xtime(<<1) / GF 乘（peasant） |
| 0x2cf2a4 / 0x2ce58c / 0x2cdca0 | 行访问器(×24) / 字节访问器 / 字节交换 |
| 0x2d9010 / 0x2da918 | 轮密钥材料构建 / 轮密钥取指 |
| 0x2d9ad4 / 0x2d9ed0 / 0x2da1c8 / 0x2da6c4 | 块提取 / NEON 合并 / 重排 / 输出重排 |
| 0x1dfc00 / 0x1dfd10 / 0x1e03b0 / 0x1ea5d8 | AES Sbox(标准) / Sbox 64B 副本 / 逆盒残表(前16B+零) / BoringSSL 逆盒 |
| 0x304eb0 | 加密 oracle 入口（Unicorn） |
