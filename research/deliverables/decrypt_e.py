# -*- coding: utf-8 -*-
"""decrypt_e.py — 囧次元自研分组密码 E 的离线解密交付物。

    decrypt(P1: bytes, K16: bytes) -> bytes

模型（已实测确认）
------------------
设 K = K16（16B），iv = K16[::-1]，E 为 16 字节分组密码：

    E(x) = T( SR( SB( AES9( T(x) ^ rk0 ) ) ) ) ^ C(K)

其中 T = 4x4 字节转置；AES9 = 标准 AES-128 前 9 轮；rk0..rk9 为标准 AES 密钥调度；
C(K) 为只依赖 K 的输出常量。

P1 = E 的分块加密结果（PKCS#7-16 填充），逐块关系：

    块 0 :  x_0 = pt_0 ^ iv                        ct_0 = E(x_0)
    块 b :  x_b = pt_b ^ ct_{b-1} ^ CONST_b        ct_b = E(x_b) ^ Cb_b   (b >= 1)

CONST_b / Cb_b 是仅依赖 (K, b) 的逐块 tweak（与明文、消息长度无关，已实测）。

解密（本模块实现）
------------------
  x_b = F_inv( ct_b ^ C(K) ^ Cb_b )      # F = E 去掉输出常量 C(K)
  pt_b = x_b ^ ct_{b-1} ^ CONST_b        # b=0 时 ct_{-1} := iv
  末块去 PKCS#7。

逐块 tweak 的**闭式生成公式尚未还原**（libcore 内 0x2d9ed0 为 OLLVM 展平，
含 NEON 位运算），因此本实现用**标定法**取得 CONST_b / Cb_b：
对同一 K 用 Unicorn 执行一次等长 dummy 加密，hook 轮驱动 0x2da498 读回每块
x_b，即得 CONST_b = x_b ^ dummy_b ^ ct_{b-1}、Cb_b = ct_b ^ F(x_b) ^ C(K)。
标定量仅依赖 (K,b)，故对任意密文成立。全流程离线（libcore.so + Unicorn，
无需设备/App/网络）。

已还原的结构（V15，实测全 22 项成立）
------------------------------------
    Cb_b = CONST_{b+1} ^ CONST_1        (b >= 0，CONST_0 = Cb_0 = 0)
即**输出 tweak 完全由输入 tweak 序列决定**，每块只剩一个独立未知量 CONST_b。
等价改写：X_0 = pt_0 ^ iv；X_{b+1} = pt_{b+1} ^ E(X_b) ^ CONST_1；
          ct_b = E(X_b) ^ CONST_{b+1} ^ CONST_1。
（CONST_b 本身仍是 (K,b) 的高熵函数：E⁻¹(CONST_b) 无结构、GF(2) 秩≈样本数，
 与 AES 扩展密钥、E(计数器) 等 40+ 候选均不匹配 → 生成器 0x2d9ed0 待逆。）

性能（V15）
----------
瓶颈在 Unicorn 仿真（≈106 万条指令/块，OLLVM 膨胀），纯 Python 求逆仅
0.0017 s/块。此前 v13.Emu3 在**全 8MB 镜像**上装了逐指令 UC_HOOK_CODE，
导致 QEMU 对每个 TB 插桩，标定 ≈0.54 s/块；移除后 ≈0.019 s/块（**28×**）。
真实样本端到端 450.5s → 9.2s（**≈49×**，明文逐字节一致）。
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(_HERE, "..", "toolchain"),
           os.path.join(_HERE, "..", "captures", "rsa_scan"),
           os.path.join(_HERE, "..", "..", "src", "tools")):
    _p = os.path.abspath(_p)
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------- 纯逻辑核心
_SO = open(os.path.join(_HERE, "..", "artifacts", "libcore.so"), "rb").read()
SBOX = _SO[0x1DFC00:0x1DFC00 + 256]
ISBOX = bytes(SBOX.index(i) for i in range(256))


def _xt(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


def expand(key):
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    rc = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rc
            rc = _xt(rc)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4 * r:4 * r + 4], [])) for r in range(11)]


def SB(s):
    return [SBOX[x] for x in s]


def ISB(s):
    return [ISBOX[x] for x in s]


def SR(s):
    o = [0] * 16
    for c in range(4):
        for r in range(4):
            o[4 * c + r] = s[4 * ((c + r) % 4) + r]
    return o


def ISR(s):
    o = [0] * 16
    for c in range(4):
        for r in range(4):
            o[4 * c + r] = s[4 * ((c - r) % 4) + r]
    return o


def MC(s):
    o = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        o[4 * c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        o[4 * c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        o[4 * c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
    return o


def IMC(s):
    o = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
        o[4 * c + 1] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
        o[4 * c + 2] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
        o[4 * c + 3] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
    return o


def T(s):
    o = [0] * 16
    for r in range(4):
        for c in range(4):
            o[4 * r + c] = s[4 * c + r]
    return o


def xr(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def F(x, rk):
    s = [a ^ b for a, b in zip(T(list(x)), rk[0])]
    for r in range(1, 10):
        s = MC(SR(SB(s)))
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(T(SR(SB(s))))


def F_inv(w, rk):
    """F 的逆（E 去掉输出常量 C(K) 后的逆）。"""
    s = ISR(ISB(T(list(w))))
    for r in range(9, 0, -1):
        s = xr(s, rk[r])
        s = ISB(ISR(IMC(s)))
    return bytes(T(xr(s, rk[0])))


def _b64len(n):
    return 4 * ((n + 2) // 3)


# ---------------------------------------------------------------- 标定
class EDecryptor:
    """标定 + 解密。可复用同一实例（按 K 缓存标定结果）。

    后端优先级: C 转译引擎 (jcy_engine.dll, 快 ~2 个数量级) → Unicorn (兜底)。
    设环境变量 JCY_BACKEND=unicorn 可强制走 Unicorn; JCY_IMAGE 可指定镜像。
    """

    def __init__(self, backend=None):
        self._o = None
        self._cache = {}          # (K, nblk) -> 标定产物(精确块数)
        self._base = {}           # K -> 该 K 已标定的**最大**块数产物(增量基线)
        self._inv_ok = {}         # K -> 该基线的不变式自检结果(复用时免重算)
        self.invariant_ok = None# V15 自检：Cb_b == CONST_{b+1} ^ CONST_1
        self.backend = backend or os.environ.get("JCY_BACKEND", "auto")
        self._c = None            # c_engine 模块
        self._c_ready = None      # None=未试 False=不可用 True=可用

    # ---------------------------------------------------------- C 引擎后端
    def _c_engine(self):
        """惰性加载 C 引擎。返回模块或 None（不可用）。"""
        if self._c_ready is False:
            return None
        if self._c_ready is True:
            return self._c
        try:
            here = os.path.dirname(os.path.abspath(__file__))
            research = os.path.dirname(here)
            if research not in sys.path:
                sys.path.insert(0, research)
            import c_engine
            img = os.environ.get("JCY_IMAGE") or os.path.join(
                research, "engine_c", "image639.bin")
            if not os.path.exists(img):
                img = os.path.join(research, "engine_c", "image128.bin")
            c_engine.init(img)
            self._c, self._c_ready = c_engine, True
        except Exception:  # noqa: BLE001
            self._c, self._c_ready = None, False
        return self._c

    def _calibrate_c(self, K, nblk):
        """用 C 引擎标定: 一次加密 dummy 全零明文, 取回逐块 x_b。

        x_b 的取法与 Unicorn 侧 hook 0x2DA498 完全一致 (轮驱动读回),
        因此两条后端产出的 CONST_b / Cb_b 应逐位相同。

        V22: 后处理(T/F/xr 循环)已下沉到 DLL 的 jcy_post, 639 块从
        200.8 ms 降到 <0.1 ms, 逐位一致(verify_post.py 已对拍1/8/128/639)。
        DLL 不可用时自动退回原 Python 循环。
        """
        c = self._c_engine()
        if c is None:
            return None
        ctd, xs = c.encrypt_with_x(K, bytes(16 * nblk), nblk)
        rk = expand(K)
        C = self._determine_C_c(c, K)
        iv = K[::-1]
        dummy = bytes(16 * nblk)

        # 优先走 C 后处理 (jcy_post 由 build_fuse.sh 链入; 老 DLL 没有该导出
        # 时 getattr 返回 None, 自动落回 Python 循环)
        # c 是 c_engine 模块本身(lib 由其 load() 单例持有), 故取模块级 lib。
        try:
            import c_engine as _ce
            post = getattr(getattr(_ce, "_lib", None), "jcy_post", None)
        except Exception:                   # noqa: BLE001
            post = None
        if post is not None:
            try:
                return self._calibrate_c_post(post, K, nblk, ctd, xs, dummy, iv, C, rk)
            except Exception:               # noqa: BLE001
                pass                        # 落回 Python 循环

        CONST, Cb = [], []
        for b in range(nblk):
            xb = bytes(T(list(xs[b])))          # 与 Unicorn 侧同一置换
            prev = ctd[b * 16 - 16:b * 16] if b else iv
            CONST.append(xr(xr(xb, dummy[b * 16:(b + 1) * 16]), prev))
            Cb.append(xr(ctd[b * 16:(b + 1) * 16], xr(F(xb, rk), C)))
        return C, rk, CONST, Cb

    def _calibrate_c_post(self, post, K, nblk, ctd, xs, dummy, iv, C, rk):
        """用 DLL 的 jcy_post 一次算完 CONST[]/Cb[]。

        xflat 必须是**连续的** nblk*16 字节 —— jcy_post 按 [b*16] 索引,
        不能喂Python 的 list-of-bytes。
        """
        import ctypes
        xflat = b"".join(bytes(x) for x in xs[:nblk])
        if len(xflat) != nblk * 16:
            raise RuntimeError("xflat 长度 %d != %d" % (len(xflat), nblk * 16))
        CO = ctypes.create_string_buffer(nblk * 16)
        Cb = ctypes.create_string_buffer(nblk * 16)
        rc = post(xflat, ctd, dummy, iv, C, K, nblk, CO, Cb)
        if rc != 0:
            raise RuntimeError("jcy_post rc=%d" % rc)
        # 必须按 16 字节切成 bytes 列表 —— list(buffer.raw) 得到的是**int 列表**,
        # 与原 Python 路径返回的 bytes 列表类型不同, 下游 xr()/F() 会炸。
        cob = CO.raw[:nblk * 16]
        cbb = Cb.raw[:nblk * 16]
        return (C, rk,
                [cob[b * 16:(b + 1) * 16] for b in range(nblk)],
                [cbb[b * 16:(b + 1) * 16] for b in range(nblk)])

    def _determine_C_c(self, c, K):
        # 必须显式传 iv=全零 —— c.encrypt() 的 iv 被硬编码成 reverse(K),
        # 而 C 的标定式C = ct ^ T(st10) 用的 ct 来自 **iv=0** 的那次加密。
        # (V21 实测: 用 reverse(K) 会让 C 与 Unicorn 侧不一致, 但 CONST 仍对 ——
        #  因为 CONST 只依赖 x_b, 不依赖 C。)
        ct = c.encrypt_with_iv(K, bytes(16), bytes(16))[:16]
        rk = expand(K)
        A0 = list(rk[0])
        G9 = A0
        for r in range(1, 10):
            G9 = MC(SR(SB(G9)))
            G9 = [a ^ b for a, b in zip(G9, rk[r])]
        st10 = SR(SB(G9))
        return xr(ct, bytes(T(st10)))

    def _oracle(self):
        if self._o is None:
            from e_oracle import EOracle  # 延迟导入（需 Unicorn）
            import unicorn
            from authgen import DEV_BASE
            from emu_v11 import HEAP, HEAP_SIZE
            from unicorn.arm64_const import UC_ARM64_REG_X1

            o = EOracle()
            self._DEV_BASE = DEV_BASE
            self._HEAP, self._HEAP_SIZE = HEAP, HEAP_SIZE
            self._uc = o.s.e.uc

            def _hook(uc_, address, size, ud):
                x1 = uc_.reg_read(UC_ARM64_REG_X1)
                b = struct.unpack("<Q", o.s.e.rd(x1, 8))[0]
                self._cap.append(
                    b"".join(o.s.e.rd(struct.unpack("<Q", o.s.e.rd(b + i * 24, 8))[0], 4)
                             for i in range(4)))

            self._cap = []
            self._uc.hook_add(unicorn.UC_HOOK_CODE, _hook,
                              begin=DEV_BASE + 0x2DA498, end=DEV_BASE + 0x2DA498 + 4)
            self._o = o
        return self._o

    def _enc_big(self, pt, key, iv, timeout=3_000_000_000):
        """EOracle.enc 的大超时版本（Unicorn timeout 单位 µs，默认 120s 不够长消息）。"""
        from authgen import OFF_PIPE, DEV_BASE
        # 堆重建守卫：会话堆接近上限时 mkstr 会静默失败 → 捕获截断、标定缺块。
        # （UnicornESession.encrypt 有同款守卫；本方法直接 call 所以自带一份。）
        if self._o is not None and self._o.s.e.heap_ptr > self._HEAP + self._HEAP_SIZE - 0x200000:
            self._o = None
            self._uc = None
            self._oracle()
        s = self._o.s
        s.e.fix_long_string(0x688130, key)
        s.e.fix_long_string(0x688148, iv)
        L = next((c for c in range(1, len(pt) + 1) if _b64len(c) == len(pt)), None)
        if L is None:
            raise ValueError("明文长度 %d 无法凑出" % len(pt))
        s._cur[0] = pt
        s._out.clear()
        inp = s.e.mkstr(b"\x00" * L)
        s.e.call(DEV_BASE + OFF_PIPE,
                 (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
                 sret=s.sret, timeout=timeout)
        return s._out.get("body", b"")

    def _determine_C(self, K):
        rk = expand(K)
        A0 = list(rk[0])
        G9 = A0
        for r in range(1, 10):
            G9 = MC(SR(SB(G9)))
            G9 = [a ^ b for a, b in zip(G9, rk[r])]
        st10 = SR(SB(G9))
        ct = self._enc_big(bytes(16), K, bytes(16))[:16]
        return xr(ct, bytes(T(st10)))

    def _check_invariant(self, CONST, Cb):
        """V15 不变式自检：Cb_b == CONST_{b+1} ^ CONST_1。

        用于探测引擎/模型回归；失败不影响解密（仅把 invariant_ok 置 False）。
        失败通常意味着标定只算出了部分块（Cb 长度 < CONST 长度），
        这时也要显式置 False 而不是静默通过。
        """
        self.invariant_ok = None
        try:
            n = min(len(CONST), len(Cb))
            if n >= 2:
                self.invariant_ok = len(CONST) == len(Cb) and all(
                    Cb[b] == xr(CONST[b + 1], CONST[1]) for b in range(n - 1))
        except Exception:  # noqa: BLE001
            self.invariant_ok = None
        return self.invariant_ok

    def calibrate(self, K, nblk):
        """返回 (C, rk, CONST[list], Cb[list])，nblk = 需要标定的块数。

        2026-10-06 增量标定（性能关键）
        --------------------------------
        CONST[b] / Cb[b] **只依赖 K16 和块序号 b**，与本次请求的明文/密文
        无关（见 decrypt() 的循环体：只有 prev 依赖前序密文）。所以：

          - 同一 K 下，标定到 N 块后，任何 <= N 的请求都**零引擎开销**。
          - 请求更大时只补算增量，不重跑全量。

        split_timing.py 实测：同 K 二次标定 639 块从 2938 ms 降到 0.0086 ms
        （34 万倍），这才是「跟 app 一致」的正解 —— App 侧K16 也是每会话
        一次，不是每请求一次。
        """
        # 1) 精确命中
        key = (K, nblk)
        if key in self._cache:
            return self._cache[key]

        # 2) 增量：同一 K 下若已标定的块数 >= 目标，直接切用（零引擎开销）
        #    不变式在**写入基线时**已自检并记入 _inv_ok[K], 复用路径直接取,
        #    不重算 —— 639 块的自检是 638 次 xr(约 1 ms), 不能放在热路径。
        base = self._base.get(K)
        if base is not None and len(base[2]) >= nblk:
            C, rk, CONST, Cb = base
            self.invariant_ok = self._inv_ok.get(K)
            out = (C, rk, CONST[:nblk], Cb[:nblk])
            self._cache[key] = out
            return out

        # 3) 需要扩到nblk 块。CONST/Cb 只依赖 K 与块序号, 与 P1 无关,
        #    所以一次算满 nblk 即可, 之后任何 <= nblk 的请求都零开销。
        need = nblk
        out = None
        if self.backend != "unicorn":
            try:
                out = self._calibrate_c(K, need)
            except Exception:               # noqa: BLE001
                out = None
                self._c_ready = False         # 标记 C 后端不可用, 后续走 Unicorn
        if out is None:
            out = self._calibrate_unicorn(K, need)
        C, rk, CONST, Cb = out
        # 防御：标定必须给满 nblk 块。少于则直接报错, 不能静默返回短数组——
        # 下游 decrypt() 会按use 索引 CONST/Cb, 短了会 IndexError 或更糟:
        # 用错的Cb[b] 解出错误明文且不报错(静默数据损坏)。
        if len(CONST) < nblk or len(Cb) < nblk:
            raise RuntimeError(
                "标定块数不足: 需要 %d, 得到 CONST=%d Cb=%d"
                % (nblk, len(CONST), len(Cb)))

        # V15 不变式自检：Cb_b == CONST_{b+1} ^ CONST_1 (b = 0..nblk-2)
        # 用于探测引擎/模型回归；失败不影响解密（仅置 False）。
        self._check_invariant(CONST, Cb)

        # 记为该 K 的基线：只保留**块数更多**的那份, 防止小请求覆盖大结果
        prev = self._base.get(K)
        if prev is None or len(CONST) > len(prev[2]):
            self._base[K] = (C, rk, CONST, Cb)
            self._inv_ok[K] = self.invariant_ok   # 供复用路径免重算
        else:
            C, rk, CONST, Cb = prev
            self.invariant_ok = self._inv_ok.get(K)
        self._cache[key] = (C, rk, CONST[:nblk], Cb[:nblk])
        return self._cache[key]

    def _calibrate_unicorn(self, K, nblk):
        self._oracle()
        C = self._determine_C(K)
        rk = expand(K)
        iv = K[::-1]
        dummy = bytes(16 * nblk)
        self._cap.clear()
        ctd = self._enc_big(dummy, K, iv)
        xs = [bytes(T(list(self._cap[i]))) for i in range(0, len(self._cap), 2)]
        if len(xs) < nblk:
            raise RuntimeError("标定不足: captured %d < nblk %d" % (len(xs), nblk))
        CONST, Cb = [], []
        for b in range(nblk):
            xb = xs[b]
            prev = ctd[b * 16 - 16:b * 16] if b else iv
            CONST.append(xr(xr(xb, dummy[b * 16:(b + 1) * 16]), prev))
            Cb.append(xr(ctd[b * 16:(b + 1) * 16], xr(F(xb, rk), C)))
        return C, rk, CONST, Cb

    def decrypt(self, P1, K16, blocks=None):
        """解密 P1。

        blocks=None → 全解；blocks=N → 只解前 N 块（标定也只做 N 块，秒级返回，
        用于快速看 code / 前几条数据；此时明文是**截断**的）。
        """
        if len(P1) == 0 or len(P1) % 16 != 0:
            raise ValueError("P1 长度须为 16 的非零倍数")
        nblk = len(P1) // 16
        use = nblk if not blocks or blocks >= nblk else int(blocks)
        C, rk, CONST, Cb = self.calibrate(K16, use)
        iv = K16[::-1]
        out = b""

        # 2026-10-06: 优先走 C 的解密主循环。
        # split_timing.py 实测 639 块纯 Python 解密占 1076 ms (28.4%),
        # 那是 639 次 F_inv(10 轮 SM4) 的解释开销, 里面**没有任何 ARM64 模拟**
        # —— 同样算式在 C 里是微秒级。老 DLL 无导出时自动落回 Python 循环。
        got = self._decrypt_c(P1[:use * 16], K16, C, CONST, Cb, use)
        if got is not None:
            out = got
        else:
            for b in range(use):
                ctb = P1[b * 16:(b + 1) * 16]
                xb = F_inv(xr(xr(ctb, C), Cb[b]), rk)
                prev = P1[b * 16 - 16:b * 16] if b else iv
                out += xr(xr(xb, prev), CONST[b])
        if use < nblk:
            return out          # 截断模式：不做 PKCS#7 去填充
        n = out[-1]
        if 1 <= n <= 16 and out[-n:] == bytes([n]) * n:
            out = out[:-n]
        return out

    def _decrypt_c(self, P1, K16, C, CONST, Cb, use):
        """调 C 的解密主循环。DLL 无导出/出错时返回 None（落回 Python）。"""
        c = self._c_engine()
        if c is None:
            return None
        try:
            return c.decrypt_blocks(
                P1, K16, C, b"".join(CONST[:use]), b"".join(Cb[:use]))
        except Exception:                   # noqa: BLE001
            return None


_DEC = None


def decrypt(P1: bytes, K16: bytes, blocks=None) -> bytes:
    """离线解密 P1（E 分块密文）到明文。"""
    global _DEC
    if _DEC is None:
        _DEC = EDecryptor()
    return _DEC.decrypt(P1, K16, blocks)


def decrypt_envelope(data_field: str, K16: bytes) -> bytes:
    """data_field = "<P0_b64>.<P1_b64>"（自定义 base64），解出 P1 明文。"""
    from jcy_protocol.auth import custom_b64d
    p1_b64 = data_field.split(".", 1)[1]
    return decrypt(custom_b64d(p1_b64), K16)


if __name__ == "__main__":
    import json
    HERE = _HERE
    pairs = json.load(open(os.path.join(HERE, "..", "tmp_pairs.json")))
    d = EDecryptor()
    ok = bad = skip = 0
    for e in pairs:
        if not e.get("k16"):
            continue
        P1 = bytes.fromhex(e["p1_hex"])
        if len(P1) % 16 != 0:
            print("hit=%-4s SKIP 截断样本 p1_len=%d (非16倍数)" % (e["hit"], len(P1)))
            skip += 1
            continue
        got = d.decrypt(P1, e["k16"].encode())
        good = got[:1] == b"{" and got[-1:] == b"}"
        ok += good
        bad += (not good)
        print("hit=%-4s K=%s len=%-5d json=%s %r" % (e["hit"], e["k16"], len(got), good, got[:70]))
    print("RESULT ok=%d bad=%d skip=%d" % (ok, bad, skip))

    # 真实信封样例 (tmp_real_env.json)
    envp = os.path.join(HERE, "..", "tmp_real_env.json")
    if os.path.exists(envp):
        env = json.load(open(envp))
        got = decrypt_envelope(env["payload"]["data"], b"T9Z19J7NCY9S9X58")
        print("envelope len=%d json=%s %r" % (len(got), got[:1] == b"{", got[:90]))
