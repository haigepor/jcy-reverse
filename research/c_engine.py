#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""c_engine.py — jcy_engine.dll 的 ctypes 绑定,作为 Unicorn EOracle 的替代后端。

用途: 把 `decrypt_e.EDecryptor._enc_big` 的仿真换成 C 转译引擎 (快 ~2 个数量级)。
标定所需的逐块 x_b 现在不再 hook 0x2DA498 采集,改由 `jcy_calibrate` 直接调
引擎的 Cb/CONST 导出(见 jcy_export_tweak); 若引擎未导出该能力则回退标定。

ABI (dll_iface.c):
    jcy_init(image_path)                      -> int
    jcy_encrypt(k16, pt, ptlen, out, outcap)-> long
    jcy_last_error()                -> const char*
    jcy_version()                             -> const char*
    jcy_heap_stat(&n,&b,&big)
"""
from __future__ import annotations

import ctypes
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# 默认加载**基本块合并版** (--fuse, 25018 → 4401 基本块, 消掉 82.4% dispatch)。
# 实测 639 块标定 14535 ms → 3682 ms (3.95x), 且 2,180,018 条 PC trace
# 与 Unicorn 参考逐条一致、1/128/639 块 body 逐字节一致。
# 需要未合并基线时设环境变量 JCY_DLL 指向 jcy_engine.dll。
_DLL_CANDIDATES = ["jcy_fuse.dll", "jcy_engine.dll"]
_dll_pick = None
for _c in _DLL_CANDIDATES:
    _p = os.path.join(HERE, "engine_c", _c)
    if os.path.exists(_p):
        _dll_pick = _p
        break
DLL = os.environ.get("JCY_DLL") or _dll_pick or os.path.join(HERE, "engine_c", "jcy_fuse.dll")

_lib = None


def unload():
    """卸载 DLL 引用（换库重测时用）。

    注意：**同一进程内不能同时持有两份 jcy 引擎实例**。
    引擎的 REGP/RBASE/RSZ（镜像映射）与 JT（跳转表）是进程级全局，
    换 DLL 加载第二份会与之冲突。所以 benchmark 必须按「一个进程测一个库」
    组织，或用 subprocess 隔离。
    """
    global _lib, _dll_dir_handle
    _lib = None
    _dll_dir_handle = None


def loaded_path():
    """当前实际加载的 DLL 路径（benchmark 必须断言它== 想测的那个）。"""
    return getattr(_lib, "_name", None)
_dll_dir_handle = None


def load(dll_path: str = None):
    """加载 DLL (进程内单例)。"""
    global _lib, _dll_dir_handle
    #注意: 默认参数不能用 `dll_path=DLL` —— 默认值在 **函数定义时** 求值,
    # 之后改模块变量 DLL 也不生效, benchmark 换 DLL 会静默复用同一个 _lib。
    # (V21 实测踩过: 换DLL 重测耗时,两次都是同一个库,结论全是假的)
    if dll_path is None:
        dll_path = DLL
    if _lib is not None:
        return _lib
    dll_path = os.path.abspath(dll_path)
    if not os.path.exists(dll_path):
        raise FileNotFoundError(dll_path)
    # MinGW 运行时依赖 (libgcc_s_seh-1.dll / libwinpthread-1.dll) 与 DLL 同目录,
    # 但 Python 3.8+ 默认不搜索该目录, 必须显式 add_dll_directory 并持有句柄
    # (句柄被 GC 会导致后续 dlopen 失败)。
    if hasattr(os, "add_dll_directory"):
        _dll_dir_handle = os.add_dll_directory(os.path.dirname(dll_path))
    lib = ctypes.CDLL(dll_path)

    lib.jcy_version.restype = ctypes.c_char_p
    lib.jcy_version.argtypes = []

    lib.jcy_last_error.restype = ctypes.c_char_p
    lib.jcy_last_error.argtypes = []

    lib.jcy_init.restype = ctypes.c_int
    lib.jcy_init.argtypes = [ctypes.c_char_p]

    lib.jcy_encrypt.restype = ctypes.c_long
    lib.jcy_encrypt_iv.restype = ctypes.c_long
    lib.jcy_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint64,
                                ctypes.c_char_p, ctypes.c_uint64]

    lib.jcy_heap_stat.restype = None
    lib.jcy_heap_stat.argtypes = [ctypes.POINTER(ctypes.c_uint64)] * 3

    lib.jcy_encrypt_ex.restype = ctypes.c_long
    lib.jcy_encrypt_ex.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint64,
                                   ctypes.c_char_p, ctypes.c_uint64, ctypes.c_int]

    lib.jcy_capture_enable.restype = ctypes.c_int
    lib.jcy_capture_enable.argtypes = [ctypes.c_uint64]

    lib.jcy_capture_count.restype = ctypes.c_uint64
    lib.jcy_capture_count.argtypes = []

    lib.jcy_capture_get.restype = ctypes.c_int
    lib.jcy_capture_get.argtypes = [ctypes.c_uint64, ctypes.c_char_p]

    # ---- V22: 标定后处理下沉到 C (jcy_post.c) ----
    # 老 DLL 没有这些导出; hasattr 判一下, 没有就留给 Python 循环兜底。
    for _n in ("jcy_expand", "jcy_determine_C", "jcy_post"):
        if hasattr(lib, _n):
            getattr(lib, _n).restype = ctypes.c_int
    if hasattr(lib, "jcy_expand"):
        lib.jcy_expand.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    if hasattr(lib, "jcy_determine_C"):
        lib.jcy_determine_C.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                       ctypes.c_char_p]
    if hasattr(lib, "jcy_post"):
        lib.jcy_post.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                 ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                 ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]

    # ---- 2026-10-06: 解密主循环下沉到 C ----
    # split_timing.py 实测 639 块里纯 Python 解密占 1076 ms (28.4%),
    # 那是 639 次 F_inv(10 轮 SM4) 的解释开销, 无任何 ARM64 模拟。
    # 老 DLL 无此导出, hasattr 判一下, 缺失时由Python 循环兜底。
    for _n in ("jcy_decrypt", "jcy_finv"):
        if hasattr(lib, _n):
            getattr(lib, _n).restype = ctypes.c_int
    if hasattr(lib, "jcy_decrypt"):
        lib.jcy_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_uint64,
                                    ctypes.c_char_p, ctypes.c_char_p,
                                    ctypes.c_char_p, ctypes.c_char_p,
                                    ctypes.c_char_p]
    if hasattr(lib, "jcy_finv"):
        lib.jcy_finv.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

    _lib = lib
    return lib


def init(image_path: str) -> None:
    lib = load()
    rc = lib.jcy_init(image_path.encode())
    if rc != 0:
        raise RuntimeError("jcy_init 失败: %s" % lib.jcy_last_error().decode())


def encrypt(k16: bytes, pt: bytes, outcap: int | None = None) -> bytes:
    """E(k16, pt) → body。pt 长度须为 16 的非零倍数。"""
    lib = load()
    if len(k16) != 16:
        raise ValueError("K16 须 16 字节")
    outcap = outcap or (len(pt) + 16 + 64)
    buf = ctypes.create_string_buffer(outcap)
    n = lib.jcy_encrypt(k16, pt, len(pt), buf, outcap)
    if n < 0:
        raise RuntimeError("jcy_encrypt 失败(%d): %s" % (n, lib.jcy_last_error().decode()))
    return buf.raw[:n]


def encrypt_with_iv(k16: bytes, iv16: bytes, pt: bytes,
                    outcap: int | None = None) -> bytes:
    """E(k16, iv16, pt) → body。**可显式指定 iv**。

    decrypt_e._determine_C 需要 `iv =全零` 来标定常量 C，而 jcy_encrypt()
    把 iv 硬编码成 reverse(K) —— V21 之前没有这个导出，导致 C 后端算出的
    C 与 Unicorn 侧不一致（CONST 反而对，因为 CONST 只用 x_b）。
    """
    lib = load()
    outcap = outcap or (len(pt) + 16 + 64)
    buf = ctypes.create_string_buffer(outcap)
    n = lib.jcy_encrypt_iv(k16, iv16, pt, len(pt), buf, outcap)
    if n < 0:
        raise RuntimeError("jcy_encrypt_iv 失败(%d): %s"
                           % (n, lib.jcy_last_error().decode()))
    return buf.raw[:n]


def decrypt_blocks(P1: bytes, k16: bytes, C: bytes,
                   CONSTb: bytes, Cbb: bytes) -> bytes:
    """解密主循环的 C 版（2026-10-06 新增）。

    对齐 decrypt_e.EDecryptor.decrypt() 的循环体:
        for b in range(use):
            xb   = F_inv(xr(xr(ctb, C), Cb[b]), rk)
            prev = P1[b-1] if b else iv        # 密文链式
            out += xr(xr(xb, prev), CONST[b])

    **CONSTb / Cbb 必须是标定产物**，只依赖 k16，与本次 P1 无关 ——
    所以标定可跨请求复用，复用后单请求只剩这里的 nblk 次 F_inv。

    DLL 无 jcy_decrypt 导出时返回 None，由调用方落回 Python 循环。
    """
    lib = load()
    if not hasattr(lib, "jcy_decrypt"):
        return None
    nblk = len(P1) // 16
    buf = ctypes.create_string_buffer(nblk * 16)
    rc = lib.jcy_decrypt(P1, nblk, k16, C, CONSTb, Cbb, buf)
    if rc != 0:
        raise RuntimeError("jcy_decrypt 失败(%d): %s"
                           % (rc, lib.jcy_last_error().decode()))
    return buf.raw[:nblk * 16]


def finv(w: bytes, k16: bytes) -> bytes | None:
    """F_inv 单块（供 verify 对拍）。DLL 无导出时返回 None。"""
    lib = load()
    if not hasattr(lib, "jcy_finv"):
        return None
    buf = ctypes.create_string_buffer(16)
    if lib.jcy_finv(w, k16, buf) != 0:
        raise RuntimeError("jcy_finv 失败: %s" % lib.jcy_last_error().decode())
    return buf.raw[:16]


def heap_stat() -> tuple:
    lib = load()
    a, b, c = ctypes.c_uint64(), ctypes.c_uint64(), ctypes.c_uint64()
    lib.jcy_heap_stat(ctypes.byref(a), ctypes.byref(b), ctypes.byref(c))
    return a.value, b.value, c.value


def encrypt_with_x(k16: bytes, pt: bytes, nblk: int) -> tuple:
    """加密并捕获每块的 x_b(轮驱动 0x2da498 读回) → (body, [x_0..x_{nblk-1}]).

    这是 decrypt_e.calibrate 需要的量: Unicorn 侧在同一PC 挂 CODE hook 采集,
    C 侧由 hook_x() 完成, 两条路径的 x_b 必须逐位相同。
    """
    lib = load()
    rc = lib.jcy_capture_enable(nblk)
    if rc != 0:
        raise RuntimeError("jcy_capture_enable 失败: %s" % lib.jcy_last_error().decode())
    outcap = len(pt) + 16 + 64
    buf = ctypes.create_string_buffer(outcap)
    n = lib.jcy_encrypt_ex(k16, pt, len(pt), buf, outcap, 1)
    if n < 0:
        raise RuntimeError("jcy_encrypt_ex 失败(%d): %s" % (n, lib.jcy_last_error().decode()))
    got = lib.jcy_capture_count()
    # 真实命中数(V21 分档实测): nblk=1→2, 2→3, 4→5, 8→9, 32→33, 128→129, 639→640
    # 即 **nblk+1** 条 —— 轮驱动 0x2da498 在 C 引擎里**每块严格命中 1 次**。
    #
    # Unicorn侧同一PC 命中 2nblk+2 条(639→1280), 取 range(0,len,2) 偶数位得 nblk+1 条。
    # 那个「取偶数位」是 **Unicorn TB 重译的伪影**, 不是语义。V19 照抄它到 C 侧,
    # 而当时 C 侧恰好每块留 2 条, 于是「偶数位」正好对上 —— 纯属巧合。
    # V21 移除 C 侧 %2 去重后每块只 1 条, 必须**顺序取前 nblk 条**。
    if got < nblk:
        raise RuntimeError("捕获条数不足: 期望 >=%d 实得 %d (%s)"
                           % (nblk, got, lib.jcy_last_error().decode()))
    xs = []
    tmp = ctypes.create_string_buffer(16)
    for i in range(nblk):
        if lib.jcy_capture_get(i, tmp) != 0:
            raise RuntimeError("jcy_capture_get(%d) 失败" % i)
        xs.append(tmp.raw[:16])
    return buf.raw[:n], xs


if __name__ == "__main__":
    img = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "engine_c", "image128.bin")
    init(img)
    print("version:", load().jcy_version().decode())
    K = bytes(range(0x05, 0x15))
    body = encrypt(K, bytes(32))
    print("body %d 字节 前32 %s" % (len(body), body[:32].hex()))
    print("heap:", heap_stat())