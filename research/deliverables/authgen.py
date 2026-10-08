# -*- coding: utf-8 -*-
"""authgen.py — 囧次元 ``authentication`` 头离线生成器（CLI + Unicorn 后端）。

算法与纯逻辑部分在 :mod:`jcy_protocol.auth`；本模块只负责**注入 ``E`` 的实现**
（以 Unicorn 执行 libcore.so 原函数）并提供命令行入口。

    authentication = CUSTOM_B64( E( CUSTOM_B64( S ) ) )

用法::

    ./.venv/Scripts/python.exe research/deliverables/authgen.py --selftest
    ./.venv/Scripts/python.exe research/deliverables/authgen.py --ts 1790755350520
    ./.venv/Scripts/python.exe research/deliverables/authgen.py --test-server

依赖：``research/artifacts/`` 下的 ``libcore.so`` + ``libcore_dev_img.bin`` +
``regions_min/``（28.6 MB，由 ``toolchain/probe_regions.py`` 统计得出）。
"""
from __future__ import annotations

import argparse
import os
import random
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RESEARCH = os.path.dirname(HERE)
ROOT = os.path.dirname(RESEARCH)
TOOLCHAIN = os.path.join(RESEARCH, "toolchain")
for _p in (os.path.join(ROOT, "src", "tools"), TOOLCHAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jcy_protocol import auth as A          # noqa: E402
from jcy_protocol.auth import (             # noqa: E402  (re-export 便于旧调用)
    ALPHABET, APPID_HEADER, APP_VERSION, AES_IV, AES_KEY, CLIENT_APPID,
    CODE_VERSION, CT0, STD_B64, build_input, custom_b64, custom_b64d,
    split_body,
)

#: 当前设备实例的指纹（取自 ``research/artifacts/`` 的设备镜像；随安装实例变化）
DEVICE_FP = "16613a7076284a15bc723d018bcd67e1"

# libcore.so 中的关键地址
DEV_BASE = 0x400024a00000
OFF_PIPE = 0x304eb0          # auth 编码管线入口
OFF_AFTER_A1 = 0x304fb8      # A1 返回处（补丁点）
OFF_AFTER_E = 0x3050fc       # E 返回处（取样点）


def _pipe_input_from_a1(a1: bytes) -> bytes:
    """由 A1 反解出管线输入串 ``S``（``A1 = CUSTOM_B64(S)``）。

    管线 ``0x304eb0`` 的 x0 必须是长度 78 的输入串（它决定 A1 向量的长度）；
    我们随后会用正确的 A1 覆盖其输出，因此这里只需保证长度与内容自洽。
    """
    return custom_b64d(a1.decode())


class UnicornESession:
    """复用一个 Unicorn 实例连续计算多次 ``E``（批量核验用）。

    堆占用约 106 KB/次；接近上限时自动重建实例。
    """

    def __init__(self):
        self._cur = [None]
        self._out = {}
        self.boots = 0
        self._boot()

    def _boot(self):
        from unicorn import UC_HOOK_CODE
        from unicorn.arm64_const import UC_ARM64_REG_X29
        from emu_v14 import Emu4
        from emu_v11 import HEAP, HEAP_SIZE

        self._R_X29 = UC_ARM64_REG_X29
        self._HEAP = HEAP
        self._HEAP_SIZE = HEAP_SIZE

        e = Emu4()
        e.fix_long_string(0x688130, AES_KEY)
        self.e = e
        self.sret = e.alloc(0x40)
        e.wr(self.sret, b"\0" * 0x40)
        for a in (DEV_BASE + OFF_AFTER_A1, DEV_BASE + OFF_AFTER_E):
            e.uc.hook_add(UC_HOOK_CODE, self._hook, user_data=e, begin=a, end=a + 4)
        self.boots += 1

    def _hook(self, uc, address, size, ud):
        e = self.e
        x29 = uc.reg_read(self._R_X29)
        b, en, _cap = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        if address == DEV_BASE + OFF_AFTER_A1:
            if en - b == len(self._cur[0]):
                e.wr(b, self._cur[0])
        else:
            self._out["body"] = e.rd(b, en - b)

    def encrypt(self, a1: bytes) -> bytes:
        if self.e.heap_ptr > self._HEAP + self._HEAP_SIZE - 0x200000:
            self._boot()
        self._cur[0] = a1
        self._out.clear()
        inp = self.e.mkstr(_pipe_input_from_a1(a1))
        self.e.call(DEV_BASE + OFF_PIPE,
                    (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
                    sret=self.sret, timeout=120_000_000)
        body = self._out.get("body", b"")
        if len(body) != 112:
            raise RuntimeError("E 输出长度异常: %d" % len(body))
        return body


class UnicornE:
    """单次调用即新建模拟器实例（状态干净、结果可复现），约 4–6 秒。

    批量场景请复用 :class:`UnicornESession`。
    """

    def encrypt(self, a1: bytes) -> bytes:
        return UnicornESession().encrypt(a1)


# ---------------------------------------------------------------- 生成

def gen(ts: int, fp: str = DEVICE_FP) -> str:
    """生成 ``authentication`` 头（152 字符）。"""
    return A.generate(ts, fp, UnicornE())


def gen_parsed(ts: int, fp: str = DEVICE_FP) -> dict:
    """同 :func:`gen`，但返回解析后的结构（便于自检与调试）。"""
    return A.generate_parsed(ts, fp, UnicornE())


# ---------------------------------------------------------------- 服务器

def probe_server(ts: int, auth: str, nonce: str, path="/app/config", timeout=15):
    """用给定 auth 打真实服务器，返回 ``(status, reason, body)``。"""
    import http.client
    conn = http.client.HTTPConnection("43.145.33.254", 27990, timeout=timeout)
    hdrs = {
        "x-version": "2020-09-17",
        "user-agent": "Dart/3.6 (dart:io)",
        "appid": APPID_HEADER,
        "ts": str(ts),
        "accept-encoding": "identity",
        "authentication": auth,
        "tcs": "2",
        "content-type": "application/json; charset=utf-8",
        "nonce": nonce,
    }
    conn.request("GET", path, headers=hdrs)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, r.reason, data


# ---------------------------------------------------------------- CLI

SELFTEST_TS = 1790618586109
SELFTEST_O32 = bytes.fromhex(
    "2b3ef9d5b6c78fd91e33fb5136486918"
    "f70e50af61d497be95acdd0fd7ffae85")
SELFTEST_PREFIX24 = "6MsfEg71pCxZ4ipNACeen/VL"


def _selftest() -> int:
    ts = SELFTEST_TS
    print("ts            = %d" % ts)
    print("input         = %s" % build_input(ts, DEVICE_FP))
    t0 = time.time()
    auth = gen(ts)
    body = custom_b64d(auth)
    checks = [
        ("auth 长度 = 152", len(auth) == 152),
        ("body 长度 = 112", len(body) == 112),
        ("body[0:16] == ct0", body[0:16] == CT0),
        ("body[16:48] == O[0:32]", body[16:48] == SELFTEST_O32),
        ("头前 24 字符一致", auth[:24] == SELFTEST_PREFIX24),
    ]
    for name, ok in checks:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    print("耗时 %.1fs" % (time.time() - t0))
    ok = all(c[1] for c in checks)
    print("自检结果: %s" % ("PASS" if ok else "FAIL"))
    if not ok:
        print("  body[0:16]  =", body[0:16].hex())
        print("  body[16:48] =", body[16:48].hex())
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="囧次元 authentication 头离线生成器")
    ap.add_argument("--ts", type=int, default=None, help="毫秒时间戳，默认当前时间")
    ap.add_argument("--fp", default=DEVICE_FP, help="设备指纹")
    ap.add_argument("--selftest", action="store_true", help="对固化真机向量做回归自检")
    ap.add_argument("--test-server", action="store_true", help="生成后打真实服务器")
    ap.add_argument("--path", default="/app/config", help="--test-server 使用的端点")
    a = ap.parse_args()

    if a.selftest:
        return _selftest()

    ts = a.ts if a.ts else int(time.time() * 1000)
    t0 = time.time()
    auth = gen(ts, a.fp)
    print("ts        = %d" % ts)
    print("input     = %s" % build_input(ts, a.fp))
    print("auth (%d) = %s" % (len(auth), auth))
    print("耗时      = %.1fs" % (time.time() - t0))
    if a.test_server:
        nonce = "%08d" % random.randint(0, 99999999)
        st, rs, data = probe_server(ts, auth, nonce, a.path)
        print("--- 服务器实测 ---")
        print("GET %s -> %s %s  (%d 字节)" % (a.path, st, rs, len(data)))
        print("nonce = %s" % nonce)
        print("resp  = %r" % data[:160])
    return 0


if __name__ == "__main__":
    sys.exit(main())
