# -*- coding: utf-8 -*-
"""tmp_malloc_log.py — Python 侧 1 块运行的 malloc 桩日志 (与 C 引擎 MALLOC# 打印对照)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
sys.path.insert(0, os.path.join(HERE, "toolchain"))

import unicorn  # noqa: E402
from decrypt_e import EDecryptor, _b64len  # noqa: E402
from authgen import DEV_BASE, OFF_PIPE  # noqa: E402
import emu_v11  # noqa: E402

LOG = []
_orig = emu_v11.Emu._do_stub


def patched(self, nm, uc):
    if nm in ("malloc", "_Znwm", "_Znam", "_ZNSt6__ndk17operator newEm"):
        a0 = uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X0)
        LOG.append(("malloc", a0))
        print("PY-MALLOC#%d sz=%d" % (len(LOG), a0), flush=True)
    elif nm in ("calloc", "realloc"):
        LOG.append((nm, -1))
        print("PY-%s" % nm, flush=True)
    return _orig(self, nm, uc)


emu_v11.Emu._do_stub = patched
print("patched emu_v11.Emu._do_stub")

d = EDecryptor()
d._oracle()
o = d._o
s = o.s
e = s.e
uc = e.uc

K = bytes(range(0x05, 0x15))
iv = K[::-1]
PT = bytes(16)

L = next(c for c in range(1, len(PT) + 1) if _b64len(c) == len(PT))
s._cur[0] = PT
s._out.clear()
inp = e.mkstr(b"\x00" * L)
e.call(DEV_BASE + OFF_PIPE, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
       sret=s.sret, timeout=600_000_000)
body = s._out.get("body", b"")
print("body 前32:", body[:32].hex(), "mallocs:", len(LOG))
