# -*- coding: utf-8 -*-
"""tmp_g1_step4b.py — 认表：搜已知密码常量 + 精读直方图(16B)定位表访问模式。"""
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_PC  # noqa: E402
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

K = bytes(range(0x30, 0x40))
NBLK = 2

d = EDecryptor()
d.calibrate(K, NBLK)
d._o = None
d._uc = None
d._oracle()
uc = d._uc

# ---- 1) 全镜像搜常量
snap_mem = []


def on_snap(uc_, address, size, ud):
    if snap_mem:
        return
    for rbase, rend, _perms in uc_.mem_regions():
        sz = rend - rbase
        if sz > 64 * 1024 * 1024:
            continue
        try:
            snap_mem.append((rbase, sz, bytes(uc_.mem_read(rbase, sz))))
        except Exception:
            pass


h = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap, begin=DEV_BASE + 0x2D9AD4,
                end=DEV_BASE + 0x2D9AD4 + 3)
d._cap.clear()
d._enc_big(bytes(16 * NBLK), K, K[::-1])
uc.hook_del(h)

SIGS = {
    "AES_SBOX": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]),
    "AES_INV_SBOX": bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38]),
    "TE0_le": bytes([0xa5, 0x63, 0x63, 0xc6]),       # c66363a5 小端序
    "TE0_be": bytes([0xc6, 0x63, 0x63, 0xa5]),
    "SM4_FK": bytes([0xa3, 0xb1, 0xba, 0xc6]),       # a3b1bac6 big-endian 字节序
    "SHA256_K": bytes([0x42, 0x8a, 0x2f, 0x98]),
    "MD5_T1": bytes([0x78, 0xa4, 0x69, 0xd7]),       # d76aa478 le
    "CRC32": bytes([0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77]),
    "GF_MUL2": bytes([0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e]),
    "GF_MUL3": bytes([0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09]),
}
print("=== 已知常量命中 ===")
for base, sz, data in snap_mem:
    for nm, sig in SIGS.items():
        i = data.find(sig)
        while i != -1:
            print("  %s @ %#x (DEV+%#x)" % (nm, base + i, base + i - DEV_BASE))
            i = data.find(sig, i + 1)
            if i > sz:
                break

# ---- 2) 精读直方图（16B 桶，仅 rodata 区）+ 精写
rd_hist = Counter()
wr_hist = Counter()


def on_rd(uc_, access, address, size, value, ud):
    rd_hist[address & ~0xF] += 1


def on_wr(uc_, access, address, size, value, ud):
    wr_hist[address & ~0xF] += 1


ctx = None
mem0 = []


def on_snap2(uc_, address, size, ud):
    global ctx, mem0
    if ctx is not None:
        return
    ctx = uc_.context_save()
    for rbase, rend, _perms in uc_.mem_regions():
        s2 = rend - rbase
        if s2 > 64 * 1024 * 1024:
            continue
        try:
            mem0.append((rbase, s2, bytes(uc_.mem_read(rbase, s2))))
        except Exception:
            pass


h2 = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap2, begin=DEV_BASE + 0x2D9AD4,
                 end=DEV_BASE + 0x2D9AD4 + 3)
d._cap.clear()
d._enc_big(bytes(16 * NBLK), K, K[::-1])
uc.hook_del(h2)

uc.context_restore(ctx)
for base, size, data in mem0:
    try:
        uc.mem_write(base, data)
    except Exception:
        pass
uc.ctl_flush_tb()

h_rd = uc.hook_add(unicorn.UC_HOOK_MEM_READ, on_rd, begin=1 << 20, end=(1 << 47) - 1)
h_wr = uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_wr, begin=1 << 20, end=(1 << 47) - 1)
bound_fires = [0]


def on_stop(uc_, address, size, ud):
    bound_fires[0] += 1
    if bound_fires[0] >= 4:
        uc_.emu_stop()


h_stop = uc.hook_add(unicorn.UC_HOOK_CODE, on_stop, begin=DEV_BASE + 0x2DA498,
                     end=DEV_BASE + 0x2DA498 + 4)
d._cap.clear()
uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=120 * 1000000, count=3_000_000)

print("\n=== TOP 24 读 16B 桶（DEV 偏移） ===")
for addr, cnt in rd_hist.most_common(24):
    off = addr - DEV_BASE
    print("  DEV+%#x ×%d" % (off, off >= 0 and off < 0x800000 and off or 0))
print("\n=== TOP 16 写 16B 桶 ===")
for addr, cnt in wr_hist.most_common(16):
    print("  %#x (DEV%+#x) ×%d" % (addr, addr - DEV_BASE, cnt))

# 按区域聚合读
agg = Counter()
for addr, cnt in rd_hist.items():
    off = addr - DEV_BASE
    if 0 <= off < 0x300000:
        agg["rodata %#x~" % (off & ~0xFFFF)] += cnt
    elif 0x2cd000 <= off < 0x2ef600:
        agg["codegen"] += cnt
    elif 0x50000000 <= addr < 0x60000000:
        agg["heap"] += cnt
    else:
        agg["stack/other %#x~" % (addr & ~0xFFFFF)] += cnt
print("\n=== 读聚合 ===")
for k, v in agg.most_common(12):
    print("  %s ×%d" % (k, v))
