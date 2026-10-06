import sys, re
from capstone import *
LIB = 'research/artifacts/device_libs/libapp.so'
data = open(LIB,'rb').read()
# 扫整个可执行段: 找 add xN, x27, #0x1d, lsl #12 ... ldr xM, [xN, #0xc10]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = False
# libapp 段布局: blutter_rt 地址=文件地址近似(旧构建), .text 大约 0x1c0000..0xd00000
# 扫描全文件 4 字节对齐的 add/ldr 组合 (机器码模式):
# add xN, x27, #hi, lsl #12 : 0x91xxxxxx  编码: sf=1 op=0 S=0 100010 sh=1 imm12 Rn Rn
# 直接搜编码: ADD (immediate) = 0x91000000 | (sh<<22) | (imm12<<10) | (Rn<<5) | Rd
import struct
TARGETS = {0x1dc10: 'api_decrypt', 0x1dd10: 'api_encrypt'}
hits = []
n = len(data)
for hi in range(0x0, 0x40):
    add_enc = 0x91000000 | (1 << 22) | (hi << 10) | (27 << 5)
    for lo, name in TARGETS.items():
        need_lo = lo - (hi << 12)
        if not (0 <= need_lo < 0x1000): continue
        # ldr xM, [xN, #need_lo] : 0xF9400000 | (need_lo//8 << 10) | (Rn<<5) | Rt
        for rn in range(0, 32):
            add_full = add_enc | rn
            a = struct.pack('<I', add_full)
            pos = data.find(a)
            while pos >= 0:
                # 检查后续 8 条指令内是否有 ldr [rn, need_lo]
                for k in range(1, 8):
                    off = pos + 4*k
                    w = struct.unpack('<I', data[off:off+4])[0]
                    if (w & 0xFFC00000) == 0xF9400000:
                        rn2 = (w >> 5) & 31
                        imm12 = ((w >> 10) & 0xFFF) * 8
                        if rn2 == rn and imm12 == need_lo:
                            hits.append((pos, hi, need_lo, name))
                            break
                pos = data.find(a, pos+4)
print('命中 %d 处:' % len(hits))
for pos, hi, lo, name in hits:
    print('  file@%x -> pp+%x (%s)' % (pos, (hi<<12)+lo, name))
