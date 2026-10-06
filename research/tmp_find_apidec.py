"""扫 .text 中对 api_decrypt 字符串(0x6898a2) 的 adr/adrp+add 引用, 定位 action 比较点/处理函数."""
import struct

IMG = open('research/tmp_img.bin', 'rb').read()
BASE = 0x400024a00000
TARGET = 0x6898a2          # 'api_decrypt'
TARGET_END = TARGET + 11

TEXT_LO, TEXT_HI = 0x2c0000, 0x690000   # 扫描范围 (含 dispatcher 0x307a38 附近)

hits = []
for off in range(TEXT_LO, TEXT_HI - 8, 4):
    w = struct.unpack_from('<I', IMG, off)[0]
    # adr xN, #imm  : 0b0 immlo 10000 immhi Rd  => (w & 0x9F000000) == 0x10000000
    if (w & 0x9F000000) == 0x10000000:
        immlo = (w >> 5) & 3
        immhi = (w >> 8) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        rd = w & 0x1F
        tgt = off + imm
        if TARGET <= tgt <= TARGET_END:
            hits.append((off, 'adr x%d' % rd, tgt))
    # adrp xN, #imm : (w & 0x9F000000) == 0x90000000
    elif (w & 0x9F000000) == 0x90000000:
        immlo = (w >> 5) & 3
        immhi = (w >> 8) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & 0x100000000:
            imm -= 0x200000000
        rd = w & 0x1F
        page = ((off) & ~0xFFF) + imm
        if page <= TARGET < page + 0x1000:
            hits.append((off, 'adrp x%d' % rd, page))

print('adr/adrp 命中 %d 处:' % len(hits))
for off, kind, tgt in hits:
    # 找其后 4 条指令里的 add x?, x?, #imm
    addinfo = ''
    for k in range(1, 5):
        if off + 4 * k + 4 > len(IMG):
            break
        w2 = struct.unpack_from('<I', IMG, off + 4 * k)[0]
        # add xD, xN, #imm12 : 1001000100 imm12 Rn Rd
        if (w2 & 0xFFC00000) == 0x91000000:
            imm12 = (w2 >> 10) & 0xFFF
            rn = (w2 >> 5) & 0x1F
            rd2 = w2 & 0x1F
            addinfo += ' | +4*%d: add x%d, x%d, #0x%x → 0x%x' % (k, rd2, rn, imm12, tgt + imm12 if kind.startswith('adrp') else tgt)
            break
    print('  0x%x %s → 0x%x%s' % (off, kind, tgt, addinfo))
