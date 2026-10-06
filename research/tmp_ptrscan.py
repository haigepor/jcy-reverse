import struct

p = 'research/captures/rsa_scan/emu_heap_dump.bin'
blob = open(p, 'rb').read()
HEAP, HEAP_SZ = 0x50000000, 0x500000
data_base = 0x400024a00000 + 0x660000   # img .data/.bss 段基址
assert len(blob) == HEAP_SZ + 0x90000, len(blob)
heap_part = blob[:HEAP_SZ]
data_part = blob[HEAP_SZ:]

targets = [0x500025b0, 0x500028d8, 0x50003b40]
for t in targets:
    pat = struct.pack('<Q', t)
    print('=== target 0x%x ===' % t)
    for nm, part, base in (('heap', heap_part, HEAP), ('data', data_part, data_base)):
        pos, n = 0, 0
        while True:
            i = part.find(pat, pos)
            if i < 0:
                break
            pos = i + 1
            n += 1
            a = base + i
            # 长串对象形态: [cap|1][size][ptr] → ptr 在对象 +16
            pre16 = part[i - 16:i]
            pre8 = part[i - 8:i]
            post8 = part[i + 8:i + 16]
            tag = ''
            if len(pre8) == 8 and struct.unpack('<Q', pre8)[0] == 16:
                tag = ' <== 长串{cap,size=16,ptr} obj@0x%x' % (a - 16)
            if len(post8) == 8 and struct.unpack('<Q', post8)[0] == 16:
                tag = ' <== size 在后 obj@0x%x' % a
            print('  %s ptr@0x%x  pre16=%s post8=%s%s' % (nm, a, pre16.hex(), post8.hex(), tag))
        if n == 0:
            print('  %s 无引用' % nm)
