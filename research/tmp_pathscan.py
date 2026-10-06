import struct

p = 'research/captures/rsa_scan/emu_heap_dump.bin'
blob = open(p, 'rb').read()
HEAP_SZ = 0x500000
heap = blob[:HEAP_SZ]
data = blob[HEAP_SZ:]
data_base = 0x400024a00000 + 0x660000

path = b'/app/video/device-base'
K16 = bytes.fromhex('5aa33015e4a3c82f230875b1e91c1013')

print('=== path 在 heap 中的落点 ===')
pos, n = 0, 0
while True:
    i = heap.find(path, pos)
    if i < 0:
        break
    pos = i + 1
    n += 1
    a = 0x50000000 + i
    print('heap @0x%x' % a)
    print('  前64: %s' % heap[max(0, i - 64):i].hex())
    print('  后96: %s' % heap[i + len(path):i + len(path) + 96].hex())
    if n >= 10:
        break
print('共', n)

print('=== path 在 .data/.bss 的落点 ===')
pos, n = 0, 0
while True:
    i = data.find(path, pos)
    if i < 0:
        break
    pos = i + 1
    n += 1
    a = data_base + i
    print('data @0x%x' % a)
    print('  前64: %s' % data[max(0, i - 64):i].hex())
    print('  后96: %s' % data[i + len(path):i + len(path) + 96].hex())
    if n >= 10:
        break
print('共', n)

# K16 与 path 同节点: 检查 K16 各落点前后是否有 path 指针
for t in (0x500025b0, 0x500028d8, 0x50003b40):
    off = t - 0x50000000
    seg = heap[off:off + 16]
    print('K16@0x%x 确认: %s' % (t, seg.hex()))
