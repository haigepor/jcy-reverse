import ast

p = 'research/toolchain/emu_unwind.py'
lines = open(p, encoding='utf-8', newline='').readlines()

# 摘除现有 scan 块
start = end = None
for i, l in enumerate(lines):
    if 'if args.scan_store and RAND_K16:' in l:
        start = i
    if start is not None and "log('[scan-store] %s 无命中' % nm)" in l:
        end = i
        break
assert start is not None and end is not None, (start, end)
blk = lines[start:end + 1]
del lines[start:end + 1]

# 放到 then_decrypt 块之前 (main 尾部, 调用之后)
anchor = None
for i, l in enumerate(lines):
    if 'if args.then_decrypt and body:' in l:
        anchor = i
        break
assert anchor is not None
lines[anchor:anchor] = blk
open(p, 'w', encoding='utf-8', newline='').writelines(lines)
ast.parse(open(p, encoding='utf-8').read())
print('scan block moved after call')
