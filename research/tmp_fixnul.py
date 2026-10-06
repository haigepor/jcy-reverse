import re
p = 'research/toolchain/emu_unwind.py'
b = open(p, 'rb').read()
idx = [m.start() for m in re.finditer(b'\x00', b)]
print('NUL total', len(idx))
for i in idx[:6]:
    print(repr(b[max(0, i - 40):i + 20]))
# 将源码里的真实 NUL 字节替换为转义序列 \x00 四个字符
b2 = b.replace(b'\x00', b'\\x00')
open(p, 'wb').write(b2)
print('replaced')
import ast
ast.parse(open(p, encoding='utf-8').read())
print('syntax ok')
