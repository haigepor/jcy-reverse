p = 'research/toolchain/emu_unwind.py'
lines = open(p, encoding='utf-8', newline='').readlines()

start = end = None
for i, l in enumerate(lines):
    if l.lstrip().startswith('if args.then_decrypt and body:'):
        start = i
    if start is not None and "e.logs[-8:]" in l:
        end = i
        break
assert start is not None and end is not None, (start, end)
blk = lines[start:end + 1]
rest = lines[:start] + lines[end + 1:]

anchor = None
for i, l in enumerate(rest):
    if l.startswith("if __name__ == '__main__':"):
        anchor = i
        break
assert anchor is not None
# 插到 __main__ 前的空行处, 保持块前有一个空行
ins = anchor
while rest[ins - 1].strip() == '':
    ins -= 1
new = rest[:ins] + ['\r\n'] + blk + rest[ins:]
open(p, 'w', encoding='utf-8', newline='').writelines(new)

import ast
ast.parse(open(p, encoding='utf-8').read())
print('moved to line', ins, '+ syntax ok')
