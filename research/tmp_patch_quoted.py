p = 'research/toolchain/emu_unwind.py'
lines = open(p, encoding='utf-8', newline='').readlines()

hit = None
for i, l in enumerate(lines):
    if 'pl2 = {"action": "api_decrypt"' in l:
        hit = i
        break
assert hit is not None
old = lines[hit]
assert 'data": body' in old, old
lines[hit] = old.replace('{"data": body, "path": args.path}',
                         '{"data": json.dumps(body), "path": args.path}')
open(p, 'w', encoding='utf-8', newline='').writelines(lines)

import ast
ast.parse(open(p, encoding='utf-8').read())
print('patched line', hit + 1, '-> quoted data')
