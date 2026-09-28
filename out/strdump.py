# -*- coding: utf-8 -*-
"""dump ±N lines around anchor strings in libapp_strings_full.txt"""
import re
import sys

anchor = sys.argv[1]
before = int(sys.argv[2]) if len(sys.argv) > 2 else 12
after = int(sys.argv[3]) if len(sys.argv) > 3 else 30

lines = open('libapp_strings_full.txt', encoding='latin1').read().splitlines()
hits = [i for i, l in enumerate(lines) if anchor in l]
print(f'# anchors for {anchor!r}: {len(hits)} -> {hits[:10]}')
for i in hits[:4]:
    print(f'----- hit line {i} -----')
    for j in range(max(0, i - before), min(len(lines), i + after)):
        mark = '>>' if j == i else '  '
        print(f'{mark}{j}: {lines[j]}')
