import ast

p = 'research/toolchain/emu_unwind.py'
lines = open(p, encoding='utf-8', newline='').readlines()

# 1) rand_cb: 记录 K16 字节内容
for i, l in enumerate(lines):
    if "log('[RAND_bytes] buf=0x%x num=%d'" in l:
        lines[i] = l.replace(
            "log('[RAND_bytes] buf=0x%x num=%d' % (xs[0], xs[1]))",
            "log('[RAND_bytes] buf=0x%x num=%d' % (xs[0], xs[1]))\r\n"
            "        try:\r\n"
            "            _rb = rd(uc, xs[0], min(xs[1], 64))\r\n"
            "            if xs[1] == 16:\r\n"
            "                RAND_K16.append(_rb)\r\n"
            "                log('[RAND_K16] %s' % _rb.hex())\r\n"
            "        except Exception as _ex:\r\n"
            "            log('[RAND_K16] 读失败 %s' % _ex)")
        break
else:
    raise SystemExit('rand_cb not found')

# 2) 全局 RAND_K16 容器 — 挂在 CAPTURES 定义旁
for i, l in enumerate(lines):
    if l.startswith('CAPTURES = '):
        lines.insert(i, 'RAND_K16 = []\r\n')
        break
else:
    raise SystemExit('CAPTURES not found')

# 3) argparse: --scan-store
for i, l in enumerate(lines):
    if '--seed-store' in l and 'add_argument' in l:
        j = i
        while 'help=' not in lines[j]:
            j += 1
        lines.insert(j + 1,
            "    ap.add_argument('--scan-store', action='store_true',\r\n"
            "                    help='api_encrypt 后全堆/.bss 扫描 RAND 出的 K16 落点, 定位真会话 store')\r\n")
        break
else:
    raise SystemExit('argparse seed-store not found')

# 4) 退出前扫描: 放在 seed-store 块之前 (同区域)
for i, l in enumerate(lines):
    if 'if args.seed_store and K16:' in l:
        ins = i
        break
else:
    raise SystemExit('seed-store block not found')
scan = (
    "    if args.scan_store and RAND_K16:\r\n"
    "        k16b = RAND_K16[-1]\r\n"
    "        log('[scan-store] 目标 K16=%s' % k16b.hex())\r\n"
    "        regions = [(0x400024a00000 + 0x600000, 0x200000, 'img-data'),\r\n"
    "                   (0x50000000, 0x500000, 'heap')]\r\n"
    "        for sa, sl, nm in regions:\r\n"
    "            try:\r\n"
    "                buf = rd(e.uc, sa, sl)\r\n"
    "            except Exception as ex:\r\n"
    "                log('[scan-store] %s 读失败 %s' % (nm, ex))\r\n"
    "                continue\r\n"
    "            pos, hits = 0, 0\r\n"
    "            while hits < 12:\r\n"
    "                i = buf.find(k16b, pos)\r\n"
    "                if i < 0:\r\n"
    "                    break\r\n"
    "                pos = i + 1\r\n"
    "                hits += 1\r\n"
    "                a = sa + i\r\n"
    "                ctx = buf[max(0, i - 32):i + 48]\r\n"
    "                log('[scan-store] HIT %s @0x%x ctx=%s' % (nm, a, ctx.hex()))\r\n"
    "            if not hits:\r\n"
    "                log('[scan-store] %s 无命中' % nm)\r\n"
)
lines[ins:ins] = [scan]
open(p, 'w', encoding='utf-8', newline='').writelines(lines)
ast.parse(open(p, encoding='utf-8').read())
print('patched ok')
