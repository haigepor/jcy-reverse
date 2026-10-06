import ast

p = 'research/toolchain/emu_unwind.py'
lines = open(p, encoding='utf-8', newline='').readlines()

# 1) argparse 加 --seed-store
for i, l in enumerate(lines):
    if '--then-decrypt' in l and 'add_argument' in l:
        # 在 then-decrypt 定义块之后插 (含 help 行)
        j = i
        while 'help=' not in lines[j]:
            j += 1
        lines.insert(j + 1,
            "    ap.add_argument('--seed-store', action='store_true',\r\n"
            "                    help='把离线解出的 K16resp/rev 写入 KS_KEY/KS_IV, 诱导 api_decrypt 走真解密分支')\r\n")
        break
else:
    raise SystemExit('argparse anchor not found')

# 2) alphabet-fix 块结束后、clear_key 之前插入 seed-store
for i, l in enumerate(lines):
    if "if args.clear_first and args.action == 'api_encrypt':" in l:
        ins = i
        break
else:
    raise SystemExit('clear_first anchor not found')
seed = (
    "    if args.seed_store and K16:\r\n"
    "        try:\r\n"
    "            e.wr(KS_KEY + 1, K16)\r\n"
    "            e.wr(KS_IV + 1, K16[::-1])\r\n"
    "            log('[seed-store] KS_KEY=%r KS_IV=%r' % (K16, K16[::-1]))\r\n"
    "        except Exception as ex:\r\n"
    "            log('[seed-store] 写入失败 %s' % ex)\r\n"
)
lines[ins:ins] = [seed]
open(p, 'w', encoding='utf-8', newline='').writelines(lines)
ast.parse(open(p, encoding='utf-8').read())
print('patched ok')
