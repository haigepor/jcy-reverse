#!/usr/bin/env python3
"""emu_dec_scan.py - 真机格式信封基线: 全程块 trace + stub 序列 + E 管线命中检测."""
import base64
import collections
import json
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG, gstr

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
PIPE_E = 0x304eb0

CFG = json.dumps(CONFIG, separators=(',', ':'))


def main():
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    print('action =', env.get('action'))
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = base64.b64encode(plain.encode()).decode()
    print('input b64 len=%d' % len(enc_b64))

    e = Emu()
    blocks = collections.Counter()

    def blk(uc, address, size, ud):
        off = address - DEV_BASE
        if 0 <= off < 0x800000:
            blocks[off >> 8] += 1

    e.uc.hook_add(unicorn.UC_HOOK_BLOCK, blk)

    hits = {'pipeE': 0}

    def pipeE_cb(uc, address, size, ud):
        hits['pipeE'] += 1
        if hits['pipeE'] <= 3:
            lr = uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_LR)
            print('[pipeE] hit#%d lr_off=0x%x' % (hits['pipeE'], lr - DEV_BASE), flush=True)

    e.uc.hook_add(unicorn.UC_HOOK_CODE, pipeE_cb,
                  begin=DEV_BASE + PIPE_E, end=DEV_BASE + PIPE_E + 4)

    stubs = collections.Counter()
    orig = e._do_stub

    def spy(nm, uc):
        stubs[nm] += 1
        return orig(nm, uc)

    e._do_stub = spy

    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    r1 = e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print('[*] init x0=0x%x, stubs=%s' % (r1, dict(stubs)), flush=True)
    n_init = sum(blocks.values())
    print('[*] init 块命中总计 %d' % n_init)
    blocks.clear()
    stubs.clear()

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
    print('[*] call x0=0x%x  pipeE=%d' % (out, hits['pipeE']), flush=True)
    if out > 0x1000:
        s = gstr(e.uc, out, 8192)
        print('[*] 返回串 %d B: %r' % (len(s or b''), (s or b'')[:300]), flush=True)
        if s:
            open('research/tmp_decscan_ret.bin', 'wb').write(s)
    print('[*] call 阶段 stubs: %s' % stubs.most_common(25), flush=True)

    with open('research/tmp_decscan_blocks.txt', 'w') as f:
        for b in sorted(blocks):
            f.write('%x %d\n' % (b << 8, blocks[b]))
    print('[*] call 块桶 %d 个已存 tmp_decscan_blocks.txt' % len(blocks), flush=True)
    for l in e.logs[-12:]:
        print('   ', l)


if __name__ == '__main__':
    main()
