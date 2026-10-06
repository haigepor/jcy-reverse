#!/usr/bin/env python3
"""emu_dec_keyhunt.py - Route A: 用 nlohmann out_of_range 消息钓出真实字段名.

喂 D='{"a":1}' -> 解析成对象 -> 访问真实键 -> 抛 out_of_range('key XXX not found').
hook 0x37577c (runtime_error ctor 调用点) 读 x1 消息串 + 静态缓冲 0x68af85.
"""
import json
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG
from emu_keyhook import ch_encrypt

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))

CTOR_CALL = 0x37577c      # bl 0x612e00  (x1 = msg 串)
RTE_CTOR = 0x612e00
THROW = 0x612ed0
MSG_BUF = 0x68af85        # 静态消息缓冲 (x0 of the snprintf-ish call)
CALLSITE_NL = 0x309564


def gstr(uc, addr, n=256):
    if not addr or addr < 0x1000:
        return None
    try:
        return bytes(uc.mem_read(addr, n)).split(b'\x00')[0]
    except Exception:
        out = bytearray()
        for off in range(0, n, 16):
            try:
                b = bytes(uc.mem_read(addr + off, 16))
            except Exception:
                break
            out += b
            if 0 in b:
                break
        return bytes(out).split(b'\x00')[0]


def run(data_val, label):
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    env['payload']['data'] = data_val
    env['payload']['path'] = data_val
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = ch_encrypt(plain.encode())

    e = Emu()
    info = {'msgs': [], 'nl': None, 'ret': None, 'stopped': False}

    def rdb(a, n):
        try:
            return bytes(e.rd(a, n))
        except Exception:
            return None

    def ctor_cb(uc, address, size, ud):
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        m = gstr(uc, x1, 320)
        info['msgs'].append(('x1', m))
        m2 = gstr(uc, DEV_BASE + MSG_BUF, 320)
        info['msgs'].append(('buf', m2))
        uc.emu_stop()

    def nl_cb(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        raw = rdb(x0, 24)
        if raw:
            import struct
            a, b, p = struct.unpack('<QQQ', raw)
            info['nl'] = (b, (rdb(p, 96) or b''))

    info['fault'] = None
    info['recent'] = []
    info['fpchain'] = []

    def fetch_cb(uc, access, address, size, value, ud):
        regs = {}
        for nm in ('PC', 'LR', 'X0', 'X1', 'X2', 'X3', 'X8', 'X9', 'X19', 'X20',
                   'X21', 'X22', 'X23', 'X24', 'X25', 'X26', 'X27', 'X28', 'X29'):
            regs[nm] = uc.reg_read(getattr(unicorn.arm64_const, 'UC_ARM64_REG_' + nm))
        info['fault'] = (address, regs)
        # 走 fp 链
        fp = regs['X29']
        chain = []
        for _ in range(24):
            if not fp or fp < 0x1000:
                break
            try:
                nxt = int.from_bytes(bytes(uc.mem_read(fp, 8)), 'little')
                ret = int.from_bytes(bytes(uc.mem_read(fp + 8, 8)), 'little')
            except Exception:
                break
            chain.append((fp, ret))
            if nxt <= fp:
                break
            fp = nxt
        info['fpchain'] = chain

    def rec_cb(uc, address, size, ud):
        info['recent'].append(address - DEV_BASE)
        if len(info['recent']) > 300:
            del info['recent'][:100]

    e.uc.hook_add(unicorn.UC_HOOK_CODE, ctor_cb,
                  begin=DEV_BASE + CTOR_CALL, end=DEV_BASE + CTOR_CALL + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, nl_cb,
                  begin=DEV_BASE + CALLSITE_NL, end=DEV_BASE + CALLSITE_NL + 4)
    e.uc.hook_add(unicorn.UC_HOOK_MEM_FETCH_UNMAPPED, fetch_cb)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, rec_cb,
                  begin=DEV_BASE + 0x300000, end=DEV_BASE + 0x320000)

    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = None
    try:
        out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
    except Exception as ex:
        print('   [call 异常] %s' % ex, flush=True)
        if info['fault']:
            ad, regs = info['fault']
            print('   [fetch fault] addr=0x%x' % ad, flush=True)
            for k in ('PC', 'LR', 'X0', 'X1', 'X2', 'X3', 'X8', 'X9', 'X19', 'X20',
                      'X21', 'X22', 'X23', 'X24', 'X25', 'X26', 'X27', 'X28', 'X29'):
                v = regs[k]
                tag = ' (off 0x%x)' % (v - DEV_BASE) if DEV_BASE <= v < DEV_BASE + 0x800000 else ''
                print('      %-4s = 0x%x%s' % (k, v, tag), flush=True)
            print('   [fp 链]', flush=True)
            for fp, ret in info['fpchain'][:16]:
                tag = ' off 0x%x' % (ret - DEV_BASE) if DEV_BASE <= ret < DEV_BASE + 0x800000 else ''
                print('      fp=0x%x ret=0x%x%s' % (fp, ret, tag), flush=True)
            print('   [最近 PC 尾 60]', flush=True)
            print('      ' + ' '.join('%x' % a for a in info['recent'][-60:]), flush=True)

    print('== %s' % label, flush=True)
    if info['nl']:
        print('   nlohmann size=%d 头=%r' % info['nl'], flush=True)
    for tag, m in info['msgs'][:4]:
        print('   msg[%s] = %r' % (tag, m), flush=True)
    if out is not None and out > 0x1000:
        s = (rdb(out, 4096) or b'').split(b'\x00')[0]
        print('   返回(%d): %r' % (len(s), s[:200]), flush=True)
    else:
        print("   x0=%r, logs尾=%s" % (out, e.logs[-4:]), flush=True)
    return info


if __name__ == '__main__':
    dv = sys.argv[1] if len(sys.argv) > 1 else '{"a":1}'
    run(dv, 'D=%r' % dv)
