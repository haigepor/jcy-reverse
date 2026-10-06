# -*- coding: utf-8 -*-
# probe_C.py — 抓取 E 的密钥/IV 并验证是否为 AES-CBC
import os, sys, struct, base64
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE
from emu_v14 import Emu4 as _Engine

ALPHA = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
FWD = str.maketrans(STD, ALPHA)

AFTER_A1 = DEV_BASE + 0x304fb8
CALL_E = DEV_BASE + 0x3050f8
AFTER_E = DEV_BASE + 0x3050fc

S = "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
A1B = base64.b64encode(S.encode()).decode().translate(FWD).encode()

CAP = {}


def vec(e, addr):
    b, en, cap = struct.unpack("<QQQ", e.rd(addr, 24))
    if 0x40000000 <= b < 0x70000000 and 0 <= en - b < 0x4000:
        return b, en - b, e.rd(b, en - b)
    return None


def on_code(uc, address, size, ud):
    e = ud
    if address == AFTER_A1:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        b, en, cap = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        if en - b == len(A1B):
            e.wr(b, A1B)
    elif address == CALL_E:
        CAP["in"] = vec(e, uc.reg_read(UC_ARM64_REG_X1))
        CAP["x2"] = uc.reg_read(UC_ARM64_REG_X2)
        CAP["x3"] = uc.reg_read(UC_ARM64_REG_X3)
        CAP["x2_raw"] = e.rd(CAP["x2"], 0x40)
        CAP["x3_raw"] = e.rd(CAP["x3"], 0x40)
        # 解析 x2 / x3 里的子对象
        subs = {}
        for nm, base in (("x2", CAP["x2"]), ("x3", CAP["x3"])):
            for off in (0, 0x18):
                try:
                    v = vec(e, base + off)
                    if v:
                        subs["%s+%#x" % (nm, off)] = v[2]
                except Exception:
                    pass
        CAP["subs"] = subs
    elif address == AFTER_E:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        CAP["out"] = vec(e, x29 - 0x38)


def main():
    e = _Engine()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    for a in (AFTER_A1, CALL_E, AFTER_E):
        e.uc.hook_add(UC_HOOK_CODE, on_code, user_data=e, begin=a, end=a + 4)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(S)
    err = None
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=300_000_000)
    except Exception as ex:
        err = repr(ex)
    print("err:", err)
    print("E.in  len=%d %s" % (len(CAP['in'][2]), CAP['in'][2].decode('latin1')))
    print("E.x2  ptr=%#x raw=%s" % (CAP['x2'], CAP['x2_raw'].hex()))
    print("E.x3  ptr=%#x raw=%s" % (CAP['x3'], CAP['x3_raw'].hex()))
    for k, v in CAP['subs'].items():
        print("  %-6s len=%d %s" % (k, len(v), v.hex()))
    print("E.out len=%d %s" % (len(CAP['out'][2]), CAP['out'][2].hex()))

    # ---- Python 侧验证 ----
    from Crypto.Cipher import AES
    keys = [v for k, v in CAP['subs'].items() if len(v) in (16, 24, 32)]
    ivs = [v for k, v in CAP['subs'].items() if len(v) == 16]
    outs = CAP['out'][2]
    plain_cands = {
        "A1(104)+pkcs7": A1B,
        "A1(104)": A1B,
        "std_b64": base64.b64encode(S.encode()),
        "input_str": S.encode(),
    }
    for kn, k in [("sub%d" % i, v) for i, v in enumerate(keys)]:
        for ivn, iv in [("sub%d" % i, v) for i, v in enumerate(ivs)]:
            for pn, p in plain_cands.items():
                for pad in (True, False):
                    if pad:
                        from Crypto.Util.Padding import pad as _pad
                        pt = _pad(p, 16)
                    else:
                        if len(p) % 16:
                            continue
                        pt = p
                    try:
                        c = AES.new(k, AES.MODE_CBC, iv).encrypt(pt)
                    except Exception:
                        continue
                    if c == outs:
                        print("*** HIT AES-CBC enc key=%s(%d) iv=%s plain=%s pad=%s" % (kn, len(k), ivn, pn, pad))
                    if c[:16] == outs[:16]:
                        print("    prefix-hit key=%s iv=%s plain=%s pad=%s" % (kn, ivn, pn, pad))
    print("done")


if __name__ == "__main__":
    main()
