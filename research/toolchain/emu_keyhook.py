#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""emu_keyhook.py - Unicorn 跑 native api_decrypt, hook RSA/AES 入口读 key/iv.

已实证的 native 输入协议:
  std_b64( AES-CBC(qPwClBj7j7ZQraSm, p3JdVQl3q7WQJIgG, JSON) )
  native: b64dec -> AES dec -> JSON.parse -> action dispatch -> handler
handler 会对 payload.data 做 JSON.parse(失败本应被 catch 走解密分支),
Unicorn 缺 unwind 根因 = dl_iterate_phdr 空桩, 本脚本补上真桩.
"""
import base64
import json
import struct
import sys

sys.path.insert(0, 'research/toolchain')
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, \
    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_LR
import unicorn
from emu_v11 import Emu, DEV_BASE

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24

AES_SET_ENC = 0x3851e0
AES_SET_DEC = 0x385400
AES_CBC = 0x385540
EVP_DINIT = 0x387db4
EVP_DUPDATE = 0x3877d0
EVP_DFINAL = 0x387be4
RSA_PRIV_DEC = 0x43e324
THROW_INLINE = 0x60cc2c

CONFIG = {
    "app_id": "4150439554430529",
    "device_id": "cddc4dcf-260d-4684-a8e7-463b2db261e5",
    "code_version": "2020-09-17",
    "app_version": "1.5.8.0",
    "files_path": "/data/user/0/com.tudou.tool/files",
    "tcp": "43.145.33.254:27990",
}

HITS = []


def rd(uc, addr, n):
    try:
        return bytes(uc.mem_read(addr, n))
    except unicorn.unicorn.UcError:
        return None


def ch_encrypt(plain: bytes) -> str:
    from Crypto.Cipher import AES as _AES
    from Crypto.Util.Padding import pad as _pad
    return base64.b64encode(
        _AES.new(b"qPwClBj7j7ZQraSm", _AES.MODE_CBC, b"p3JdVQl3q7WQJIgG")
        .encrypt(_pad(plain, 16))).decode()


class EmuKey(Emu):
    """补 dl_iterate_phdr 桩: 让 libunwind 解析 .eh_frame 完成 C++ 异常 unwinding."""

    def _do_stub(self, nm, uc):
        if nm == 'dl_iterate_phdr':
            from unicorn.arm64_const import UC_ARM64_REG_SP
            cb = uc.reg_read(UC_ARM64_REG_X0)
            data = uc.reg_read(UC_ARM64_REG_X1)
            info = self.alloc(0x80)
            name_p = self.alloc(24)
            self.wr(name_p, b'libcore.so\x00')
            self.wr(info, struct.pack('<Q', DEV_BASE))
            self.wr(info + 8, struct.pack('<Q', name_p))
            e_phoff = struct.unpack_from('<Q', self.data, 0x20)[0]
            e_phnum = struct.unpack_from('<H', self.data, 0x38)[0]
            self.wr(info + 16, struct.pack('<Q', DEV_BASE + e_phoff))
            self.wr(info + 24, struct.pack('<H', e_phnum))
            self.wr(info + 26, b'\x00' * 0x50)
            sp0 = uc.reg_read(UC_ARM64_REG_SP)
            magic2 = 0x53FFF000  # HEAP 尾部未用页, 避开 STUBS hook 区
            sp = sp0 - 0x200
            self.wr(sp, struct.pack('<Q', magic2))
            uc.reg_write(UC_ARM64_REG_SP, sp)
            uc.reg_write(UC_ARM64_REG_X0, info)
            uc.reg_write(UC_ARM64_REG_X1, 56)
            uc.reg_write(UC_ARM64_REG_X2, data)
            uc.reg_write(UC_ARM64_REG_LR, magic2)
            uc.emu_start(cb, magic2, count=10_000_000)
            uc.reg_write(UC_ARM64_REG_SP, sp0)
            ret = uc.reg_read(UC_ARM64_REG_X0)
            uc.reg_write(UC_ARM64_REG_X0, 1 if ret == 0 else ret)
            return
        return super()._do_stub(nm, uc)


def main():
    body = None
    path = '/app/video/device-base'
    for line in open('research/captures/rsa_scan/bodies_now.jsonl',
                     encoding='utf-8', errors='replace'):
        try:
            o = json.loads(line)
        except Exception:
            continue
        if path in o.get('req', ''):
            r = o.get('resp_body_ascii', '')
            if r.count('.') == 1 and len(r) > 400:
                body = r.strip()

    payload = {"action": "api_decrypt", "payload": {"data": body, "path": path}}
    plain = json.dumps(payload, separators=(',', ':'))
    enc_b64 = ch_encrypt(plain.encode())

    e = EmuKey()

    def dump(label, uc):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        x3 = uc.reg_read(UC_ARM64_REG_X3)
        x4 = uc.reg_read(UC_ARM64_REG_X4)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        info = ['lr_off=0x%x' % (lr - DEV_BASE)]
        for nm, v in (('x0', x0), ('x1', x1), ('x2', x2), ('x3', x3), ('x4', x4)):
            if 0x1000 < v < 0x400100000000:
                b = rd(uc, v, 48)
                if b:
                    info.append('%s@0x%x=%s' % (nm, v, b[:32].hex()))
        line = '[%s] %s' % (label, ' | '.join(info))
        print(line, flush=True)
        HITS.append(line)

    def mk_cb(label):
        def cb(uc, addr, size, ud):
            dump(label, uc)
        return cb

    def final_cb(uc, addr, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        print('[EVP_DecryptFinal_ex] ctx=0x%x lr_off=0x%x' % (x0, lr - DEV_BASE), flush=True)
        HITS.append('final')

    def throw_cb(uc, addr, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        ty = msg = None
        try:
            if x1:
                p = int.from_bytes(bytes(uc.mem_read(x1 + 8, 8)), 'little')
                ty = rd(uc, p, 64)
            raw = rd(uc, x0, 96)
            for off in (8, 16, 24):
                if raw:
                    s0 = raw[off:off + 8]
                    if s0 and sum(32 <= c < 127 for c in s0) >= 6:
                        msg = s0.split(b'\x00')[0]
                        break
                    p = int.from_bytes(s0, 'little')
                    if 0x400024000000 < p < 0x400030000000 or 0x50000000 <= p < 0x70200000:
                        s = rd(uc, p, 200)
                        if s and sum(32 <= c < 127 for c in s[:40]) > 30:
                            msg = s.split(b'\x00')[0]
                            break
        except unicorn.unicorn.UcError:
            pass
        print('[内联throw] lr_off=0x%x ty=%r msg=%r' % (lr - DEV_BASE, ty, msg), flush=True)
        HITS.append('throw')

    for off, label in ((AES_SET_ENC, 'aes_v8_set_encrypt_key'),
                       (AES_SET_DEC, 'aes_v8_set_decrypt_key'),
                       (AES_CBC, 'aes_v8_cbc_encrypt'),
                       (EVP_DINIT, 'EVP_DecryptInit_ex'),
                       (EVP_DUPDATE, 'EVP_DecryptUpdate'),
                       (RSA_PRIV_DEC, 'RSA_private_decrypt')):
        e.uc.hook_add(unicorn.UC_HOOK_CODE, mk_cb(label),
                      begin=DEV_BASE + off, end=DEV_BASE + off + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, final_cb,
                  begin=DEV_BASE + EVP_DFINAL, end=DEV_BASE + EVP_DFINAL + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, throw_cb,
                  begin=DEV_BASE + THROW_INLINE, end=DEV_BASE + THROW_INLINE + 4)

    upd_state = {}

    def upd_call(uc, addr, size, ud):
        upd_state['out'] = uc.reg_read(UC_ARM64_REG_X1)
        upd_state['inl'] = uc.reg_read(UC_ARM64_REG_X4)
        print('[upd-call] out=0x%x inl=%d' % (upd_state['out'], upd_state['inl']), flush=True)

    def upd_ret(uc, addr, size, ud):
        out = upd_state.get('out')
        if out:
            b = rd(uc, out, 128)
            print('[upd-ret] 解密输出: %r' % b, flush=True)

    e.uc.hook_add(unicorn.UC_HOOK_CODE, upd_call,
                  begin=DEV_BASE + 0x375284, end=DEV_BASE + 0x375284)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, upd_ret,
                  begin=DEV_BASE + 0x375288, end=DEV_BASE + 0x375288)

    cfg = json.dumps(CONFIG, separators=(',', ':'))
    cfg_p = e.alloc(len(cfg) + 1)
    e.wr(cfg_p, cfg.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print("[*] init 完成", flush=True)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    try:
        out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
        print("[*] call x0=0x%x, hits=%d" % (out, len(HITS)), flush=True)
    except unicorn.unicorn.UcError as ex:
        from unicorn.arm64_const import UC_ARM64_REG_PC
        pc = e.uc.reg_read(UC_ARM64_REG_PC)
        lr = e.uc.reg_read(UC_ARM64_REG_LR)
        print("[!!] crash %s PC=0x%x (off 0x%x) LR=0x%x (off 0x%x)"
              % (ex, pc, pc - DEV_BASE, lr, lr - DEV_BASE), flush=True)
        print("[*] 最近桩:", e.logs[-10:], flush=True)


if __name__ == '__main__':
    main()
