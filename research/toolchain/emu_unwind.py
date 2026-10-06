#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""emu_unwind.py - Unicorn 跑 native api_decrypt + 手工 CFI 栈回退替代 libunwind.

实证布局(由 __cxa_throw/__cxa_begin_catch 反汇编导出):
  入口 x0 = thrown(对象指针); 头基 H = thrown-0x80; U(_Unwind_Exception*) = thrown-0x20
  U+0x00 exception_class | U+0x08 cleanup | H+0x10 tinfo | H+0x18 dtor
  H+0x20 unexpectedHandler | H+0x28 terminateHandler | H+0x30 nextException
  H+0x38 handlerCount | H+0x3c switchValue | H+0x58 adjustedPtr(begin_catch 返回它)
__cxa_throw 在 0x60cca4 bl 内部 _Unwind_RaiseException(0x1fb4), 此时头已初始化完。
真实 libunwind 走 dl_iterate_phdr(空桩即崩) → 在 0x60cca4 拦截, 手工回退:
  沿 FDE CFI 恢复 caller 的 x29/x30/x19-x28, 首个 action!=0 的 landing pad 直接落地。
adjustedPtr 手工写 thrown(等价 personality phase2); begin/end_catch 跑真代码。

地址体系: 遍历全程用运行时绝对地址(寄存器值), find_fde/cfi_eval 前减 DEV_BASE 转 VA。
"""
import base64
import json
import os
import struct
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn import UC_HOOK_CODE, UC_PROT_ALL, UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_READ
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_SP, UC_ARM64_REG_PC,
                                 UC_ARM64_REG_X29, UC_ARM64_REG_LR,
                                 UC_ARM64_REG_X19, UC_ARM64_REG_X20,
                                 UC_ARM64_REG_X21, UC_ARM64_REG_X22,
                                 UC_ARM64_REG_X23, UC_ARM64_REG_X24,
                                 UC_ARM64_REG_X25, UC_ARM64_REG_X26,
                                 UC_ARM64_REG_X27, UC_ARM64_REG_X28,
                                 UC_ARM64_REG_X30)
from emu_v11 import DEV_BASE
from emu_keyhook import EmuKey, ch_encrypt, CONFIG, CALL_OFF, INIT_OFF, \
    AES_SET_DEC, AES_CBC, EVP_DINIT, EVP_DUPDATE, EVP_DFINAL, RSA_PRIV_DEC
from elftools.elf.elffile import ELFFile

SO = 'research/artifacts/device_libs/libcore.so'
THROW = 0x60cc2c
THROW_RAISE = 0x60cca4          # __cxa_throw 内 bl _Unwind_RaiseException
BEGIN_CATCH = 0x60cb18
FREE_EXC = 0x60cd18             # unhandled → free+terminate
END_CATCH = 0x60cd48
# V10 §4.1 新增偏移 (dynsym 逐一实证)
EVP_CINIT_EX = 0x387368         # EVP_CipherInit_ex
EVP_CUPDATE = 0x387780          # EVP_CipherUpdate
EVP_CFINAL = 0x387d84           # EVP_CipherFinal
EVP_CFINAL_EX = 0x387a98        # EVP_CipherFinal_ex
PKEY_DEC_INIT = 0x3ffbc0        # EVP_PKEY_decrypt_init
PKEY_DEC = 0x3ffc40             # EVP_PKEY_decrypt
EVP_EINIT_EX = 0x387da4         # EVP_EncryptInit_ex
EVP_EUPDATE = 0x387790          # EVP_EncryptUpdate
EVP_EFINAL_EX = 0x387aa8        # EVP_EncryptFinal_ex
RSA_PUB_ENC = 0x43e30c          # RSA_public_encrypt(flen, from=key+iv, to, rsa, pad)
RAND_BYTES = 0x438d18           # RAND_bytes(buf, num)
EVP_DINIT2 = 0x387dac           # EVP_DecryptInit
EVP_DFINAL2 = 0x387d98          # EVP_DecryptFinal
CCE0 = 0x30cce0                 # call 内 `ldr x8,[sp,#8]; blr x8` (崩溃点)
CCE8 = 0x30cce8                 # blr 返回点
PAD_ENTRY = 0x3027d0            # catch pad 起点
PAD_AFTER_STR = 0x3027e4        # `str x22,[sp,#8]` 之后
PAD_X20 = 0x302864              # end_catch 后 `mov x0,x20`
CB_ADDR = 0x62000000            # 真回调桩页 (一条 ret)
MAGIC_LR = 0x53FFD000

# X0..X28 编号连续, X29/X30 不在序列内(-197), 单独取
RX = [UC_ARM64_REG_X0 + i for i in range(29)] + [UC_ARM64_REG_X29, UC_ARM64_REG_X30]
REGX = {19: UC_ARM64_REG_X19, 20: UC_ARM64_REG_X20, 21: UC_ARM64_REG_X21,
        22: UC_ARM64_REG_X22, 23: UC_ARM64_REG_X23, 24: UC_ARM64_REG_X24,
        25: UC_ARM64_REG_X25, 26: UC_ARM64_REG_X26, 27: UC_ARM64_REG_X27,
        28: UC_ARM64_REG_X28, 29: UC_ARM64_REG_X29, 30: UC_ARM64_REG_X30}

TRACE = open('research/captures/rsa_scan/emu_unwind_trace.log', 'w', encoding='utf-8')


def log(*a):
    s = ' '.join(str(x) for x in a)
    print(s, flush=True)
    TRACE.write(s + '\n')
    TRACE.flush()


# ---------------- 离线解析 .eh_frame ----------------
elf = ELFFile(open(SO, 'rb'))
ehf = elf.get_section_by_name('.eh_frame')
EADDR, EDATA = ehf['sh_addr'], ehf.data()
gcc = elf.get_section_by_name('.gcc_except_table')
GADDR, GDATA = gcc['sh_addr'], gcc.data()


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def s32(b, o):
    return struct.unpack_from('<i', b, o)[0]


def uleb(b, o):
    r = s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7f) << s
        if not x & 0x80:
            return r, o
        s += 7


def sleb(b, o):
    r = s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7f) << s
        s += 7
        if not x & 0x80:
            if x & 0x40:
                r -= 1 << s
            return r, o


ENC_SIZE = {0x00: 8, 0x02: 2, 0x03: 4, 0x04: 8, 0x09: 8, 0x0a: 2, 0x0b: 4, 0x0c: 8}


class CFI:
    __slots__ = ('cfa_reg', 'cfa_off', 'rules')

    def __init__(self):
        self.cfa_reg = 31
        self.cfa_off = 0
        self.rules = {}

    def clone(self):
        c = CFI()
        c.cfa_reg = self.cfa_reg
        c.cfa_off = self.cfa_off
        c.rules = dict(self.rules)
        return c


def parse_cie_full(cie_off):
    length = u32(EDATA, cie_off)
    p = cie_off + 9  # 跳过 version
    end0 = EDATA.find(b'\x00', p)
    aug = EDATA[p:end0].decode('latin1')
    p = end0 + 1
    code_align, p = uleb(EDATA, p)
    data_align, p = sleb(EDATA, p)
    ret_reg, p = uleb(EDATA, p)
    fde_enc = 0x1b
    lsda_enc = 0x1c
    if 'z' in aug:
        alen, p = uleb(EDATA, p)
        for ch in aug[1:]:
            if ch == 'R':
                fde_enc = EDATA[p]
                p += 1
            elif ch == 'P':
                enc = EDATA[p]
                p += 1
                if (enc & 0x0f) in (0x01, 0x09):
                    _, p = uleb(EDATA, p)
                else:
                    p += ENC_SIZE[enc & 0x0f]
            elif ch == 'L':
                lsda_enc = EDATA[p]
                p += 1
    return dict(aug=aug, code_align=code_align, data_align=data_align,
                ret_reg=ret_reg, fde_enc=fde_enc, lsda_enc=lsda_enc,
                init_off=p, init_end=cie_off + 4 + length)


CIES = {}
FDES = []  # (start_va, end_va, cie_off, ins_off, ins_end, lsda_va)


def walk_fdes():
    o = 0
    N = len(EDATA)
    while o < N - 4:
        length = u32(EDATA, o)
        if length in (0, 0xffffffff):
            break
        cie_ptr = s32(EDATA, o + 4)
        if cie_ptr == 0:
            if o not in CIES:
                CIES[o] = parse_cie_full(o)
            o += 4 + length
            continue
        cie_off = o + 4 - cie_ptr
        if cie_off not in CIES:
            CIES[cie_off] = parse_cie_full(cie_off)
        cie = CIES[cie_off]
        pco = o + 8
        try:
            pc_begin = EADDR + pco + s32(EDATA, pco)
            pc_range = u32(EDATA, pco + 4)
        except Exception:
            o += 4 + length
            continue
        p = pco + 8
        lsda_va = None
        if 'z' in cie['aug']:
            alen, p = uleb(EDATA, p)
            q = p
            for ch in cie['aug'][1:]:
                if ch == 'L':
                    enc = cie['lsda_enc']
                    n = ENC_SIZE[enc & 0x0f]
                    if enc & 0x10:  # pcrel
                        raw = int.from_bytes(EDATA[q:q + n], 'little', signed=True)
                        lsda_va = EADDR + q + raw
                    else:
                        lsda_va = int.from_bytes(EDATA[q:q + n], 'little')
                    q += n
                elif ch == 'R':
                    q += 1
            p = q
        FDES.append((pc_begin, pc_begin + pc_range, cie_off, p, o + 4 + length, lsda_va))
        o += 4 + length
    FDES.sort(key=lambda f: f[0])
    return len(FDES)


def find_fde_rt(rt):
    """运行时代码地址 → FDE (内部转 VA)."""
    va = rt - DEV_BASE
    lo, hi = 0, len(FDES)
    while lo < hi:
        m = (lo + hi) // 2
        if FDES[m][1] <= va:
            lo = m + 1
        else:
            hi = m
    if lo < len(FDES) and FDES[lo][0] <= va < FDES[lo][1]:
        return FDES[lo]
    return None


def cfi_eval(fde, off):
    """评估 FDE 在函数内偏移 off 处的 CFI 状态 (caller 寄存器保存规则)."""
    cie_off, ins_off, ins_end = fde[2], fde[3], fde[4]
    cie = CIES[cie_off]
    st = CFI()
    loc = 0
    stack = []

    def run(p, end):
        nonlocal loc, st
        b = EDATA
        while p < end:
            op = b[p]
            if op == 0x00:  # nop
                p += 1
            elif op == 0x01:  # set_loc (eh_frame 罕见)
                addr, p = uleb(b, p + 1)
                if addr > off:
                    return
                loc = addr
            elif op in (0x02, 0x03, 0x04):  # advance_loc1/2/4
                n = {0x02: 1, 0x03: 2, 0x04: 4}[op]
                delta = int.from_bytes(b[p + 1:p + 1 + n], 'little')
                p += 1 + n
                cand = loc + delta * cie['code_align']
                if cand > off:
                    return
                loc = cand
            elif op < 0x40:  # 扩展操作码
                if op == 0x05:  # offset_extended
                    r, p = uleb(b, p + 1)
                    v, p = uleb(b, p)
                    st.rules[r] = cie['data_align'] * v
                elif op == 0x06:  # restore_extended
                    r, p = uleb(b, p + 1)
                    st.rules.pop(r, None)
                elif op in (0x07, 0x08):  # undefined / same_value
                    _, p = uleb(b, p + 1)
                elif op == 0x09:  # register
                    _, p = uleb(b, p + 1)
                    _, p = uleb(b, p)
                elif op == 0x0a:  # remember_state
                    stack.append(st.clone())
                    p += 1
                elif op == 0x0b:  # restore_state
                    st = stack.pop()
                    p += 1
                elif op == 0x0c:  # def_cfa
                    r, p = uleb(b, p + 1)
                    v, p = uleb(b, p)
                    st.cfa_reg = r
                    st.cfa_off = v
                elif op == 0x0d:  # def_cfa_register
                    r, p = uleb(b, p + 1)
                    st.cfa_reg = r
                elif op == 0x0e:  # def_cfa_offset
                    v, p = uleb(b, p + 1)
                    st.cfa_off = v
                elif op == 0x0f:  # def_cfa_sf
                    r, p = uleb(b, p + 1)
                    v, p = sleb(b, p)
                    st.cfa_reg = r
                    st.cfa_off = v * cie['data_align']
                elif op == 0x10:  # def_cfa_offset_sf
                    v, p = sleb(b, p + 1)
                    st.cfa_off = v * cie['data_align']
                elif op == 0x11:  # offset_extended_sf
                    r, p = uleb(b, p + 1)
                    v, p = sleb(b, p)
                    st.rules[r] = cie['data_align'] * v
                elif op == 0x2d:  # DW_CFA_AARCH64_negate_ra_state (PAC, 模拟中为 NOP)
                    p += 1
                else:
                    raise ValueError('cfi op %#x' % op)
            elif op < 0x80:  # advance_loc
                cand = loc + (op & 0x3f) * cie['code_align']
                p += 1
                if cand > off:
                    return
                loc = cand
            elif op < 0xc0:  # offset r
                r = op & 0x3f
                v, p = uleb(b, p + 1)
                st.rules[r] = cie['data_align'] * v
            else:  # restore r
                st.rules.pop(op & 0x3f, None)
                p += 1

    run(cie['init_off'], cie['init_end'])
    run(ins_off, ins_end)
    return st


LSDA_CACHE = {}


def lsda_of(fde):
    lsda_va = fde[5]
    if lsda_va is None:
        return None
    key = fde[0]
    if key in LSDA_CACHE:
        return LSDA_CACHE[key]
    o = lsda_va - GADDR
    lp_enc = GDATA[o]
    o += 1
    lp_start = fde[0]
    if lp_enc not in (0x00, 0xff):
        if (lp_enc & 0x0f) == 0x0b:
            lp_start = GADDR + o + s32(GDATA, o)
        elif (lp_enc & 0x0f) == 0x03:
            lp_start = u32(GDATA, o)
        o += 4
    ttype_enc = GDATA[o]
    o += 1
    ttype_base_rt = None
    ttype_esz = 8
    if ttype_enc != 0x00:
        fpos = o
        co, o = uleb(GDATA, o)          # 偏移字段恒为 ULEB (0x1a3c50=236, 0x1a40b8=2176 实测)
        k = ttype_enc & 0x0f
        if k == 0x0b:
            ttype_esz = 4
        elif k == 0x0a:
            ttype_esz = 2
        else:
            ttype_esz = 8
        # V10 §4.2: enc=0x9c(indirect|pcrel|sdata8)。pcrel 基址 = 字段起始 + co;
        # 旧代码 `o - co` 方向反了 → 落进 ELF 头 ('\x7fELF' 垃圾名)
        if ttype_enc & 0x10:
            ttype_base_rt = DEV_BASE + GADDR + fpos + co
        else:
            ttype_base_rt = co & ((1 << 64) - 1)
    cs_enc = GDATA[o]
    o += 1
    cs_len, o = uleb(GDATA, o)
    cs_end = o + cs_len
    act_off = cs_end               # action 表紧跟 call-site 表
    table = []
    while o < cs_end:
        cs_start, o = uleb(GDATA, o)
        cs_len2, o = uleb(GDATA, o)
        lp_off, o = uleb(GDATA, o)
        act, o = uleb(GDATA, o)
        table.append((fde[0] + cs_start, cs_len2,
                      (lp_start + lp_off) if lp_off else None, act))
    LSDA_CACHE[key] = (table, ttype_base_rt, ttype_enc, act_off, ttype_esz)
    return LSDA_CACHE[key]


def find_catch_rt(rt):
    fde = find_fde_rt(rt)
    if fde is None:
        return None
    ent = lsda_of(fde)
    if not ent:
        return None
    va = rt - DEV_BASE
    for cs, cl, lp, act in ent[0]:
        if cs <= va < cs + cl:
            if act and lp:
                return lp, act, fde[0]
            return None
    return None


def action_chain(ent, act):
    """cs 的 action 偏移 → [(filter, next)...]（action 表在 call-site 表之后）"""
    act_off = ent[3]
    out = []
    off = act
    seen = set()
    while off:
        if off in seen:
            break
        seen.add(off)
        p = act_off + off
        if p + 2 > len(GDATA):
            break
        f, p = sleb(GDATA, p)
        nx, p = sleb(GDATA, p)
        out.append((f, nx))
        off = nx
    return out


def ttype_name_rt(uc, ent, f):
    """filter f → catch 类型名（处理 pcrel/indirect/sdata8，走运行时内存读）"""
    tb, tenc, esz = ent[1], ent[2], ent[4]
    if f <= 0 or tb is None:
        return None
    entry = (tb - f * esz) & ((1 << 64) - 1)
    try:
        v = int.from_bytes(bytes(uc.mem_read(entry, esz)), 'little', signed=True)
    except unicorn.unicorn.UcError:
        return None
    target = (entry + v) if (tenc & 0x10) else v          # pcrel: 相对字段自身
    target &= (1 << 64) - 1
    if tenc & 0x80:                                        # indirect
        target = rd64(uc, target)
        if not target:
            return None
    nmp = rd64(uc, target + 8)
    return rd_c(uc, nmp, 160) if nmp else None


def ti_chain(uc, ti, limit=8):
    """type_info 继承链: [自身名, 基类名, ...]（__si_class_type_info 布局）"""
    out = []
    cur = ti
    ok0 = set('NSZ0123456789')
    while cur and len(out) < limit:
        nmp = rd64(uc, cur + 8)
        nm = rd_c(uc, nmp, 160) if nmp else None
        if not nm or len(nm) > 150 or (nm[0] not in ok0 and not nm.startswith('St')):
            break
        out.append(nm)
        nxt = rd64(uc, cur + 16)
        if nxt:
            nmp2 = rd64(uc, nxt + 8)
            nm2 = rd_c(uc, nmp2, 160) if nmp2 else None
            if nm2 and len(nm2) <= 150 and (nm2[0] in ok0 or nm2.startswith('St')):
                cur = nxt
                continue
        break
    return out


def rd64(uc, addr):
    try:
        return int.from_bytes(bytes(uc.mem_read(addr, 8)), 'little')
    except unicorn.unicorn.UcError:
        return None


def rd_c(uc, addr, n=64):
    try:
        b = bytes(uc.mem_read(addr, n))
    except unicorn.unicorn.UcError:
        return None
    i = b.find(0)
    if i < 0:
        i = n
    return b[:i].decode('latin1', 'replace')


def manual_unwind(uc):
    x29 = uc.reg_read(UC_ARM64_REG_X29)
    sp = uc.reg_read(UC_ARM64_REG_SP)
    U = uc.reg_read(UC_ARM64_REG_X0)
    H = U - 0x60
    thrown = U + 0x20
    log('[unwind] U=0x%x H=0x%x thrown=0x%x' % (U, H, thrown))
    try:
        b0 = int.from_bytes(bytes(uc.mem_read(thrown + 8, 8)), 'little')
        if b0 & 1:  # libc++ long string
            sz = int.from_bytes(bytes(uc.mem_read(thrown + 16, 8)), 'little')
            da = int.from_bytes(bytes(uc.mem_read(thrown + 24, 8)), 'little')
            msg = rd_c(uc, da, min(sz + 1, 700)) or ''
        else:
            msg = rd_c(uc, thrown + 9, min((b0 >> 1) + 1, 700)) or ''
        log('[unwind] 异常消息: %r' % msg)
    except Exception as ex:
        log('[unwind] 异常消息读取失败: %s' % ex)
    try:
        hdr = bytes(uc.mem_read(U - 0x70, 0xa0))
        log('[unwind] header: %s' % hdr.hex())
        tinfo = int.from_bytes(hdr[0x20:0x28], 'little')  # H+0x10 = U-0x50 → hdr 内偏移 0x20
        thrown_chain = []
        if tinfo > 0x10000:
            thrown_chain = ti_chain(uc, tinfo)
            log('[unwind] thrown 类型链: %s' % thrown_chain)
    except unicorn.unicorn.UcError as e:
        thrown_chain = []
        log('[unwind] header read fail: %s' % e)
    cs = DEV_BASE + THROW_RAISE
    fp = x29
    regs = {r: uc.reg_read(REGX[r]) for r in range(19, 29)}
    chain = []
    def land(cfa, nfp, nregs, lp, act):
        log('[unwind] 落地: SP=0x%x X29=0x%x' % (cfa, nfp))
        log('[unwind] 帧链: %s' % ' | '.join(
            '%d:cs=%x/fn=%x' % (d, c, f) for d, c, f, _ in chain))
        log('[unwind] 恢复态 x19-x28: %s' %
            ' '.join('%x' % nregs.get(r, 0) for r in range(19, 29)))
        log('[unwind] 判H2: 恢复 x22=0x%x [CFA+8]=0x%x (pad 将把 x22 写入 [sp+8])'
            % (nregs.get(22, 0), rd64(uc, cfa + 8) or 0))
        uc.mem_write(H + 0x58, struct.pack('<Q', thrown))   # adjustedPtr
        log('[unwind] [H+0x58] ← thrown=0x%x (adjustedPtr)' % thrown)
        uc.reg_write(UC_ARM64_REG_SP, cfa)
        uc.reg_write(UC_ARM64_REG_X29, nfp)
        for r in range(19, 29):
            uc.reg_write(REGX[r], nregs[r])
        uc.reg_write(UC_ARM64_REG_X1, act)
        uc.reg_write(UC_ARM64_REG_LR, MAGIC_LR)
        uc.reg_write(UC_ARM64_REG_PC, DEV_BASE + lp)

    fallback = None
    for depth in range(80):
        fde = find_fde_rt(cs)
        if fde is None:
            log('[unwind] depth=%d 无 FDE cs=0x%x → 放弃' % (depth, cs - DEV_BASE))
            return None
        try:
            st = cfi_eval(fde, cs - DEV_BASE - fde[0])
        except ValueError as e:
            log('[unwind] depth=%d CFI op 失败 %s cs=0x%x' % (depth, e, cs - DEV_BASE))
            return None
        base = sp if st.cfa_reg == 31 else fp
        cfa = base + st.cfa_off
        caller = {}
        for r, off in st.rules.items():
            v = rd64(uc, cfa + off)
            if v is not None:
                caller[r] = v
        ncs_v = caller.get(30)
        nfp = caller.get(29)
        if ncs_v is None and fp:
            ncs_v = rd64(uc, fp + 8)
        if nfp is None and fp:
            nfp = rd64(uc, fp)
        if not ncs_v or not nfp:
            log('[unwind] depth=%d cs=0x%x 链断 (x30/x29 读不到)'
                % (depth, cs - DEV_BASE))
            return None
        ncs = ncs_v - 4
        nregs = dict(regs)
        for r in range(19, 29):
            if r in caller:
                nregs[r] = caller[r]
        chain.append((depth, cs - DEV_BASE, fde[0], cfa))
        pad = find_catch_rt(ncs)
        if pad:
            lp, act, fstart = pad
            fde2 = find_fde_rt(ncs)
            ent = lsda_of(fde2) if fde2 else None
            names = []
            if ent:
                chain2 = action_chain(ent, act)
                names = [(ttype_name_rt(uc, ent, f) if f > 0 else '<cleanup>')
                         for f, _ in chain2]
            log('[unwind] depth=%d 候选 pad=0x%x 函数=0x%x act=%d 类型=%s'
                % (depth, lp, fstart, act, names))
            hit = any(nm and nm != '<cleanup>' and nm in thrown_chain
                      for nm in names)
            if hit:
                log('[unwind] 命中 catch: depth=%d 调用点=0x%x 函数=0x%x pad=0x%x act=%d'
                    % (depth, ncs - DEV_BASE, fstart, lp, act))
                land(cfa, nfp, nregs, lp, act)
                return True
            if fallback is None and any(nm and nm != '<cleanup>' for nm in names):
                fallback = (cfa, nfp, nregs, lp, act, fstart)
        cs, sp, fp, regs = ncs, cfa, nfp, nregs
    if fallback is not None:
        cfa, nfp, nregs, lp, act, fstart = fallback
        log('[unwind] !! 80 帧内无类型匹配 catch —— 回退落地旧候选: 函数=0x%x pad=0x%x act=%d'
            % (fstart, lp, act))
        land(cfa, nfp, nregs, lp, act)
        return True
    log('[unwind] 80 帧内无 catch')
    return None


# ---------------- 运行时 ----------------
RAND_K16 = []
CAPTURES = []


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('path', nargs='?', default='/app/video/device-base')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--enc', default='quoted', choices=['plain', 'quoted', 'object'],
                    help='data 字段编码: plain=原文, quoted=JSON字符串字面量, object=对象包裹')
    ap.add_argument('--action', default='api_decrypt', choices=['api_decrypt', 'api_encrypt', 'get_record', 'check', 'get_pid'])
    ap.add_argument('--rec', type=int, default=-1, help='bodies_now.jsonl 记录号 (附带其请求头)')
    ap.add_argument('--pshape', default='std', choices=['std', 'payloadstr', 'datakey', 'flat'],
                    help='api_encrypt 信封形状变体')
    ap.add_argument('--clear-first', action='store_true', help='api_encrypt 前先调 clear_key')
    ap.add_argument('--then-decrypt', action='store_true',
                    help='第一个 call 后同会话再跑 api_decrypt(真 body 裸 data, 测 store 状态分支)')
    ap.add_argument('--seed-store', action='store_true',
                    help='把离线解出的 K16resp/rev 写入 KS_KEY/KS_IV, 诱导 api_decrypt 走真解密分支')
    ap.add_argument('--scan-store', action='store_true',
                    help='api_encrypt 后全堆/.bss 扫描 RAND 出的 K16 落点, 定位真会话 store')
    ap.add_argument('--params', default='{"device_id":"cddc4dcf-260d-4684-a8e7-463b2db261e5","appid":"4150439554430529","version":"1.5.8.0","code_version":"2020-09-17","app_name":"jcymh"}',
                    help='api_encrypt 的 params 内容')
    args = ap.parse_args()

    n = walk_fdes()
    log('[*] FDE 数: %d' % n)

    if args.selftest:
        for t in (THROW_RAISE, 0x307a9c, 0x328b84, 0x307a38):
            fde = find_fde_rt(DEV_BASE + t)
            if not fde:
                log('selftest 0x%x: 无 FDE' % t)
                continue
            st = cfi_eval(fde, t - fde[0])
            ent = lsda_of(fde)
            log('selftest 0x%x → fn 0x%x..0x%x cfa=r%d+%#x 规则数=%d lsda=%s 条目=%d'
                % (t, fde[0], fde[1], st.cfa_reg, st.cfa_off, len(st.rules),
                   hex(fde[5]) if fde[5] else None, len(ent[0]) if ent else 0))
            if ent:
                for cs, cl, lp, act in ent[0][:6]:
                    log('   cs 0x%x+0x%x → lp %s act=%d'
                        % (cs, cl, hex(lp) if lp else None, act))
        return

    body = None
    K16 = None
    if args.action == 'api_decrypt' or args.then_decrypt:
        bs = [json.loads(l) for l in open('research/captures/rsa_scan/bodies_now.jsonl',
                                          encoding='utf-8', errors='replace')]
        if args.rec >= 0:
            r = bs[args.rec].get('resp_body_ascii', '')
            if r.count('.') == 1 and len(r) > 400:
                body = r.strip()
        else:
            for o in bs:
                if args.path in o.get('req', ''):
                    r = o.get('resp_body_ascii', '')
                    if r.count('.') == 1 and len(r) > 400:
                        body = r.strip()
        if not body:
            sys.exit('未找到 body: ' + args.path)

        # 离线还原 K16
        ALPHA = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
        STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_v1_5
        priv = RSA.import_key(open('research/captures/rsa_scan/priv_from_go.pem', 'rb').read())
        t0 = body.split('.')[0].translate(str.maketrans(ALPHA, STD))
        t0 += '=' * ((-len(t0)) % 4)
        p0 = base64.b64decode(t0)
        K16 = PKCS1_v1_5.new(priv).decrypt(p0[:256], None)
        log('[*] body=%s K16=%r hex=%s' % (args.path, K16, K16.hex() if K16 else '-'))

    if args.action in ('get_record', 'check', 'get_pid'):
        payload = {"action": args.action, "payload": {}}
    elif args.action == 'api_encrypt':
        if args.enc == 'plain':
            data_field = args.params
        elif args.enc == 'object':
            data_field = json.loads(args.params)   # 真 JSON 对象
        else:
            data_field = json.dumps(args.params)   # 二次编码
        hdrs = {}
        if getattr(args, 'rec', -1) >= 0:
            pl = [json.loads(l) for l in open('research/captures/rsa_scan/proxy_now.jsonl',
                                              encoding='utf-8')]
            h = pl[args.rec].get('req_headers', {})
            for kk in ('authentication', 'ts', 'nonce', 'tcs', 'x-version', 'appid'):
                if kk in h:
                    hdrs[kk] = h[kk]
            log('[*] api_encrypt 附带请求头 rec=%d: ts=%s nonce=%s auth_len=%d'
                % (args.rec, hdrs.get('ts'), hdrs.get('nonce'), len(hdrs.get('authentication', ''))))
        payload = {"action": "api_encrypt",
                   "payload": dict(hdrs, params=data_field, path=args.path)}
        if args.pshape == 'payloadstr':
            payload = {"action": "api_encrypt",
                       "payload": json.dumps(dict(params=data_field, path=args.path))}
        elif args.pshape == 'datakey':
            payload = {"action": "api_encrypt",
                       "payload": {"data": data_field, "path": args.path}}
        elif args.pshape == 'flat':
            payload = dict(hdrs, action="api_encrypt", params=data_field, path=args.path)
    else:
        if args.enc == 'plain':
            data_field = body
        elif args.enc == 'object':
            data_field = {"d": body}
        else:
            data_field = json.dumps(body)   # 二次编码: parse(data) 还原出 body 字符串
        # 携带该 rec 的真实请求头 (native 可能用头字段派生会话 key)
        hdrs = {}
        if getattr(args, 'rec', -1) >= 0:
            pl = [json.loads(l) for l in open('research/captures/rsa_scan/proxy_now.jsonl',
                                              encoding='utf-8')]
            h = pl[args.rec].get('req_headers', {})
            for kk in ('authentication', 'ts', 'nonce', 'tcs', 'x-version', 'appid'):
                if kk in h:
                    hdrs[kk] = h[kk]
            log('[*] 附带请求头 rec=%d: ts=%s nonce=%s auth_len=%d'
                % (args.rec, hdrs.get('ts'), hdrs.get('nonce'), len(hdrs.get('authentication', ''))))
        payload = {"action": "api_decrypt", "payload": dict(hdrs, data=data_field, path=args.path)}
    log('[*] enc=%s 信封头: %s' % (args.enc, json.dumps(payload, separators=(',', ':'))[:120]))
    enc_b64 = ch_encrypt(json.dumps(payload, separators=(',', ':')).encode())
    e = EmuKey()

    # map-on-demand: 未映射读 → 记录+零页映射+继续 (api_encrypt 路线硬闯)
    # V12: 0x737E41C00000 区间用真机堆快照回填 (r_ dump), 供 api_encrypt 取公钥串
    faults = []
    # 多区域回填: (基址, 相对 artifacts 的文件路径); 指针链跨区时逐区命中
    _here = os.path.dirname(os.path.abspath(__file__))
    REGION_IMGS = [
        (0x737E41C00000, os.path.join(_here, '..', 'artifacts', 'regions', 'r_0000737e41c00000.bin')),
        (0x737DDFAF1000, os.path.join(_here, '..', 'artifacts', 'regions_all', '0255.bin')),
        (0x737DE0F00000, os.path.join(_here, '..', 'artifacts', 'regions_all', '0262.bin')),
    ]
    region_imgs = []
    for _base, _p in REGION_IMGS:
        if os.path.exists(_p):
            _img = open(_p, 'rb').read()
            region_imgs.append((_base, _img))
            e.add_backfill(_base, _img)   # V12: Python 侧 rd/桩 memcpy 也走快照回填
            log('[*] 堆快照回填: %s (%dKB) @0x%x' % (os.path.basename(_p), len(_img) // 1024, _base))

    def mem_fault(uc, access, address, size, value, ud):
        try:
            hit = e._map_backfill(address, size)
            if not hit:
                pg = address & ~0xFFF
                end = (address + max(size, 1) - 1) & ~0xFFF
                while pg <= end:
                    try:
                        uc.mem_map(pg, 0x1000, UC_PROT_ALL)
                    except unicorn.unicorn.UcError:
                        pass
                    pg += 0x1000
            faults.append((access, address, size))
            if len(faults) <= 24:
                pc = uc.reg_read(UC_ARM64_REG_PC)
                _hitbase = next((b for b, i in e.backfills if b <= address < b + len(i)), None)
                log('[mem-fault] acc=%d addr=0x%x size=%d pc_off=0x%x → %s'
                    % (access, address, size, pc - DEV_BASE,
                       ('回填@0x%x' % _hitbase) if _hitbase is not None else '零页映射'))
            return True
        except unicorn.unicorn.UcError:
            return False

    e.uc.hook_add(UC_HOOK_MEM_UNMAPPED, mem_fault)

    def rd(uc, addr, n):
        try:
            return bytes(uc.mem_read(addr, n))
        except unicorn.unicorn.UcError:
            return None

    def keyrel(k, K16):
        if not k or not K16:
            return '?'
        if k == K16:
            return 'EQUAL'
        if k == K16[::-1]:
            return 'REVERSED'
        x = bytes(a ^ b for a, b in zip(k, K16))
        if len(set(x)) == 1:
            return 'XOR-CONST 0x%02x' % x[0]
        tag = ''
        if x[:4] == b'\x00' * 4:
            tag = ' 前4字节相同'
        if x[-4:] == b'\x00' * 4:
            tag += ' 后4字节相同'
        return 'xor=%s%s' % (x.hex(), tag)

    def evp_init_cb(uc, addr, size, ud):
        x3 = uc.reg_read(RX[3])
        x4 = uc.reg_read(RX[4])
        k = rd(uc, x3, 16)
        v = rd(uc, x4, 16)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        log('[EVP_Init] key=%s iv=%s lr_off=0x%x K16关系=%s'
            % (k.hex() if k else '-', v.hex() if v else '-', lr - DEV_BASE,
               keyrel(k, K16)))
        CAPTURES.append((k, v))

    def generic(label):
        def cb(uc, addr, size, ud):
            a = [uc.reg_read(RX[i]) for i in range(5)]
            lr = uc.reg_read(UC_ARM64_REG_LR)
            extra = ''
            if label == 'RSA_private_decrypt':
                CAPTURES.append(('rsa_out', a[2]))
                extra = ' out=0x%x' % a[2]
            log('[%s] x0-x4=%s lr_off=0x%x%s'
                % (label, ' '.join(hex(v) for v in a), lr - DEV_BASE, extra))
        return cb

    def throw_cb(uc, addr, size, ud):
        x0 = uc.reg_read(RX[0])
        tinfo = uc.reg_read(RX[1])
        nm = ''
        try:
            nm_p = int.from_bytes(bytes(uc.mem_read(tinfo + 8, 8)), 'little')
            nm = rd_c(uc, nm_p) or ''
        except unicorn.unicorn.UcError:
            pass
        lr = uc.reg_read(UC_ARM64_REG_LR)
        log('[throw] thrown=0x%x type=%r lr_off=0x%x' % (x0, nm, lr - DEV_BASE))
        try:
            msg = e.str_obj(x0 + 8)
            log('[throw] 消息: %r' % (msg[:600],))
        except Exception as ex:
            log('[throw] 消息读取失败: %s' % ex)
        # V12: x29 帧链 — 直接看抛出点之上的调用者
        try:
            x29 = uc.reg_read(UC_ARM64_REG_X29)
            frames = []
            for _ in range(8):
                if not (0x701e0000 <= x29 < 0x70200000):
                    break
                nx, lr = struct.unpack('<QQ', rd(uc, x29, 16))
                off = lr - DEV_BASE
                frames.append('lr_off=0x%x' % off if 0 <= off < 0x800000 else 'lr=0x%x' % lr)
                x29 = nx
            log('[throw] 帧链: %s' % ' <- '.join(frames))
        except Exception as ex:
            log('[throw] 帧链读取失败: %s' % ex)

    def raise_cb(uc, addr, size, ud):
        log('[raise-hook] 到达 _Unwind_RaiseException 调用点, 开始手工回退')
        ok = manual_unwind(uc)
        if not ok:
            log('[raise-hook] 回退失败, 放行真 libunwind (预期崩)')

    def free_cb(uc, addr, size, ud):
        log('[!!] free_exception 被调 → 异常未被捕获(落地失败)')
        uc.emu_stop()

    def bc_cb(uc, addr, size, ud):
        x0 = uc.reg_read(RX[0])
        cls = rd(uc, x0, 8)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        log('[begin_catch] U=0x%x class=%s lr_off=0x%x'
            % (x0, cls.hex() if cls else '-', lr - DEV_BASE))

    def ec_cb(uc, addr, size, ud):
        lr = uc.reg_read(UC_ARM64_REG_LR)
        log('[end_catch] lr_off=0x%x' % (lr - DEV_BASE))

    # ---- V10 §4.1c: 崩溃点 0x30cce0 (blr [sp+8]) 现场观测 ----
    def cce0_cb(uc, addr, size, ud):
        sp = uc.reg_read(UC_ARM64_REG_SP)
        xs = [uc.reg_read(RX[i]) for i in range(4)]
        s8 = rd(uc, sp + 8, 8)
        s0 = rd(uc, sp, 8)
        log('[cce0] SP=0x%x [sp]=0x%x [sp+8]=0x%x x0-x3=%s'
            % (sp, int.from_bytes(s0, 'little') if s0 else 0,
               int.from_bytes(s8, 'little') if s8 else 0,
               ' '.join(hex(v) for v in xs)))
        d = rd(uc, xs[0], 4096)
        if d:
            log('[cce0] x0 dump 4KB: %r' % d[:2048])

    def cce8_cb(uc, addr, size, ud):
        xs = [uc.reg_read(RX[i]) for i in range(4)]
        d = rd(uc, xs[0], 2048)
        log('[cce8] blr 返回点: x0-x3=%s x0dump=%r'
            % (' '.join(hex(v) for v in xs), d[:1024]))

    # ---- V10 §4.1e: pad 落地观测 (H2) ----
    def pad_cb(uc, addr, size, ud):
        sp = uc.reg_read(UC_ARM64_REG_SP)
        x22 = uc.reg_read(UC_ARM64_REG_X22)
        s8 = rd(uc, sp + 8, 8)
        log('[pad-entry] x22=0x%x [sp+8]=0x%x (写槽前)'
            % (x22, int.from_bytes(s8, 'little') if s8 else 0))

    def pad_after_str(uc, addr, size, ud):
        sp = uc.reg_read(UC_ARM64_REG_SP)
        s8 = rd(uc, sp + 8, 8)
        log('[pad-str] 写后 [sp+8]=0x%x'
            % (int.from_bytes(s8, 'little') if s8 else 0))

    def pad_x20(uc, addr, size, ud):
        x20 = uc.reg_read(UC_ARM64_REG_X20)
        d = rd(uc, x20, 96)
        log('[pad-x20] x20=0x%x raw=%r' % (x20, d))
        try:
            log('[pad-x20] str_obj=%r' % (e.str_obj(x20),))
        except Exception:
            pass

    # ---- V10 §4.1d: 真回调桩 (独立页, 不经 _do_stub 以免改写 x0) ----
    def app_cb_dump(uc, addr, size, ud):
        xs = [uc.reg_read(RX[i]) for i in range(4)]
        lr = uc.reg_read(UC_ARM64_REG_LR)
        log('[app_cb] 进入回调! x0-x3=%s lr_off=0x%x'
            % (' '.join(hex(v) for v in xs), lr - DEV_BASE))
        d = rd(uc, xs[0], 4096)
        if d:
            log('[app_cb] x0 dump 4KB: %r' % d[:2048])
        for j in (1, 3):
            dj = rd(uc, xs[j], 48)
            if dj:
                log('[app_cb] x%d dump 48B: %r' % (j, dj))
        CAPTURES.append(('app_cb', xs[0]))

    e.uc.mem_map(CB_ADDR, 0x1000, UC_PROT_ALL)
    e.uc.mem_write(CB_ADDR, struct.pack('<I', 0xD65F03C0))  # ret

    def H(cb, begin, end):
        e.uc.hook_add(UC_HOOK_CODE, cb, begin=begin, end=end)

    # 注意: 全部 begin=end=X —— end=X+4 会双发 (V10 §4.1a)
    H(generic('EVP_DecryptUpdate'), begin=DEV_BASE + EVP_DUPDATE, end=DEV_BASE + EVP_DUPDATE)
    H(evp_init_cb, begin=DEV_BASE + EVP_DINIT, end=DEV_BASE + EVP_DINIT)
    H(generic('RSA_private_decrypt'), begin=DEV_BASE + RSA_PRIV_DEC, end=DEV_BASE + RSA_PRIV_DEC)
    H(generic('aes_set_dec_key'), begin=DEV_BASE + AES_SET_DEC, end=DEV_BASE + AES_SET_DEC)
    H(generic('aes_cbc'), begin=DEV_BASE + AES_CBC, end=DEV_BASE + AES_CBC)
    H(generic('EVP_DecryptFinal'), begin=DEV_BASE + EVP_DFINAL, end=DEV_BASE + EVP_DFINAL)
    # §4.1b: Cipher / PKEY 路线 (业务解密可能不走 DecryptInit_ex)
    H(evp_init_cb, begin=DEV_BASE + EVP_CINIT_EX, end=DEV_BASE + EVP_CINIT_EX)
    H(generic('EVP_CipherUpdate'), begin=DEV_BASE + EVP_CUPDATE, end=DEV_BASE + EVP_CUPDATE)
    H(generic('EVP_CipherFinal'), begin=DEV_BASE + EVP_CFINAL, end=DEV_BASE + EVP_CFINAL)
    H(generic('EVP_CipherFinal_ex'), begin=DEV_BASE + EVP_CFINAL_EX, end=DEV_BASE + EVP_CFINAL_EX)
    H(generic('EVP_PKEY_decrypt_init'), begin=DEV_BASE + PKEY_DEC_INIT, end=DEV_BASE + PKEY_DEC_INIT)
    H(generic('EVP_PKEY_decrypt'), begin=DEV_BASE + PKEY_DEC, end=DEV_BASE + PKEY_DEC)
    # 加密族（结果重新封信封走 Encrypt 路线）
    H(evp_init_cb, begin=DEV_BASE + EVP_EINIT_EX, end=DEV_BASE + EVP_EINIT_EX)
    H(generic('EVP_EncryptUpdate'), begin=DEV_BASE + EVP_EUPDATE, end=DEV_BASE + EVP_EUPDATE)
    H(generic('EVP_EncryptFinal_ex'), begin=DEV_BASE + EVP_EFINAL_EX, end=DEV_BASE + EVP_EFINAL_EX)
    # §4.2b: api_encrypt 路线 — RSA_public_encrypt x1=32B(key+iv) 是金矿
    def rsa_pub_enc_cb(uc, addr, size, ud):
        xs = [uc.reg_read(RX[i]) for i in range(5)]
        frm = rd(uc, xs[1], 48)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        log('[RSA_pub_enc] flen=%d padding=%d from=%r lr_off=0x%x'
            % (xs[0], xs[4], frm, lr - DEV_BASE))
        CAPTURES.append(('rsa_keyiv', frm))
    def rand_cb(uc, addr, size, ud):
        xs = [uc.reg_read(RX[i]) for i in range(2)]
        log('[RAND_bytes] buf=0x%x num=%d' % (xs[0], xs[1]))
        try:
            if xs[1] == 16 and not RAND_K16:
                _lr = uc.reg_read(UC_ARM64_REG_LR)
                _buf, _n = xs[0], xs[1]
                def _rand_ret(_uc, _a, _s, _u, _b=_buf, _l=_lr):
                    try:
                        _rb = rd(_uc, _b, 16)
                        RAND_K16.append(_rb)
                        log('[RAND_K16] %s (ret@0x%x)' % (_rb.hex(), _l - DEV_BASE))
                    except Exception as _ex:
                        log('[RAND_K16] 读失败 %s' % _ex)
                    return False
                e.uc.hook_add(UC_HOOK_CODE, _rand_ret, begin=_lr, end=_lr)
        except Exception as _ex:
            log('[RAND_K16] 挂钩失败 %s' % _ex)
        CAPTURES.append(('rand_buf', xs[0]))
    H(rsa_pub_enc_cb, begin=DEV_BASE + RSA_PUB_ENC, end=DEV_BASE + RSA_PUB_ENC)
    H(rand_cb, begin=DEV_BASE + RAND_BYTES, end=DEV_BASE + RAND_BYTES)
    # V12: runtime_error ctor 桩(0x612e00, 构建函数 0x373a84 抛点) — 入口 x1=C串消息
    def rt_ctor_cb(uc, addr, size, ud):
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        try:
            msg = e.cstr(x1, 256)
            log('[runtime_error] msg=%r (x1=0x%x)' % (msg, x1))
        except Exception:
            log('[runtime_error] x1=0x%x 消息未映射' % x1)
    H(rt_ctor_cb, begin=DEV_BASE + 0x612e00, end=DEV_BASE + 0x612e00)
    # V12: 构建函数 0x373a30 = blr x8 (b64 解码调用点) — 抛 Base64 失败前最后一次调用
    def b64_call_cb(uc, addr, size, ud):
        xs = [uc.reg_read(RX[i]) for i in range(4)]
        fn = uc.reg_read(RX[8])
        log('[b64call@0x373a30] x8=0x%x x0-x3=0x%x 0x%x 0x%x 0x%x' % (fn, xs[0], xs[1], xs[2], xs[3]))
        for j in (1, 2):
            dj = rd(uc, xs[j], 96)
            if dj:
                log('[b64call] x%d 前96B: %r' % (j, dj))
    H(b64_call_cb, begin=DEV_BASE + 0x373a30, end=DEV_BASE + 0x373a30)
    # V12: 0x373de4 调用返回点 — x0=sret(libc++ string {cap,size,ptr}), dump 被 JSON 解析的串
    def sret_cb(uc, addr, size, ud):
        sp = uc.reg_read(RX[8])
        if not (0x50000000 <= sp < 0x54000000 or 0x701e0000 <= sp < 0x70200000):
            sp = uc.reg_read(RX[0])
        try:
            cap, ln = struct.unpack('<QQ', rd(uc, sp, 16))
            dp = struct.unpack('<Q', rd(uc, sp + 16, 8))[0]
            if (cap & 1) and 0 < ln < 0x10000 and dp:
                body = rd(uc, dp, min(ln, 512))
                log('[sret@0x373de8] len=%d data=%r' % (ln, body))
            else:
                log('[sret@0x373de8] 短串/SSO cap=0x%x ln=%d raw=%r' % (cap, ln, rd(uc, sp, 48)))
        except Exception as ex:
            log('[sret@0x373de8] 读取失败 %s' % ex)
    H(sret_cb, begin=DEV_BASE + 0x373de8, end=DEV_BASE + 0x373de8)
    # V12: 跟踪 x19 字符串演化 (RSA 输出 → 应 b64 → JSON dump)
    def dump_str_at(tag):
        def cb(uc, addr, size, ud):
            sp = uc.reg_read(RX[19])
            try:
                b0, b1 = struct.unpack('<QQ', rd(uc, sp, 16))
                ln = b1 - b0 if (0 < b1 - b0 < 0x10000) else 0
                body = rd(uc, b0, min(ln, 400)) if (ln and 0x50000000 <= b0 < 0x54000000) else b''
                log('[str@%s] buf=0x%x len=%d data=%r' % (tag, b0, ln, body))
            except Exception as ex:
                log('[str@%s] 读取失败 %s' % (tag, ex))
        return cb
    H(dump_str_at('0x373dd0-rsa-ret'), begin=DEV_BASE + 0x373dd0, end=DEV_BASE + 0x373dd0)
    # V12: RSA 输出替换为 ASCII — P0 结构已捕获(flen=16 PKCS1), 只需流程活到 EVP_EncryptInit
    def ascii_patch_cb(uc, addr, size, ud):
        sp = uc.reg_read(RX[19])
        try:
            b0, b1 = struct.unpack('<QQ', rd(uc, sp, 16))
            ln = b1 - b0
            if 0 < ln <= 0x1000 and 0x50000000 <= b0 < 0x54000000:
                uc.mem_write(b0, b'A' * ln)
                log('[ascii-patch@0x373dd0] buf=0x%x len=%d → 全A' % (b0, ln))
        except Exception:
            pass
    H(ascii_patch_cb, begin=DEV_BASE + 0x373dd0, end=DEV_BASE + 0x373dd0)
    # V12: json dump 调用点 (bl 0x356f74 @0x31060c) — x1=json 对象, 解出内部字符串
    def json_dump_cb(uc, addr, size, ud):
        jo = uc.reg_read(RX[1])
        # 保守设参: ensure_ascii=1(转义非ASCII), error_handler=replace(1) — 具体位次在 w3/w4/w5 中
        uc.reg_write(RX[2], 0)
        uc.reg_write(RX[3], 1)
        uc.reg_write(RX[4], 1)
        uc.reg_write(RX[5], 1)
        try:
            raw = rd(uc, jo, 64)
            log('[json-dump@0x31060c] obj=0x%x raw=%s' % (jo, raw.hex()))
            for probe in struct.unpack('<8Q', raw[:64]):
                if 0x50000000 <= probe < 0x54000000:
                    try:
                        pdat = rd(uc, probe, 64)
                        log('[json-dump] ptr 0x%x → %s' % (probe, pdat.hex()))
                    except Exception:
                        pass
        except Exception as ex:
            log('[json-dump] 解析失败 %s' % ex)
    H(json_dump_cb, begin=DEV_BASE + 0x31060c, end=DEV_BASE + 0x31060c)
    # V12: nlohmann utf8 校验出口 (0x35a418 cbnz w8 → 无效则进错误块抛 type_error.316)
    # 强制 w8=1 让循环继续, dump 完成 → 流程活到 EVP_EncryptInit (拿 P1 的 key/iv)
    def utf8_force_cb(uc, addr, size, ud):
        w8 = uc.reg_read(RX[8]) & 0xFFFFFFFF
        if w8 == 0:
            uc.reg_write(RX[8], 1)
            log('[utf8-force@0x35a418] 无效字节被放行 (dump 继续)')
    H(utf8_force_cb, begin=DEV_BASE + 0x35a418, end=DEV_BASE + 0x35a418)
    H(dump_str_at('0x373e14'), begin=DEV_BASE + 0x373e14, end=DEV_BASE + 0x373e14)
    H(dump_str_at('0x373e58'), begin=DEV_BASE + 0x373e58, end=DEV_BASE + 0x373e58)
    # V12: 构建函数 0x373a30→0x374060 逐调用轨迹 (确认 RSA BL 是否到达 / 各分支走向)
    # V12: 构建函数 0x373000-0x374c00 全部 bl/blr 轨迹
    def path_cb(uc, addr, size, ud):
        off = addr - DEV_BASE
        w = struct.unpack('<I', bytes(uc.mem_read(addr, 4)))[0]
        is_bl = (w & 0xFC000000) == 0x94000000
        is_blr = (w & 0xFFFFFC1F) == 0xD63F0000
        if not (is_bl or is_blr):
            return
        xs = [uc.reg_read(RX[i]) for i in range(4)]
        lr = uc.reg_read(UC_ARM64_REG_LR)
        tgt = ('@0x%x' % uc.reg_read(RX[8])) if is_blr else ''
        log('[path] %s 0x%x%s x0-x3=0x%x 0x%x 0x%x 0x%x lr_off=0x%x'
            % ('bl ' if is_bl else 'blr', off, tgt, xs[0], xs[1], xs[2], xs[3], lr - DEV_BASE))
    H(path_cb, begin=DEV_BASE + 0x373000, end=DEV_BASE + 0x374c00)
    # V12g: api_encrypt 处理器区间全调用追踪 — 定位 b64 编码调用 (x1=16/256 长度特征)
    def path2_cb(uc, addr, size, ud):
        off = addr - DEV_BASE
        w = struct.unpack('<I', bytes(uc.mem_read(addr, 4)))[0]
        is_bl = (w & 0xFC000000) == 0x94000000
        is_blr = (w & 0xFFFFFC1F) == 0xD63F0000
        if not (is_bl or is_blr):
            return
        xs = [uc.reg_read(RX[i]) for i in range(4)]
        lr = uc.reg_read(UC_ARM64_REG_LR)
        tgt = uc.reg_read(RX[8]) if is_blr else 0
        tdesc = ('@0x%x' % tgt) if is_blr else ('→0x%x' % (off + (struct.unpack('<I', bytes(uc.mem_read(addr, 4)))[0] & 0x03FFFFFF) - (0x04000000 if (struct.unpack('<I', bytes(uc.mem_read(addr, 4)))[0] & 0x02000000) else 0) * 4 - (0 << 0)))
        extra = b''
        for j in (0, 1):
            if 0x50000000 <= xs[j] < 0x54000000:
                try:
                    extra += b' x%d=%r' % (j, rd(uc, xs[j], 24))
                except Exception:
                    pass
        log('[h-path] %s 0x%x %s x0-x3=0x%x 0x%x 0x%x 0x%x lr_off=0x%x%s'
            % ('bl ' if is_bl else 'blr', off, tdesc, xs[0], xs[1], xs[2], xs[3], lr - DEV_BASE, extra.decode('latin1')))
    H(path2_cb, begin=DEV_BASE + 0x30b000, end=DEV_BASE + 0x30cd00)
    # V12h: rodata 密码表读取探测 — SBOX(0x1dfc00)/invSBOX(0x1e03b0)/config 16B 块区
    # 若 P1 走软件 AES, 必然触发 SBOX 字节读; PC 可定位实现函数
    PHASE = ['init']
    table_hits = {}

    def table_read_cb(uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC) - DEV_BASE
        k = (PHASE[0], pc)
        if k not in table_hits:
            table_hits[k] = [0, address - DEV_BASE]
        table_hits[k][0] += 1

    e.uc.hook_add(UC_HOOK_MEM_READ, table_read_cb,
                  begin=DEV_BASE + 0x1dfc00, end=DEV_BASE + 0x1e0500)
    # config 里 alphabet 堆拷贝 (上次 run dump 定位) — b64 编码器必读
    for _ab in (0x50006010, 0x5000f570, 0x500201e0, 0x50031e50):
        try:
            e.uc.hook_add(UC_HOOK_MEM_READ, table_read_cb,
                          begin=_ab, end=_ab + 0x40)
        except Exception:
            pass
    # 0x2cd8b0 = SBOX→栈→256 次混淆变换→x1[256] 表构造器
    def tblbuild_cb(uc, addr, size, ud):
        x0, x1, x2 = (uc.reg_read(RX[i]) for i in range(3))
        log('[tblbuild@0x2cd8b0] phase=%s x0=0x%x x1=0x%x x2=0x%x lr=0x%x'
            % (PHASE[0], x0, x1, x2, uc.reg_read(UC_ARM64_REG_LR) - DEV_BASE))
        if x1:
            TBL_BUILD_OUT.append((x1, x2))
    TBL_BUILD_OUT = []
    H(tblbuild_cb, begin=DEV_BASE + 0x2cd8b0, end=DEV_BASE + 0x2cd8b0)
    # V12i: 自定义密码模块入口链 0x303df0/0x3050f8 → 0x2d6f7c → 0x2cdeb8 → 0x2cd8b0
    def chain_cb(tag):
        def cb(uc, addr, size, ud):
            xs = [uc.reg_read(RX[i]) for i in range(5)]
            parts = ['[chain-%s] ph=%s x0-x4=0x%x 0x%x 0x%x 0x%x 0x%x'
                     % (tag, PHASE[0], *xs)]
            for j in range(3):
                v = xs[j]
                if DEV_BASE + 0x600000 <= v < DEV_BASE + 0x700000:
                    try:
                        parts.append(' s%d=%r' % (j, libcxx_str(uc, v)))
                    except Exception:
                        pass
                elif 0x50000000 <= v < 0x54000000:
                    try:
                        parts.append(' x%d=%r' % (j, rd(uc, v, 32)))
                    except Exception:
                        pass
            log(' '.join(parts))
        return cb
    for _nm, _off in (('2d6f7c', 0x2d6f7c), ('2cdeb8', 0x2cdeb8), ('2d9014', 0x2d9014),
                      ('2d9ed0', 0x2d9ed0), ('2ce1e8', 0x2ce1e8), ('2e5880', 0x2e5880),
                      ('303df0', 0x303df0), ('3050f8', 0x3050f8)):
        H(chain_cb(_nm), begin=DEV_BASE + _off, end=DEV_BASE + _off)
    # V13: 密码模块全区执行追踪 (TRACE_CIPHER=1) — 用于定位解密路径
    if os.environ.get('TRACE_CIPHER'):
        import struct as _st
        _seen = set()
        log('[*] TRACE_CIPHER 启用 (只记录 sub sp,sp,#imm 序言)')

        def trace_cb(uc, addr, size, ud):
            off = addr - DEV_BASE
            if off in _seen:
                return
            _seen.add(off)
            try:
                _w = _st.unpack('<I', bytes(uc.mem_read(addr, 4)))[0]
            except Exception:
                return
            if (_w & 0xFFC003FF) == 0xD10003FF:
                log('[fn] 0x%x' % off)

        for _t in (0x2ce598, 0x2e6364):
            def _mk(tag):
                def _cb(uc, addr, size, ud):
                    xs = [uc.reg_read(RX[i]) for i in range(5)]
                    parts = ['[DEC-%s] x0-x4=%s' % (tag, ' '.join('0x%x' % v for v in xs))]
                    for j, v in enumerate(xs):
                        if 0x50000000 <= v < 0x54000000 or 0x70000000 <= v < 0x72000000:
                            try:
                                parts.append('  x%d=%r' % (j, rd(uc, v, 32)))
                            except Exception:
                                pass
                    log(' '.join(parts))
                return _cb
            H(_mk('%x' % _t), begin=DEV_BASE + _t, end=DEV_BASE + _t)
        e.uc.hook_add(UC_HOOK_CODE, trace_cb, begin=DEV_BASE + 0x2c0000, end=DEV_BASE + 0x2f0000)

    # V12: PEM 解析内链入口 — 最后一个出现的就是失败层
    for _nm, _off in (('PEM_ASN1_read_bio', 0x42edf0), ('PEM_read_bio_ex', 0x42e200),
                      ('pem_read_bio', 0), ('BIO_gets', 0x37b6a4),
                      ('EVP_DecodeUpdate', 0x386de8), ('d2i_PUBKEY', 0x46a290),
                      ('d2i_PUBKEY_bio', 0x466db0), ('PEM_bytes_read_bio', 0x42d128),
                      ('BIO_ctrl', 0x37b890)):
        if _off:
            H(generic(_nm), begin=DEV_BASE + _off, end=DEV_BASE + _off)
    # V12: d2i_PUBKEY 深层 — 找 ASN.1 解析失败点
    for _nm, _off in (('ASN1_item_d2i', 0x38cacc), ('X509_PUBKEY_get0', 0x46a0d4),
                      ('OBJ_obj2nid', 0x42acf4), ('RSA_new', 0x43ecec),
                      ('d2i_RSAPublicKey', 0x43daec), ('BN_new', 0x390814),
                      ('BN_bin2bn', 0x390bcc), ('EVP_PKEY_new', 0x3fdf78),
                      ('EVP_PKEY_set1_RSA', 0x3fe7b0), ('EVP_PKEY_get1_RSA', 0x3fe854)):
        if _off:
            H(generic(_nm), begin=DEV_BASE + _off, end=DEV_BASE + _off)
    # V12: OBJ/EVP 类型判定 — ASN1_OBJECT 字段 + nid 值
    def obj2nid_cb(uc, addr, size, ud):
        a = uc.reg_read(RX[0])
        try:
            # ASN1_OBJECT: sn@+0 ln@+8 nid@+0x10 length@+0x14 data@+0x18 flags@+0x20
            nid, ln = struct.unpack('<ii', rd(uc, a + 0x10, 8))
            dp = struct.unpack('<Q', rd(uc, a + 0x18, 8))[0]
            data = rd(uc, dp, min(ln, 16)) if (0 < ln < 32 and dp) else b''
            log('[OBJ_obj2nid] obj=0x%x nid=%d len=%d oid=%s'
                % (a, nid, ln, data.hex()))
        except Exception as ex:
            log('[OBJ_obj2nid] obj=0x%x 字段读取失败 %s' % (a, ex))
    H(obj2nid_cb, begin=DEV_BASE + 0x42acf4, end=DEV_BASE + 0x42acf4)
    def pkey_settype_cb(uc, addr, size, ud):
        x0 = uc.reg_read(RX[0]); w1 = uc.reg_read(RX[1]) & 0xFFFFFFFF
        log('[EVP_PKEY_set_type] pkey=0x%x nid=%d' % (x0, w1))
    H(pkey_settype_cb, begin=DEV_BASE + 0x3fde90, end=DEV_BASE + 0x3fde90)
    # V12: obj bsearch 比较函数 — 逐步看 mid/len/memcmp 输入
    def obj_cmp_cb(uc, addr, size, ud):
        try:
            kp = struct.unpack('<Q', rd(uc, uc.reg_read(RX[0]), 8))[0]
            eidx = struct.unpack('<i', rd(uc, uc.reg_read(RX[1]), 4))[0]
            klen = struct.unpack('<i', rd(uc, kp + 0x14, 4))[0]
            kdp = struct.unpack('<Q', rd(uc, kp + 0x18, 8))[0]
            kdat = rd(uc, kdp, min(klen, 16)).hex() if (0 < klen < 32 and kdp) else '?'
            # 表项: nid@+0x10 len@+0x14 data@+0x18 (0x636988 + idx*0x28)
            toff = 0x636988 + eidx * 0x28
            tln = struct.unpack('<i', rd(uc, DEV_BASE + toff + 0x14, 4))[0]
            tdp = struct.unpack('<Q', rd(uc, DEV_BASE + toff + 0x18, 8))[0]
            tdat = rd(uc, tdp, min(tln, 16)).hex() if (0 < tln < 32 and tdp) else '?'
            cexp = (klen > tln) - (klen < tln)
            if cexp == 0 and kdat != '?' and tdat != '?':
                cexp = (kdat > tdat) - (kdat < tdat)
            log('[obj_cmp] eidx=%d klen=%d tlen=%d cexp=%d key=%s tbl=%s'
                % (eidx, klen, tln, cexp, kdat, tdat))
        except Exception as ex:
            log('[obj_cmp] 参数读取失败 %s' % ex)
    H(obj_cmp_cb, begin=DEV_BASE + 0x42b99c, end=DEV_BASE + 0x42b99c)
    H(evp_init_cb, begin=DEV_BASE + EVP_DINIT2, end=DEV_BASE + EVP_DINIT2)
    H(generic('EVP_DecryptFinal'), begin=DEV_BASE + EVP_DFINAL2, end=DEV_BASE + EVP_DFINAL2)
    # 异常机制
    H(throw_cb, begin=DEV_BASE + THROW, end=DEV_BASE + THROW)
    H(raise_cb, begin=DEV_BASE + THROW_RAISE, end=DEV_BASE + THROW_RAISE)
    H(bc_cb, begin=DEV_BASE + BEGIN_CATCH, end=DEV_BASE + BEGIN_CATCH)
    H(ec_cb, begin=DEV_BASE + END_CATCH, end=DEV_BASE + END_CATCH)
    H(free_cb, begin=DEV_BASE + FREE_EXC, end=DEV_BASE + FREE_EXC)
    # §4.1c/e: 崩溃点 + catch pad
    H(cce0_cb, begin=DEV_BASE + CCE0, end=DEV_BASE + CCE0)
    H(cce8_cb, begin=DEV_BASE + CCE8, end=DEV_BASE + CCE8)
    H(pad_cb, begin=DEV_BASE + PAD_ENTRY, end=DEV_BASE + PAD_ENTRY)
    H(pad_after_str, begin=DEV_BASE + PAD_AFTER_STR, end=DEV_BASE + PAD_AFTER_STR)
    H(pad_x20, begin=DEV_BASE + PAD_X20, end=DEV_BASE + PAD_X20)
    # §4.1d: 真回调
    H(app_cb_dump, begin=CB_ADDR, end=CB_ADDR)

    # V12b: keystore 追踪 — setter assign 点 + builder 入口 + 序列化串流
    KS_KEY, KS_IV = DEV_BASE + 0x689528, DEV_BASE + 0x689540

    def libcxx_str(uc, addr, maxlen=64):
        try:
            raw = rd(uc, addr, 24)
        except Exception:
            return b'?(unreadable)'
        if not (raw[0] & 1):
            n = raw[0] >> 1
            return raw[1:1 + min(n, 23)]
        try:
            cap, ln = struct.unpack('<QQ', raw[:16])
            dp = struct.unpack('<Q', raw[16:24])[0]
            if (cap & 1) and 0 < ln <= maxlen and dp:
                return rd(uc, dp, ln)
            return b'?(long cap=0x%x ln=%d dp=0x%x)' % (cap, ln, dp)
        except Exception as ex:
            return ('?(%s)' % ex).encode()

    def setter_cb(tag):
        def cb(uc, addr, size, ud):
            x0 = uc.reg_read(RX[0])
            x1 = uc.reg_read(RX[1])
            log('[setter-%s] dst=0x%x src=0x%x str=%r raw=%r'
                % (tag, x0, x1, libcxx_str(uc, x1), rd(uc, x1, 32)))
        return cb
    H(setter_cb('key'), begin=DEV_BASE + 0x2fd96c, end=DEV_BASE + 0x2fd96c)
    H(setter_cb('iv'), begin=DEV_BASE + 0x2fda44, end=DEV_BASE + 0x2fda44)

    def builder_cb(uc, addr, size, ud):
        x0, x1, x2 = (uc.reg_read(RX[i]) for i in range(3))
        log('[builder@0x374870] json(x0)=%r' % libcxx_str(uc, x0, 300))
        log('[builder]   key(x1)=0x%x %r' % (x1, libcxx_str(uc, x1)))
        log('[builder]   iv(x2)=0x%x %r' % (x2, libcxx_str(uc, x2)))
    H(builder_cb, begin=DEV_BASE + 0x374870, end=DEV_BASE + 0x374870)

    # nlohmann 序列化器逐值追踪: 0x356f74 dump 分派点, x1=&json (type@0, value@8)
    def ser_cb(uc, addr, size, ud):
        try:
            j = rd(uc, uc.reg_read(RX[1]), 16)
            t = j[0]
            if t == 3:  # string
                sp = struct.unpack('<Q', j[8:16])[0]
                try:
                    raw = rd(uc, sp, 24)
                except Exception:
                    return
                if not (raw[0] & 1):
                    ln = raw[0] >> 1
                    body = raw[1:1 + min(ln, 23)]
                else:
                    cap, ln = struct.unpack('<QQ', raw[:16])
                    dp = struct.unpack('<Q', raw[16:24])[0]
                    body = rd(uc, dp, min(ln, 400)) if (0 < ln <= 400 and dp) else b'?(ln=%d)' % ln
                log('[ser] string len=%d %r' % (ln, body))
            elif t in (1, 2):
                log('[ser] %s enter' % ('object' if t == 1 else 'array'))
        except Exception:
            pass
    H(ser_cb, begin=DEV_BASE + 0x356f74, end=DEV_BASE + 0x356f74)

    # V12c: json::dump(0x310444) 入口 — 遍历 nlohmann object 成员 (libc++ __tree)
    def dump_json_obj(uc, jp, depth=0, seen=None):
        if seen is None:
            seen = set()
        if depth > 3 or len(seen) > 24 or jp in seen:
            return
        seen.add(jp)
        try:
            thdr = rd(uc, jp, 16)
        except Exception:
            return
        if thdr[0] != 1:
            return
        mapp = struct.unpack('<Q', thdr[8:16])[0]
        try:
            beginp = struct.unpack('<Q', rd(uc, mapp, 8))[0]
            endleft = struct.unpack('<Q', rd(uc, mapp + 8, 8))[0]
            size = struct.unpack('<Q', rd(uc, mapp + 16, 8))[0]
        except Exception:
            return
        log('[json] object size=%d' % size)
        node = beginp
        endn = mapp + 8  # end node 地址(近似)
        while node and node not in seen and len(seen) < 40:
            seen.add(node)
            try:
                key = libcxx_str(uc, node + 32)
                vj = rd(uc, node + 56, 16)
                vt = vj[0]
            except Exception as ex:
                log('[json] 节点读取失败 %s' % ex)
                break
            if vt == 3:
                sp = struct.unpack('<Q', vj[8:16])[0]
                log('[json] %r => string %r' % (key, libcxx_str(uc, sp, 400)))
            elif vt == 1:
                sub = struct.unpack('<Q', vj[8:16])[0]
                log('[json] %r => object' % key)
                dump_json_obj(uc, node + 56, depth + 1, seen)
            elif vt == 2:
                log('[json] %r => array' % key)
            elif vt in (5, 6):
                try:
                    nv = struct.unpack('<q' if vt == 5 else '<Q', vj[8:16])[0]
                    log('[json] %r => int %d' % (key, nv))
                except Exception:
                    pass
            elif vt == 4:
                log('[json] %r => bool %d' % (key, vj[8]))
            else:
                log('[json] %r => type=%d' % (key, vt))
            # 中序后继: 有右子→右最左; 否则向上直到是左子
            try:
                nxt = struct.unpack('<Q', rd(uc, node + 8, 8))[0]  # __right_
                if nxt:
                    cur = nxt
                    while True:
                        l = struct.unpack('<Q', rd(uc, cur, 8))[0]
                        if not l or l in seen:
                            break
                        cur = l
                    node = cur
                else:
                    parent = struct.unpack('<Q', rd(uc, node + 16, 8))[0]
                    node = parent
            except Exception:
                break

    def dump_entry_cb(uc, addr, size, ud):
        jp = uc.reg_read(RX[0])
        log('[dump@0x310444] json=0x%x type=%d' % (jp, rd(uc, jp, 1)[0]))
        dump_json_obj(uc, jp)
    H(dump_entry_cb, begin=DEV_BASE + 0x310444, end=DEV_BASE + 0x310444)

    # V12f: data 成员缓冲区页的写入者定位 (找 b64 编码器)
    wr_log = []

    def wr_page_cb(uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        wr_log.append((address, size, value, pc - DEV_BASE))

    e.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, wr_page_cb,
                  begin=0x50010000, end=0x50011000)

    upd_state = {}

    def upd_call(uc, addr, size, ud):
        upd_state['out'] = uc.reg_read(RX[1])
        print('[upd-call] out=0x%x' % upd_state['out'], flush=True)

    def upd_ret(uc, addr, size, ud):
        out = upd_state.get('out')
        if out:
            b = rd(uc, out, 128)
            print('[upd-ret] %r' % b, flush=True)

    e.uc.hook_add(UC_HOOK_CODE, upd_call, begin=DEV_BASE + 0x375284, end=DEV_BASE + 0x375284)
    e.uc.hook_add(UC_HOOK_CODE, upd_ret, begin=DEV_BASE + 0x375288, end=DEV_BASE + 0x375288)

    cfg = json.dumps(CONFIG, separators=(',', ':'))
    cfg_p = e.alloc(len(cfg) + 1)
    e.wr(cfg_p, cfg.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    log('[*] init 完成')
    PHASE[0] = 'post-init'

    # V12d: b64 字母表修复 — 0x312dc0 用 NEON 拷贝字母表/二进制块进配置对象,
    # emu 里可能拷坏 (NUL 污染 → b64 输出垃圾)。用 64B 二进制块锚定对象, 校验/重写字母表。
    CUST_ALPHABET = b'5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
    BLOB64 = bytes.fromhex('b0f467ce6d52b3dff5e1a03baa3ca266cf12a61b31118759ea10f8d0'
                           '5bf01ed4518fdd7fddee6e3153a4833b7caa67d6858751a61bcaf82cd3651bae')
    scan_regions = [(0x400024a00000 + 0x660000, 0x90000),   # .data/.bss
                    (0x50000000, 0x400000)]                  # emu 堆
    for sa, sl in scan_regions:
        try:
            buf = rd(e.uc, sa, sl)
        except Exception:
            continue
        pos = 0
        while True:
            i = buf.find(BLOB64[:24], pos)
            if i < 0:
                break
            pos = i + 1
            if buf[i:i + 64] != BLOB64:
                continue
            obj = sa + i
            alpha_addr = obj - 0x18
            try:
                cur = rd(e.uc, alpha_addr, 64)
            except Exception:
                continue
            if cur == CUST_ALPHABET:
                log('[alphabet-fix] 对象 @0x%x 字母表完好' % obj)
            else:
                e.wr(alpha_addr, CUST_ALPHABET)
                log('[alphabet-fix] 对象 @0x%x 字母表损坏已重写: %r → 完整64B' % (obj, cur[:16]))
            # 同对象可能还有其他 16B 成员 (0x1e03b0/0x1dfd80/0x1e0150 拷贝), 顺带报告
            try:
                ctx = rd(e.uc, obj - 0x30, 0xC0)
                log('[alphabet-fix] 对象上下文: %s' % ctx.hex())
            except Exception:
                pass

    if args.seed_store and K16:
        try:
            e.wr(KS_KEY + 1, K16)
            e.wr(KS_IV + 1, K16[::-1])
            log('[seed-store] KS_KEY=%r KS_IV=%r' % (K16, K16[::-1]))
        except Exception as ex:
            log('[seed-store] 写入失败 %s' % ex)
    if args.clear_first and args.action == 'api_encrypt':
        ck = json.dumps({"action": "clear_key", "payload": {}}, separators=(',', ':'))
        ckb = ch_encrypt(ck.encode())
        cp2 = e.alloc(len(ckb) + 1)
        e.wr(cp2, ckb.encode() + b"\x00")
        try:
            out2 = e.call(DEV_BASE + CALL_OFF, (cp2, CB_ADDR), timeout=120_000_000)
            log('[*] clear_key 完成 x0=0x%x captures=%d' % (out2 or 0, len(CAPTURES)))
        except unicorn.unicorn.UcError as ex:
            log('[!!] clear_key crash %s' % ex)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    PHASE[0] = 'api'
    try:
        out = e.call(DEV_BASE + CALL_OFF, (inp, CB_ADDR), timeout=600_000_000)
        log('[*] call x0=0x%x, captures=%d' % (out, len(CAPTURES)))
    except unicorn.unicorn.UcError as ex:
        pc = e.uc.reg_read(UC_ARM64_REG_PC)
        lr = e.uc.reg_read(UC_ARM64_REG_LR)
        log('[!!] crash %s PC=0x%x (off 0x%x) LR=0x%x (off 0x%x)'
            % (ex, pc, pc - DEV_BASE, lr, lr - DEV_BASE))
        log('[*] 最近桩: %s' % e.logs[-10:])
        snm = e.stub_syms.get(pc)
        lnm = e.stub_syms.get(lr)
        if snm or lnm:
            log('[*] 桩定位: PC=%s LR=%s' % (snm, lnm))

    finally:
        # V12h: 密码表/alphabet 读取统计 (按相位)
        if table_hits:
            top = sorted(table_hits.items(), key=lambda kv: -kv[1][0])[:24]
            for (ph, pc), (cnt, first) in top:
                log('[tbl-read] phase=%s pc_off=0x%x hits=%d first=0x%x' % (ph, pc, cnt, first))
        else:
            log('[tbl-read] 无命中')
        for x1, x2 in TBL_BUILD_OUT:
            try:
                log('[tblbuild-out] x1=0x%x x2=0x%x data=%s' % (x1, x2, rd(e.uc, x1, 64).hex()))
            except Exception:
                pass
        # V12b: 退出时 keystore dump + f(K16) 候选比对
        for nm, a in (('key', KS_KEY), ('iv', KS_IV)):
            try:
                b = rd(e.uc, a, 32)
                log('[ks-exit] %s @0x%x: %s |%s|' % (nm, a, b.hex(),
                    ''.join(chr(c) if 32 <= c < 127 else '.' for c in b)))
            except Exception as ex:
                log('[ks-exit] %s 读取失败 %s' % (nm, ex))
        k16 = None
        for tg, frm in CAPTURES:
            if tg == 'rsa_keyiv':
                k16 = frm[:16]
                break
        if k16:
            import base64 as _b64
            import hashlib as _h
            cust = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
            std = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
            cands = {
                'raw': k16,
                'hex32': k16.hex().encode(),
                'hex16a': k16.hex().encode()[:16],
                'hex16b': k16.hex().encode()[16:32],
                'md5': _h.md5(k16).digest(),
                'md5hex16': _h.md5(k16).hexdigest().encode()[:16],
                'b64std': _b64.b64encode(k16),
                'b64std16': _b64.b64encode(k16)[:16],
                'cb64': _b64.b64encode(k16).decode().translate(str.maketrans(std, cust)).encode(),
                'sha256a': _h.sha256(k16).digest()[:16],
                'sha256b': _h.sha256(k16).digest()[16:32],
            }
            for nm, a in (('key', KS_KEY), ('iv', KS_IV)):
                try:
                    cur = libcxx_str(e.uc, a)
                except Exception:
                    continue
                for cn, cv in cands.items():
                    if cv == cur:
                        log('[ks-match] %s == f(%s)[%s] = %r' % (nm, k16.hex(), cn, cv))
            log('[ks-exit] K16=%s 候选已比对' % k16.hex())
        # V12e: 整堆 dump — 离线搜 P1 密文/密钥结构
        try:
            segs = [(0x50000000, 0x500000), (0x400024a00000 + 0x660000, 0x90000)]
            outp = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..',
                                'captures', 'rsa_scan', 'emu_heap_dump.bin')
            with open(outp, 'wb') as fo:
                for sa, sl in segs:
                    try:
                        fo.write(rd(e.uc, sa, sl))
                    except Exception as ex:
                        log('[heapdump] 0x%x 段读取失败 %s' % (sa, ex))
                        fo.write(b'\x00' * sl)
            log('[heapdump] 已写 %s (堆 4MB + 数据段 0x90000, 顺序拼接)' % os.path.normpath(outp))
        except Exception as ex:
            log('[heapdump] 失败 %s' % ex)
        # V12f: 写入者统计 — data 缓冲区页的 top PC
        if wr_log:
            from collections import Counter
            cnt = Counter((pc, sz) for _, sz, _, pc in wr_log)
            log('[wrpage] 写入总数=%d top-PC:' % len(wr_log))
            for (pc, sz), n in cnt.most_common(12):
                log('[wrpage]   pc_off=0x%x size=%d 次数=%d' % (pc & 0xFFFFFFFF if pc >= 0 else pc, sz, n))
            # 首尾各 8 条原始记录
            for a, sz, v, pc in wr_log[:8]:
                log('[wrpage]   首 addr=0x%x size=%d val=0x%x pc_off=0x%x' % (a, sz, v, pc & 0xFFFFFFFF if pc >= 0 else pc))
            for a, sz, v, pc in wr_log[-8:]:
                log('[wrpage]   尾 addr=0x%x size=%d val=0x%x pc_off=0x%x' % (a, sz, v, pc & 0xFFFFFFFF if pc >= 0 else pc))

    if args.scan_store and RAND_K16:
        k16b = RAND_K16[-1]
        log('[scan-store] 目标 K16=%s' % k16b.hex())
        regions = [(0x400024a00000 + 0x600000, 0x200000, 'img-data'),
                   (0x50000000, 0x500000, 'heap')]
        for sa, sl, nm in regions:
            try:
                buf = rd(e.uc, sa, sl)
            except Exception as ex:
                log('[scan-store] %s 读失败 %s' % (nm, ex))
                continue
            pos, hits = 0, 0
            while hits < 12:
                i = buf.find(k16b, pos)
                if i < 0:
                    break
                pos = i + 1
                hits += 1
                a = sa + i
                ctx = buf[max(0, i - 32):i + 48]
                log('[scan-store] HIT %s @0x%x ctx=%s' % (nm, a, ctx.hex()))
            if not hits:
                log('[scan-store] %s 无命中' % nm)
    if args.then_decrypt and body:
        try:
            pl2 = {"action": "api_decrypt", "payload": {"data": json.dumps(body), "path": args.path}}
            for i in range(10):
                pl2['n%d' % i] = 'N0ISE%02dXYZABCD' % i
            enc2 = ch_encrypt(json.dumps(pl2, separators=(',', ':')).encode())
            inp2 = e.alloc(len(enc2) + 1)
            e.wr(inp2, enc2.encode() + b"\x00")
            PHASE[0] = 'api-decrypt-2nd'
            out2 = e.call(DEV_BASE + CALL_OFF, (inp2, CB_ADDR), timeout=600_000_000)
            log('[*] 2nd(api_decrypt) x0=0x%x, captures=%d' % (out2, len(CAPTURES)))
            if out2 and out2 > 0x1000:
                s2 = rd(e.uc, out2, 16384)
                if s2:
                    s2 = s2.split(b'\x00')[0]
                    log('[*] 2nd 返回串(%dB): %r' % (len(s2), s2[:600]))
                    open('research/tmp_then_dec_ret.bin', 'wb').write(s2)
        except unicorn.unicorn.UcError as ex:
            pc = e.uc.reg_read(UC_ARM64_REG_PC)
            lr = e.uc.reg_read(UC_ARM64_REG_LR)
            log('[!!] 2nd crash %s PC_off=0x%x LR_off=0x%x' % (ex, pc - DEV_BASE, lr - DEV_BASE))
            log('[*] 最近桩: %s' % e.logs[-8:])


if __name__ == '__main__':
    main()
