# -*- coding: utf-8 -*-
"""gen_engine.py v3 — 全域 trace 唯一 PC 集的 ARM64→C 转译.

- 翻译集: reports/pc_cover_all.txt (128 块 enc_big 全域唯一 PC)
- JT: [DEV_BASE, DEV_BASE+0x660000) 全范围, 空槽 abort
- MAGIC_RET(0x900000) → return X[0]
- OFF_AFTER_A1 / OFF_AFTER_E 两槽 → hook 桥 (明文注入 / body 记录)
"""
import os
import struct
import sys
import capstone

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "..", "libcore.so")
OUTDIR = os.path.join(HERE, "engine_c")
os.makedirs(OUTDIR, exist_ok=True)

BASE = 0x400024a00000
JT_N = 0x660000 // 4
MAGIC_OFF = 0x900000
HOOK_A1 = 0x304fb8
HOOK_E = 0x3050fc
HOOK_X = 0x2da498

b = open(SO, "rb").read()
e_phoff = int.from_bytes(b[0x20:0x28], "little")
e_phnum = int.from_bytes(b[0x38:0x3a], "little")
e_phentsize = int.from_bytes(b[0x36:0x38], "little")
loads = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, _, p_off, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<IIQQQQQQ", b, o)
    if p_type == 1:
        loads.append((p_vaddr, p_off, p_filesz))


def va2off(va):
    for v, o, sz in loads:
        if v <= va < v + sz:
            return o + (va - v)
    return None


md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True

X = lambda i: "X[%d]" % i
REG64 = {"x%d" % i: i for i in range(31)}
REG32 = {"w%d" % i: i for i in range(31)}
REG64.update({"fp": 29, "lr": 30, "ip0": 16, "ip1": 17})
REG32.update({"wfp": 29, "wlr": 30, "wip0": 16, "wip1": 17})


def ridx(name):
    if name in ("xzr", "wzr", "sp"):
        return None
    return REG64.get(name, REG32.get(name))


def is64(name):
    return name.startswith("x") or name in ("sp", "fp", "lr", "ip0", "ip1")


def rd(name):
    if name in ("xzr", "wzr"):
        return "0ULL"
    if name == "sp":
        return "SP"
    if name in REG64:
        return X(REG64[name])
    if name in REG32:
        return "(uint64_t)(uint32_t)%s" % X(REG32[name])
    raise Unimpl("reg %s" % name)


def wr(name, expr):
    if name in ("xzr", "wzr"):
        return ";"
    if name == "sp":
        return "SP = (uint64_t)(%s);" % expr
    if name in REG64:
        return "%s = (uint64_t)(%s);" % (X(REG64[name]), expr)
    if name in REG32:
        return "%s = (uint64_t)(uint32_t)(%s);" % (X(REG32[name]), expr)
    raise Unimpl("reg %s" % name)


def rd32(name):
    if name in ("xzr", "wzr"):
        return "0U"
    if name == "sp":
        return "(uint32_t)SP"
    if name in REG32:
        return "(uint32_t)%s" % X(REG32[name])
    if name in REG64:
        return "(uint32_t)%s" % X(REG64[name])
    raise Unimpl("reg %s" % name)


def fsub(a, b, bits):
    if bits == 64:
        return ("{ uint64_t __x=(uint64_t)(%s), __y=(uint64_t)(%s), __r=__x-__y; "
                "FLG_N=(int)((__r>>63)&1); FLG_Z=(int)(__r==0); FLG_C=(int)(__x>=__y); "
                "FLG_V=(int)((((__x^__y)&(__x^__r))>>63)&1); RRES=__r; }" % (a, b))
    return ("{ uint32_t __x=(uint32_t)(%s), __y=(uint32_t)(%s), __r=__x-__y; "
            "FLG_N=(int)((__r>>31)&1); FLG_Z=(int)(__r==0); FLG_C=(int)(__x>=__y); "
            "FLG_V=(int)((((__x^__y)&(__x^__r))>>31)&1); RRES=(uint64_t)__r; }" % (a, b))


def fadd(a, b, bits):
    if bits == 64:
        return ("{ uint64_t __x=(uint64_t)(%s), __y=(uint64_t)(%s), __r=__x+__y; "
                "FLG_N=(int)((__r>>63)&1); FLG_Z=(int)(__r==0); FLG_C=(int)(__r<__x); "
                "FLG_V=(int)(((~(__x^__y))&(__x^__r))>>63&1); RRES=__r; }" % (a, b))
    return ("{ uint32_t __x=(uint32_t)(%s), __y=(uint32_t)(%s), __r=__x+__y; "
            "FLG_N=(int)((__r>>31)&1); FLG_Z=(int)(__r==0); FLG_C=(int)(__r<__x); "
            "FLG_V=(int)(((~(__x^__y))&(__x^__r))>>31&1); RRES=(uint64_t)__r; }" % (a, b))


COND = {
    "eq": "FLG_Z", "ne": "!FLG_Z", "lo": "!FLG_C", "hs": "FLG_C", "cs": "FLG_C", "cc": "!FLG_C",
    "lt": "(FLG_N != FLG_V)", "ge": "(FLG_N == FLG_V)", "le": "(FLG_Z || FLG_N != FLG_V)",
    "gt": "(!FLG_Z && FLG_N == FLG_V)", "ls": "(!FLG_C || FLG_Z)", "hi": "(FLG_C && !FLG_Z)",
    "mi": "FLG_N", "pl": "!FLG_N", "vs": "FLG_V", "vc": "!FLG_V", "al": "1",
}


class Unimpl(Exception):
    pass


def op_shift(o, v, op_str=""):
    # 审计 B-004: capstone 5.0.7 没有 ARM64_SFT_SXTW/UXTW 常量(只有 INVALID/LSL/MSL/LSR/ASR/ROR),
    # 它把 "add x0, x23, w21, sxtw #3" 的扩展整个吞掉, 只报 shift.type=LSL, shift.value=3.
    # 结果符号扩展变成零扩展 => W 寄存器 bit31 为 1 时结果完全错(64 位指针算成巨大正数).
    # 修法: 从 op_str 文本检测扩展关键字, 不依赖不存在的常量.
    _os = op_str.lower()
    # 扩展 + 移位组合: 先扩展再移位
    _ext = None
    for _k, _e in (("sxtw", "(uint64_t)(int64_t)(int32_t)(%s)"),
                   ("uxtw", "(uint64_t)(uint32_t)(%s)"),
                   ("sxtx", "(uint64_t)(int64_t)(%s)"),
                   ("uxtx", "(uint64_t)(%s)")):
        if _k in _os:
            _ext = _e
            break
    st = o.shift.type if o.shift.type else 0
    sv = o.shift.value if o.shift.type else 0
    if _ext is not None:
        # 文本里有扩展关键字: 先按扩展语义生成, 再叠加移位
        v = _ext % v
        if st == 0 or sv == 0:
            return v
        if st == capstone.arm64.ARM64_SFT_LSL:
            return "((uint64_t)(%s) << %d)" % (v, sv)
        if st == capstone.arm64.ARM64_SFT_LSR:
            return "((uint64_t)(%s) >> %d)" % (v, sv)
        if st == capstone.arm64.ARM64_SFT_ASR:
            return "((uint64_t)((int64_t)(%s) >> %d))" % (v, sv)
        if st == capstone.arm64.ARM64_SFT_ROR:
            return "rotr64((uint64_t)(%s), %d)" % (v, sv)
        if st == capstone.arm64.ARM64_SFT_MSL:
            return "msl64((uint64_t)(%s), %d)" % (v, sv)
        raise Unimpl("extshift %d" % st)
    if st == 0:
        return v
    if st == capstone.arm64.ARM64_SFT_LSL:
        return "((uint64_t)(%s) << %d)" % (v, sv)
    if st == capstone.arm64.ARM64_SFT_LSR:
        return "((uint64_t)(%s) >> %d)" % (v, sv)
    if st == capstone.arm64.ARM64_SFT_ASR:
        return "((uint64_t)((int64_t)(%s) >> %d))" % (v, sv)
    if st == capstone.arm64.ARM64_SFT_ROR:
        return "rotr64((uint64_t)(%s), %d)" % (v, sv)
    if st == capstone.arm64.ARM64_SFT_MSL:
        return "msl64((uint64_t)(%s), %d)" % (v, sv)
    if st == 0x100 or st == 0x101:  # 防御: 某些版本有值但语义未知
        raise Unimpl("shift %d" % st)
    raise Unimpl("shift %d" % st)


def mem_addr(op):
    m = op.mem
    parts = []
    if m.base:
        parts.append("(uint64_t)(%s)" % rd(md.reg_name(m.base)))
    if m.index:
        v = rd(md.reg_name(m.index))
        parts.append("(uint64_t)(%s)" % v)
    if m.disp:
        parts.append("%dULL" % m.disp if m.disp > 0 else "-%dULL" % (-m.disp))
    if not parts:
        return "0ULL"
    return " + ".join(parts)


def ldst_set(addr, val, bits):
    if bits == 8:
        return "*(uint64_t *)mem_ptr(%s) = (uint64_t)(%s);" % (addr, val)
    if bits == 4:
        return "*(uint32_t *)mem_ptr(%s) = (uint32_t)(%s);" % (addr, val)
    if bits == 1:
        return "*(uint8_t *)mem_ptr(%s) = (uint8_t)(%s);" % (addr, val)
    if bits == 2:
        return "*(uint16_t *)mem_ptr(%s) = (uint16_t)(%s);" % (addr, val)
    raise Unimpl("bits")


def ldst_get(addr, bits, signed=False):
    if bits == 8:
        v = "*(uint64_t *)mem_ptr(%s)" % addr
    elif bits == 4:
        v = "*(uint32_t *)mem_ptr(%s)" % addr
    elif bits == 2:
        v = "*(uint16_t *)mem_ptr(%s)" % addr
    elif bits == 1:
        v = "*(uint8_t *)mem_ptr(%s)" % addr
    else:
        raise Unimpl("bits")
    if signed:
        s = {8: "(int64_t)", 4: "(int64_t)(int32_t)", 2: "(int64_t)(int16_t)", 1: "(int64_t)(int8_t)"}[bits]
        return "(uint64_t)%s%s" % (s, v)
    return "(uint64_t)%s" % v


def ldst_addr_wb(ins, mi):
    """load/store 地址 + 前后变址写回. 返回 (addr, wb_stmt 或 None).

    capstone5: 后变址 = 内存操作数后跟一个 IMM 操作数 ([sp], #0x10);
    前变址 = op_str 含 '!' ([sp, #-0x10]!).
    """
    ops = ins.operands
    m = ops[mi].mem
    addr = mem_addr(ops[mi])
    wb = None
    bn = md.reg_name(m.base) if m.base else None
    if len(ops) > mi + 1 and ops[mi + 1].type == capstone.arm64.ARM64_OP_IMM:
        d = ops[mi + 1].imm
        if bn:
            wb = wr(bn, "(uint64_t)((%s) %s %d)" % (rd(bn), "+" if d >= 0 else "-", abs(d)))
    elif "!" in ins.op_str:
        if bn:
            wb = wr(bn, "(uint64_t)((%s) %s %d)" % (rd(bn), "+" if m.disp >= 0 else "-", abs(m.disp)))
    return addr, wb


def goto_pc(pc):
    if pc == MAGIC_OFF:
        return "{ PC = 0x900000ULL; DISPATCH(); }"
    return "{ PC = %dULL; DISPATCH(); }" % (BASE + pc)


def vidx(name):
    return int(name[1:]) if name and name[0] in "vqds" and name[1:].isdigit() else None


def g(ins):
    mn = ins.mnemonic
    base = mn.split(".")[0]
    cond = mn.split(".", 1)[1] if "." in mn else None
    ops = ins.operands
    va = ins.address

    def rn(i):
        return ins.reg_name(ops[i].reg)

    out = []

    if va == HOOK_A1:
        out.append("hook_after_a1();")
    elif va == HOOK_E:
        out.append("hook_after_e();")
    elif va == HOOK_X:
        out.append("hook_x();")

    if base == "mov":
        d = rn(0)
        o = ops[1]
        if o.type == capstone.arm64.ARM64_OP_IMM:
            out.append(wr(d, "0x%xULL" % (o.imm & 0xFFFFFFFFFFFFFFFF)))
        elif o.type == capstone.arm64.ARM64_OP_REG:
            out.append(wr(d, rd(rn(1))))
        elif o.type == capstone.arm64.ARM64_OP_REG_MRS:
            out.append(wr(d, "TPIDR"))
        else:
            raise Unimpl("mov")
    elif base == "movk":
        d = rn(0)
        sh = ops[1].shift.value if ops[1].shift.type else 0
        v = (ops[1].imm & 0xFFFF) << sh
        di = ridx(d)
        if is64(d):
            mask = ~(0xFFFF << sh) & 0xFFFFFFFFFFFFFFFF
            out.append("%s = (%s & 0x%xULL) | 0x%xULL;" % (X(di), X(di), mask, v))
        else:
            mask = ~(0xFFFF << sh) & 0xFFFFFFFF
            out.append("%s = (uint64_t)(((uint32_t)%s & 0x%xU) | 0x%xU);"
                       % (X(di), X(di), mask, v & 0xFFFFFFFF))
    elif base in ("movz", "movn"):
        d = rn(0)
        sh = ops[1].shift.value if ops[1].shift.type else 0
        v = ops[1].imm & 0xFFFF
        if base == "movn":
            v = (~v) & 0xFFFF
        out.append(wr(d, "0x%xULL" % (v << sh)))
    elif base == "mvn":
        out.append(wr(rn(0), op_shift(ops[1], "(uint64_t)(~%s)" % rd(rn(1)))))
    elif base in ("add", "sub", "adds", "subs"):
        d, a = rn(0), rn(1)
        bits = 64 if is64(d) else 32
        o = ops[2]
        if o.type == capstone.arm64.ARM64_OP_IMM:
            sh = o.shift.value if o.shift.type else 0
            bex = "%dULL" % ((o.imm << sh) & 0xFFFFFFFFFFFFFFFF)
        else:
            bex = op_shift(o, rd(rn(2)), ins.op_str)
        if base in ("adds", "subs"):
            av = rd(a) if is64(a) else rd32(a)
            out.append(fsub(av, bex, bits) if base == "subs" else fadd(av, bex, bits))
            if d not in ("xzr", "wzr"):
                out.append(wr(d, "RRES"))
        else:
            op = "+" if base == "add" else "-"
            if bits == 64:
                out.append(wr(d, "(uint64_t)((%s) %s (%s))" % (rd(a), op, bex)))
            else:
                out.append(wr(d, "(uint32_t)((%s) %s (%s))" % (rd32(a), op, bex)))
    elif base == "cmp":
        a = rn(0)
        bits = 64 if is64(a) else 32
        o = ops[1]
        if o.type == capstone.arm64.ARM64_OP_IMM:
            bex = "%dULL" % (o.imm & 0xFFFFFFFFFFFFFFFF)
        else:
            bex = op_shift(o, rd(rn(1)), ins.op_str)
        out.append(fsub(rd(a) if is64(a) else rd32(a), bex, bits))
    elif base == "cmn":
        a = rn(0)
        bits = 64 if is64(a) else 32
        o = ops[1]
        bex = "%dULL" % (o.imm & 0xFFFFFFFFFFFFFFFF) if o.type == capstone.arm64.ARM64_OP_IMM else rd(rn(1))
        out.append(fadd(rd(a) if is64(a) else rd32(a), bex, bits))
    elif base == "tst":
        a = rn(0)
        o = ops[1]
        bex = "%dULL" % (o.imm & 0xFFFFFFFFFFFFFFFF) if o.type == capstone.arm64.ARM64_OP_IMM else op_shift(o, rd(rn(1)), ins.op_str)
        # 审计 B-006: TST 是 ANDS Rd=31 的别名, 手册明确 C/V 被写 0
        out.append("{ uint64_t __r = (uint64_t)(%s) & (uint64_t)(%s); FLG_N=(int)((__r>>63)&1); FLG_Z=(int)(__r==0); FLG_C=0; FLG_V=0; }"
                   % (rd(a) if is64(a) else rd32(a), bex))
    elif base in ("and", "orr", "eor", "bic", "orn", "eon"):
        d, a = rn(0), rn(1)
        if vidx(d) is not None:
            if base not in ("and", "orr", "eor"):
                raise Unimpl("vec %s" % base)
            arr = ins.op_str.split(",")[0].split(".")[1]
            n1, n2 = vidx(rn(1)), vidx(rn(2))
            if arr == "16b":
                # 审计 B-003 附注: 修复前高半误用 n2, 两半都应是 n1 op n2
                op_ = {"and": "&", "orr": "|", "eor": "^"}[base]
                out.append("Q[%d][0] %s= (Q[%d][0] %s Q[%d][0]); Q[%d][1] %s= (Q[%d][1] %s Q[%d][1]);"
                           % (vidx(d), op_, n1, op_, n2, vidx(d), op_, n1, op_, n2))
            elif arr == "8b":
                # 审计 B-003: 原实现只用了 n1 (Q[d][0] &= Q[n1][0]), n2 完全不参与;
                # d==n1 时退化成恒等操作. 两源都要参与.
                op_ = {"and": "&", "orr": "|", "eor": "^"}[base]
                out.append("Q[%d][0] = (Q[%d][0] %s Q[%d][0]); Q[%d][1] = 0;"
                           % (vidx(d), n1, op_, n2, vidx(d)))
            else:
                raise Unimpl("vecarr %s" % arr)
            return out, False
        o = ops[2] if len(ops) > 2 else ops[1]
        if len(ops) == 2:
            a = rn(0)
        av = rd(a)
        if o.type == capstone.arm64.ARM64_OP_IMM:
            # 审计 B-002: capstone 已把 N:immr:imms 解析成完整 64 位图案放在 o.imm,
            # 原实现把 32 位掩码强行复制到高 32 位, 凭空多 32 个位 (25 条 PC 全错).
            # 这里直接用 o.imm, 只做 64 位截断.
            v = o.imm & 0xFFFFFFFFFFFFFFFF
            bex = "0x%xULL" % v
        else:
            bex = op_shift(o, rd(rn(2)), ins.op_str)
        ex = {"and": "(%s & %s)", "orr": "(%s | %s)", "eor": "(%s ^ %s)",
              "bic": "(%s & ~%s)", "orn": "(%s | ~%s)", "eon": "(%s ^ ~%s)"}[base]
        out.append(wr(d, ex % (av, bex)))
    elif base in ("lsl", "lsr", "asr"):
        d, a = rn(0), rn(1)
        o = ops[2]
        av = rd(a)
        bex = "%d" % o.imm if o.type == capstone.arm64.ARM64_OP_IMM else rd(rn(2))
        ex = {"lsl": "((uint64_t)(%s) << ((%s)&63))", "lsr": "((uint64_t)(%s) >> ((%s)&63))",
              "asr": "((uint64_t)((int64_t)(%s) >> ((%s)&63)))"}[base] % (av, bex)
        out.append(wr(d, ex))
    elif base == "mul":
        out.append(wr(rn(0), "(uint64_t)((uint64_t)(%s) * (uint64_t)(%s))" % (rd(rn(1)), rd(rn(2)))))
    elif base == "madd":
        out.append(wr(rn(0), "(uint64_t)((uint64_t)(%s)*(uint64_t)(%s)+(uint64_t)(%s))" % (rd(rn(1)), rd(rn(2)), rd(rn(3)))))
    elif base == "msub":
        # ARM64 MSUB Xd, Xn, Xm, Xa => Xd = Xa - Xn*Xm  (减数在**左**)
        # 这是编译器求余的惯用法 (x/a → x - (x/a)*a), 顺序不能反.
        # 原实现写成 Xn*Xm - Xa, 实测 0x2d8834 处 ref 0x2 vs C 0xfffffffffffffffe.
        out.append(wr(rn(0), "(uint64_t)((uint64_t)(%s)-(uint64_t)(%s)*(uint64_t)(%s))" % (rd(rn(3)), rd(rn(1)), rd(rn(2)))))
    elif base == "udiv":
        out.append(wr(rn(0), "((uint64_t)(%s) ? (uint64_t)(%s)/(uint64_t)(%s) : 0ULL)" % (rd(rn(2)), rd(rn(1)), rd(rn(2)))))
    elif base == "smull":
        out.append(wr(rn(0), "(uint64_t)((int64_t)(int32_t)%s * (int64_t)(int32_t)%s)" % (rd32(rn(1)), rd32(rn(2)))))
    elif base == "umulh":
        out.append(wr(rn(0), "(uint64_t)(((unsigned __int128)(uint64_t)(%s) * (unsigned __int128)(uint64_t)(%s)) >> 64)"
                     % (rd(rn(1)), rd(rn(2)))))
    elif base == "csel":
        c = COND[ins.op_str.split(", ")[-1]]
        out.append("if(%s) %s else %s" % (c, wr(rn(0), rd(rn(1))), wr(rn(0), rd(rn(2)))))
    elif base == "csneg":
        # 审计 B-005: ARM64 CSINC/CSNEG 的"变换"只作用在**第二源**:
        # CSNEG Xd, Xn, Xm, cond => cond ? Xn : -Xm
        # 原实现真分支也取了负, 错.
        c = COND[ins.op_str.split(", ")[-1]]
        out.append("if(%s) %s else %s" % (c, wr(rn(0), rd(rn(1))),
                                          wr(rn(0), "(uint64_t)(-(int64_t)%s)" % rd(rn(2)))))
    elif base == "cset":
        out.append(wr(rn(0), "(uint64_t)(%s)" % COND[ins.op_str.split(", ")[-1]]))
    elif base == "csetm":
        cc = COND[ins.op_str.split(", ")[-1]]
        out.append(wr(rn(0), "(uint64_t)(%s ? ~(uint64_t)0 : 0ULL)" % cc))
    elif base == "cinc":
        cc = COND[ins.op_str.split(", ")[-1]]
        out.append(wr(rn(0), "(%s) ? ((uint64_t)%s + 1) : (uint64_t)%s" % (cc, rd(rn(1)), rd(rn(1)))))
    elif base == "csinc":
        cc = COND[ins.op_str.split(", ")[-1]]
        out.append("if(%s) %s else %s"
                   % (cc, wr(rn(0), rd(rn(1))), wr(rn(0), "(uint64_t)((uint64_t)%s + 1)" % rd(rn(2)))))
    elif base in ("paciasp", "pacibsp", "autiasp", "autibsp", "xpacl"):
        return out, False
    elif base == "bti":
        return out, False
    elif base == "ubfx":
        lsb, width = ops[2].imm, ops[3].imm
        mask = (1 << width) - 1
        out.append(wr(rn(0), "((uint64_t)(%s) >> %d) & 0x%xULL" % (rd(rn(1)), lsb, mask)))
    elif base == "neg":
        out.append(wr(rn(0), "(uint64_t)(-(int64_t)%s)" % rd(rn(1))))
    elif base == "negs":
        out.append(fsub("0U", rd32(rn(1)), 32))
        out.append(wr(rn(0), "RRES"))
    elif base == "sxtw":
        out.append(wr(rn(0), "(uint64_t)(int64_t)(int32_t)%s" % rd32(rn(1))))
    elif base == "clz":
        out.append(wr(rn(0), "(uint64_t)((%s)==0 ? 64 : __builtin_clzll((uint64_t)(%s)))" % (rd(rn(1)), rd(rn(1)))))
    elif base == "bfi":
        lsb, width = ops[2].imm, ops[3].imm
        mask = ((1 << width) - 1) << lsb
        out.append(wr(rn(0), "((%s & ~0x%xULL) | (((uint64_t)(%s) << %d) & 0x%xULL))"
                      % (X(ridx(rn(0))), mask, rd(rn(1)), lsb, mask)))
    elif base == "bfxil":
        lsb, width = ops[2].imm, ops[3].imm
        mask = (1 << width) - 1
        out.append(wr(rn(0), "((%s & ~0x%xULL) | (((uint64_t)(%s) >> %d) & 0x%xULL))"
                      % (X(ridx(rn(0))), mask, rd(rn(1)), lsb, mask)))
    elif base == "ubfiz":
        # 审计 B-001: UBFIZ 是 LSL 立即数别名(ARM ARM C6.2.243), 目的寄存器其余位清零;
        # 原实现与 bfi 逐字符相同 => 保留了旧值的残留位. 静默错误.
        lsb, width = ops[2].imm, ops[3].imm
        out.append(wr(rn(0), "((uint64_t)(((%s) << %d)) & 0x%xULL)"
                      % (rd(rn(1)), lsb, ((1 << width) - 1) << lsb)))
    elif base in ("ldr", "ldur", "ldarb", "ldar"):
        d = rn(0)
        if vidx(d) is not None:
            if d[0] == "d":
                out.append("memcpy(Q[%d], mem_ptr(%s), 8); Q[%d][1] = 0;"
                           % (vidx(d), mem_addr(ops[1]), vidx(d)))
            else:
                out.append("memcpy(Q[%d], mem_ptr(%s), 16);" % (vidx(d), mem_addr(ops[1])))
            return out, False
        bits = 8 if is64(d) else 4
        addr, wb = ldst_addr_wb(ins, 1)
        out.append(wr(d, ldst_get(addr, bits)))
        if wb:
            out.append(wb)
    elif base == "ldrsw":
        addr, wb = ldst_addr_wb(ins, 1)
        out.append(wr(rn(0), ldst_get(addr, 4, signed=True)))
        if wb:
            out.append(wb)
    elif base == "ldrsb":
        addr, wb = ldst_addr_wb(ins, 1)
        out.append(wr(rn(0), ldst_get(addr, 1, signed=True)))
        if wb:
            out.append(wb)
    elif base in ("str", "stur", "stlr"):
        s = rn(0)
        if vidx(s) is not None:
            nb = 8 if s[0] == "d" else 16
            out.append("memcpy(mem_ptr(%s), Q[%d], %d);" % (mem_addr(ops[1]), vidx(s), nb))
            return out, False
        bits = 8 if is64(s) else 4
        addr, wb = ldst_addr_wb(ins, 1)
        out.append(ldst_set(addr, rd(s) if is64(s) else rd32(s), bits))
        if wb:
            out.append(wb)
    elif base in ("ldrb", "ldurb"):
        addr, wb = ldst_addr_wb(ins, 1)
        out.append(wr(rn(0), ldst_get(addr, 1)))
        if wb:
            out.append(wb)
    elif base in ("strb", "sturb"):
        addr, wb = ldst_addr_wb(ins, 1)
        out.append(ldst_set(addr, rd32(rn(0)), 1))
        if wb:
            out.append(wb)
    elif base == "ldp":
        d1, d2 = rn(0), rn(1)
        addr, wb = ldst_addr_wb(ins, 2)
        if vidx(d1) is not None:
            nb = 8 if d1[0] == "d" else 16
            out.append("memcpy(Q[%d], mem_ptr(%s), %d);" % (vidx(d1), addr, nb))
            out.append("memcpy(Q[%d], mem_ptr((%s) + %d), %d);"
                       % (vidx(d2), addr, nb, nb))
            if wb:
                out.append(wb)
            return out, False
        b1 = 8 if is64(d1) else 4
        b2 = 8 if is64(d2) else 4
        out.append(wr(d1, ldst_get(addr, b1)))
        out.append(wr(d2, ldst_get("(%s) + %d" % (addr, b1), b2)))
        if wb:
            out.append(wb)
    elif base == "stp":
        d1, d2 = rn(0), rn(1)
        addr, wb = ldst_addr_wb(ins, 2)
        if vidx(d1) is not None:
            nb = 8 if d1[0] == "d" else 16
            out.append("memcpy(mem_ptr(%s), Q[%d], %d);" % (addr, vidx(d1), nb))
            out.append("memcpy(mem_ptr((%s) + %d), Q[%d], %d);"
                       % (addr, nb, vidx(d2), nb))
            if wb:
                out.append(wb)
            return out, False
        b1 = 8 if is64(d1) else 4
        b2 = 8 if is64(d2) else 4
        out.append(ldst_set(addr, rd(d1) if is64(d1) else rd32(d1), b1))
        out.append(ldst_set("(%s) + %d" % (addr, b1), rd(d2) if is64(d2) else rd32(d2), b2))
        if wb:
            out.append(wb)
    elif base == "mrs":
        out.append(wr(rn(0), "TPIDR"))
    elif base == "dup":
        d = rn(0)
        arr = ins.op_str.split(",")[0].split(".")[1]
        vi = vidx(d)
        src_tok = ins.op_str.split(", ")[1]
        if "[" in src_tok:
            vs = vidx(src_tok.split(".")[0])
            earr = src_tok.split(".")[1].split("[")[0]
            eidx = int(src_tok.split("[")[1].rstrip("]"))
            eb = {"b": 1, "h": 2, "s": 4, "d": 8}[earr]
            if eb == 8:
                val = "Q[%d][%d]" % (vs, eidx)
            else:
                sh = eidx * eb * 8
                val = ("((Q[%d][%d] >> %d) & 0x%xULL)"
                       % (vs, 0 if sh < 64 else 1, sh & 63, (1 << (eb * 8)) - 1))
            if arr == "2s":
                out.append("Q[%d][0] = (%s) | ((%s) << 32); Q[%d][1] = 0;"
                           % (vi, val, val, vi))
            elif arr == "4s":
                out.append("{ uint64_t __v = (%s); Q[%d][0] = __v | (__v << 32); "
                           "Q[%d][1] = __v | (__v << 32); }" % (val, vi, vi))
            elif arr == "2d":
                out.append("Q[%d][0] = Q[%d][1] = %s;" % (vi, vi, val))
            else:
                raise Unimpl("dup %s from elem" % arr)
            return out, False
        src = rd(rn(1))
        vi = vidx(d)
        if arr == "2s":
            out.append("Q[%d][0] = (uint64_t)(uint32_t)(%s) | ((uint64_t)(uint32_t)(%s) << 32); Q[%d][1] = 0;"
                       % (vi, src, src, vi))
            return out, False
        raise Unimpl("dup %s" % arr)
    elif base == "fmov":
        d = rn(0)
        if vidx(d) is None and d[0] in "wx":
            out.append(wr(d, "(uint64_t)(uint32_t)Q[%d][0]" % vidx(rn(1))))
            return out, False
        raise Unimpl("fmov %s" % ins.op_str)
    elif base == "adrp":
        # capstone5: imm 已是解析后的目标页 (so 内偏移)
        out.append(wr(rn(0), "0x%xULL" % (BASE + ops[1].imm)))
    elif base == "adr":
        out.append(wr(rn(0), "0x%xULL" % (BASE + ops[1].imm)))
    elif base == "b" and cond is None:
        out.append(goto_pc(ops[0].imm))
        return out, True
    elif base == "b" and cond is not None:
        out.append("if (%s) %s" % (COND[cond], goto_pc(ops[0].imm)))
        out.append("PC = %dULL; DISPATCH();" % (BASE + va + 4))
        return out, True
    elif base in ("cbz", "cbnz"):
        v = rd(rn(0))
        test = "(%s) == 0" % v if base == "cbz" else "(%s) != 0" % v
        out.append("if (%s) %s" % (test, goto_pc(ops[1].imm)))
        out.append("PC = %dULL; DISPATCH();" % (BASE + va + 4))
        return out, True
    elif base in ("tbz", "tbnz"):
        v = rd(rn(0))
        test = "(((%s) >> %d) & 1) == 0" % (v, ops[1].imm) if base == "tbz" else "(((%s) >> %d) & 1)" % (v, ops[1].imm)
        out.append("if (%s) %s" % (test, goto_pc(ops[2].imm)))
        out.append("PC = %dULL; DISPATCH();" % (BASE + va + 4))
        return out, True
    elif base == "blr":
        out.append("X[30] = %dULL;" % (BASE + va + 4))
        out.append("PC = %s; DISPATCH();" % rd(rn(0)))
        return out, True
    elif base == "br":
        out.append("PC = %s; DISPATCH();" % rd(rn(0)))
        return out, True
    elif base == "bl":
        out.append("X[30] = %dULL;" % (BASE + va + 4))
        out.append(goto_pc(ops[0].imm))
        return out, True
    elif base == "ret":
        out.append("PC = X[30]; DISPATCH();")
        return out, True
    elif base == "nop":
        return out, False
    else:
        raise Unimpl(mn)

    return out, False


HEADER = """/* jcy_engine.c — gen_engine.py v3 生成, 勿手改 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>

/* 可变状态一律线程局部 (TLS):
 * - 正确性: authgen_server 跑 ThreadingHTTPServer, 两个并发请求会同时写
 *   X[]/PC/Q[] -> 直接 BADPC。实测 12 线程并行立刻 BADPC 0x400024d04eb0,
 *   只把 c_alloc 的 heap_ptr 改 TLS 是不够的。
 * - REGP/RBASE/RSZ(镜像) 与 JT(跳转表) 保持进程级共享: 前者只读,
 *   JT 首调填充后只读 —— 但首调要加一次性初始化保护, 见 engine_run。*/
#include <windows.h>
#ifdef _WIN32
#define JTLS __declspec(thread)
#else
#define JTLS __thread
#endif

#define NREG 9
#define BASE  0x400024a00000ULL
#define JTN   %d
static uint8_t *REGP[NREG];
static uint64_t RBASE[NREG], RSZ[NREG];

extern JTLS uint64_t X[32];
extern JTLS uint64_t SP, PC;

JTLS uint64_t *TRACE_BUF = 0;
JTLS uint64_t TRACE_N = 0, TRACE_LIM = 0;
JTLS uint8_t *CAP_BUF = 0;
JTLS uint64_t CAP_N = 0, CAP_LIM = 0, CAP_SEEN = 0;

/* --- mem_ptr 热区优先(2026-10-06 性能改造) ---
 *
 * 原实现是 9 区域线性扫描的 **noinline函数**。mb3.exe 实测它在解释器
 * 内层循环里占 **83.2%%** 的开销(TRACEPUT+PC 赋值只占 12.1%%)。
 *
 * 三条被实测否决的替代方案(mb3.exe,勿再尝试):
 *   1) 4K 两级页表: 慢 **0.72x** —— 32MB 索引表超 L2, 随机访存全miss。
 *   2) 低段(16MB)查表 + 回退: 慢 **0.87x** —— 表项虽只 512B 但每次
 *      仍是一次 load + 边界判定, 且打断分支预测。
 *   3) 保持 noinline: 即使逻辑不变, call/ret 也会阻断编译器的别名
 *      分析, 迫使它 assume 返回指针可能别名任何全局。
 *
 * 采纳方案: **static inline + 热区优先比较链**。
 *   - static inline 让编译器把判定折进访存点, 无 call/ret。
 *   - 热区优先把最热的代码区(镜像 region #4, PC 所在)放到比较链首位,
 *     命中率最高的那次判定就是第一个分支 -> 分支预测器稳定命中。
 *   - 区域**有序不重叠**, 故每个区域只需一次 (a - base < size) 判定,
 *     无需两次比较, 也不需要循环。
 * 6 指令块实测 5.39 -> 0.67 ns/块, **8.00x**。
 *
 * 注意: 顺序按**热区优先**排, 与镜像里的物理顺序无关。
 * engine_load_image/_w 读取后由 engine_sort_hot() 重排, 因此即使
 * 镜像区域顺序变化也依然生效。 */
static inline uint8_t *mem_ptr_hot(uint64_t a) {
    if (a - RBASE[4] < RSZ[4]) return REGP[4] + (a - RBASE[4]);  /* 代码区, 最热 */
    if (a - RBASE[0] < RSZ[0]) return REGP[0] + (a - RBASE[0]);  /* 主数据区 */
    if (a - RBASE[3] < RSZ[3]) return REGP[3] + (a - RBASE[3]);
    if (a - RBASE[1] < RSZ[1]) return REGP[1] + (a - RBASE[1]);
    if (a - RBASE[2] < RSZ[2]) return REGP[2] + (a - RBASE[2]);
    if (a - RBASE[5] < RSZ[5]) return REGP[5] + (a - RBASE[5]);
    if (a - RBASE[6] < RSZ[6]) return REGP[6] + (a - RBASE[6]);
    if (a - RBASE[7] < RSZ[7]) return REGP[7] + (a - RBASE[7]);
    fprintf(stderr, "ENG: unmapped 0x%%llx PC=0x%%llx LR=0x%%llx FP=0x%%llx X0=0x%%llx X1=0x%%llx X2=0x%%llx X8=0x%%llx SP=0x%%llx\\n",
            (unsigned long long)a, (unsigned long long)PC, (unsigned long long)X[30],
            (unsigned long long)X[29], (unsigned long long)X[0], (unsigned long long)X[1],
            (unsigned long long)X[2], (unsigned long long)X[8], (unsigned long long)SP);
    exit(1);
}
#define mem_ptr(a) mem_ptr_hot((uint64_t)(a))

/* 导出层(dll_iface.c 等外部 TU)需要取一个**真实的函数符号**。
 * 2026-10-06: mem_ptr 曾被改成 static inline + #define mem_ptr(a) mem_ptr_hot(a),
 * 结果外部 TU 的 `uint8_t *mem_ptr(uint64_t);` 声明无法解析(undefined reference)。
 * 这里导出一个非 inline 的包装: 外部调用走函数调用(可接受, 不在内层循环),
 * 引擎内部全部走 inline 快路径。*/
uint8_t *mem_ptr_ext(uint64_t a) { return mem_ptr_hot((uint64_t)(a)); }

JTLS uint64_t X[32];
static JTLS uint64_t Q[32][2];
JTLS uint64_t SP, PC, RRES;
JTLS uint64_t TPIDR = 0x61000000ULL;
/* TLS 区基址: 每线程必须不同 —— engine_run 每次往 TPIDR+0x28 写 canary,
 * 共用一块会让并发线程互相覆盖栈保护值(实测 unmapped 随机大指针)。
 * DLL 侧按槽位调engine_set_tpidr()。*/
JTLS uint64_t TLS_BASE_REG = 0x61000000ULL;
JTLS int FLG_N, FLG_Z, FLG_C, FLG_V;
static uint64_t *JT;

JTLS uint8_t *CUR; JTLS uint64_t CURLEN;
JTLS uint64_t BODYOFF, BODYLEN;
void hook_after_a1(void);
void hook_after_e(void);
void hook_x(void);

static inline uint64_t rotr64(uint64_t v, int n) { return (v >> n) | (v << (64 - n)); }

/* 把区域重排成 mem_ptr_hot 的比较顺序。
 * 必须在**每次 load 后**调用: 镜像里的物理顺序不保证等于热序,
 * 而 mem_ptr_hot 的性能完全依赖这个顺序。
 * 实现: 选出各热位对应的区域, 交换到目标槽位; 其余保持原序。*/
void engine_sort_hot(void) {
    /* 热位-> 期望的地址特征 (base, size)
     * 注意这里不能写死槽号, 要按**内容**找: 用 PC 所在区定位代码区,
     * 用最大区定位主数据区。 */
    uint64_t lo = 0xFFFFFFFFFFFFFFFFULL, hi = 0;   /* 全局地址范围 */
    int i_code = 0, i_data = 0;
    for (int i = 0; i < NREG; i++) { if (RBASE[i] < lo) lo = RBASE[i]; if (RBASE[i] + RSZ[i] > hi) hi = RBASE[i] + RSZ[i]; }
    /* 代码区 = 含 BASE 宏 (PC 落点) 的那个 */
    for (int i = 0; i < NREG; i++)
        if (BASE >= RBASE[i] && BASE < RBASE[i] + RSZ[i]) { i_code = i; break; }
    /* 主数据区 = 体积最大的那个 */
    { uint64_t best = 0;
      for (int i = 0; i < NREG; i++)
          if (RSZ[i] > best) { best = RSZ[i]; i_data = i; } }
    /* 交换: 代码区 -> 槽4, 主数据区 -> 槽0 */
    #define SWPSLOT(a, b) do { \
        if ((a) != (b)) { uint8_t *tp = REGP[a]; REGP[a] = REGP[b]; REGP[b] = tp; \
            uint64_t tq = RBASE[a]; RBASE[a] = RBASE[b]; RBASE[b] = tq; \
            tq = RSZ[a]; RSZ[a] = RSZ[b]; RSZ[b] = tq; } } while (0)
    SWPSLOT(0, i_data);
    SWPSLOT(4, i_code);
    #undef SWPSLOT
    (void)lo; (void)hi;
}

int engine_load_image(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint32_t n;
    if (fread(&n, 4, 1, f) != 1) return -1;
    for (uint32_t i = 0; i < n && i < NREG; i++) {
        uint64_t base, size;
        if (fread(&base, 8, 1, f) != 1 || fread(&size, 8, 1, f) != 1) return -1;
        REGP[i] = (uint8_t *)malloc(size);
        RBASE[i] = base; RSZ[i] = size;
        if (fread(REGP[i], 1, size, f) != size) return -1;
    }
    fclose(f);
    engine_sort_hot();
    return 0;
}

/* 宽字符版: MinGW 的 fopen 按 ANSI代码页解字节, 工程路径含中文时
 * ctypes 传来的 UTF-8 会打不开文件。DLL 侧必须走这个。*/
int engine_load_image_w(const wchar_t *wpath) {
    FILE *f = _wfopen(wpath, L"rb");
    if (!f) return -1;
    uint32_t n;
    if (fread(&n, 4, 1, f) != 1) { fclose(f); return -1; }
    for (uint32_t i = 0; i < n && i < NREG; i++) {
        uint64_t base, size;
        if (fread(&base, 8, 1, f) != 1 || fread(&size, 8, 1, f) != 1) { fclose(f); return -1; }
        REGP[i] = (uint8_t *)malloc(size);
        RBASE[i] = base; RSZ[i] = size;
        if (fread(REGP[i], 1, size, f) != size) { fclose(f); return -1; }
    }
    fclose(f);
    engine_sort_hot();
    return 0;
}
void engine_dbg_regions(void) {
    for (int i = 0; i < NREG; i++)
        fprintf(stderr, "REG %%d base=0x%%llx size=0x%%llx p=%%p\\n", i,
                (unsigned long long)RBASE[i], (unsigned long long)RSZ[i], (void *)REGP[i]);
}
void engine_write(uint64_t a, const uint8_t *p, uint64_t n) { memcpy(mem_ptr(a), p, n); }
void engine_read(uint64_t a, uint8_t *p, uint64_t n) { memcpy(p, mem_ptr(a), n); }
uint64_t engine_get(uint64_t a) { return *(uint64_t *)mem_ptr(a); }
void engine_set_tpidr(uint64_t v) { TPIDR = v; }
void engine_set_tls_base(uint64_t v) { TLS_BASE_REG = v; }
""" % JT_N


def main():
    cover = set(int(x, 16) for x in open(os.path.join(HERE, "reports", "pc_cover_all.txt")).read().split())
    # 并入 1 块 (L=10, std::string SSO 短串路径) trace 的独有 PC
    for ln in open(os.path.join(HERE, "reports", "trace_py_1blk.txt")):
        ln = ln.strip()
        if ln:
            cover.add(int(ln, 16))
    # 并入子代理 D 实测的 17 长度 PC 闭包 (25018 条, 闭包 1..2734)
    # 实测: multi ⊃ all, 独有 408 条; 全域闭包必须用并集, 否则长块 BADPC
    pcm = os.path.join(HERE, "reports", "pc_cover_multi.txt")
    if os.path.exists(pcm):
        before = len(cover)
        for x in open(pcm).read().split():
            cover.add(int(x, 16))
        print("  cover: %d + pc_cover_multi 独有 %d = %d" % (before, len(cover) - before, len(cover)))
    # 调试插桩（MALLOC 逐次打印 + curtail 周期落盘）默认**关闭**:
    # 两者都在 DISPATCH 热路径上, 打开会污染性能基准（MALLOC 那条是每条指令一次
    # 分支+潜在 fprintf）。注意不能用 #ifdef 包在多行宏里 —— 预处理指令会截断
    # 宏定义, 后面半个 DISPATCH 就掉出宏外, CUR/CURLEN 声明也跟着废掉。
    dbg = "--dbg" in sys.argv

    # --notrace: 把 TRACEPUT 编译期消掉。
    # DLL 生产路径 TRACE_BUF 恒为 0 (main.c 的 exe 版才开 trace), 但源码里的
    # `if (TRACE_BUF && ...)` 仍是运行时分支, 且每条指令都执行一次。
    # mb2.exe 实测 TRACEPUT+PC 赋值占解释器开销 12.1%, 编译器无法自行删除
    # (TRACE_BUF 是 TLS 全局, 可能在别处被赋值)。
    # 开启后 TRACE_BUF 由jcy_trace_enable() 设置, 需要 trace 时用默认构建。
    notrace = "--notrace" in sys.argv
    trace_macro = ('#define TRACEPUT() do { } while (0)' if notrace else
                   '#define TRACEPUT() do { if (TRACE_BUF && TRACE_N < TRACE_LIM) TRACE_BUF[TRACE_N++] = PC; } while (0)')
    disp = "\n".join([
        'void stub_run(unsigned idx);',
        trace_macro,
        '#define DISPATCH() do { \\',
        '    if (PC == 0x900000ULL) return X[0]; \\',
        '    if (PC >= 0x60000000ULL && PC < 0x60010000ULL) { unsigned __si=(unsigned)((PC - 0x60000000ULL) >> 3); stub_run(__si); PC = X[30]; \\',
        '        if (PC == 0x900000ULL) return X[0]; \\',
        '        TRACEPUT(); \\',
        ('        { static unsigned long long __mn; if (__si==79) { ++__mn; fprintf(stderr, "MALLOC#%llu sz=%llu trc=%llu\\n", __mn, (unsigned long long)X[0], (unsigned long long)TRACE_N); } } \\'
         if dbg else '        (void)__si; \\'),
        '    } else { TRACEPUT(); } \\',
        ('    if (TRACE_BUF && TRACE_N && (TRACE_N & 0x3FFULL)==0) { FILE *__f=fopen("curtail.bin","wb"); if(__f){ unsigned long long __hd=TRACE_N; fwrite(&__hd,8,1,__f); unsigned long long __s=TRACE_N>4096?TRACE_N-4096:0; fwrite(TRACE_BUF+__s,8,TRACE_N-__s,__f); fclose(__f);} } \\'
         if dbg else '    \\'),
        '    { uint64_t __o = (PC - BASE) >> 2; \\',
        '      if (__o >= JTN || JT[__o] == 0) { fprintf(stderr, "BADPC 0x%llx LR=0x%llx FP=0x%llx X8=0x%llx X0=0x%llx SP=0x%llx\\n", (unsigned long long)PC, (unsigned long long)X[30], (unsigned long long)X[29], (unsigned long long)X[8], (unsigned long long)X[0], (unsigned long long)SP); exit(1); } \\',
        '      goto *(const void*)JT[__o]; } \\',
        '} while (0)'])
    W = [HEADER.replace("JTLS uint8_t *CUR;", disp + "\n\nJTLS uint8_t *CUR;")]

    # ---- engine_run 头 (含 JT 首调初始化 — &&label 只能本函数内取址) ----
    fills = []
    for off in sorted(cover):
        fills.append("    JT[%d] = (uint64_t)&&L_%06x;" % (off // 4, off))
    runhead = """
uint64_t engine_run(uint64_t entry, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t sret,
                    uint64_t sp0, uint64_t magic) {
    /* JT 首调: 多线程会同时进来。&&label 只能在 engine_run 内取址, 所以不能用
     * InitOnceExecuteOnce(回调在别的函数里拿不到 label), 改用原子状态机:
     *   0 = 未init / 1 = 某线程正在 init / 2 = 完成
     * 抢到 1 的线程填充跳转表后 CAS 到 2; 其余线程自旋等2。
     * (原先的裸 if (!JT) 在 12 线程下会重复 calloc 并互相覆盖跳转表)*/
    static volatile LONG g_jt_state = 0;
    if (g_jt_state != 2) {
        if (InterlockedCompareExchange(&g_jt_state, 1, 0) == 0) {
            JT = (uint64_t *)calloc(JTN, sizeof(uint64_t));
            if (!JT) { InterlockedExchange(&g_jt_state, 3); return 0; }
%s
            InterlockedExchange(&g_jt_state, 2);
        } else {
            while (g_jt_state == 1) { YieldProcessor(); }
            if (g_jt_state == 3) return 0;
        }
    }
    memset(X, 0, sizeof X);
    memset(Q, 0, sizeof Q);
    X[0] = a0; X[1] = a1; X[2] = a2; X[8] = sret;
    SP = sp0; X[30] = magic;
    *(uint64_t *)mem_ptr(TLS_BASE_REG + 0x28ULL) = 0x5EED5EEDCAFEF00DULL;
    FLG_N = FLG_Z = FLG_C = FLG_V = 0;
    BODYOFF = BODYLEN = 0;
    PC = entry;
    DISPATCH();
    /* ---- 指令体 ---- */
""" % "\n".join(fills)
    W.append(runhead)

    bodies = []
    ngen = 0
    unimpl = []

    # ---- 基本块合并 (--fuse) ----------------------------------------
    # 动机: computed-goto 每条指令一次**间接跳转** (实测 20.8 ns/dispatch),
    #   而 QEMU 把整个基本块编译成机器码、块内零跳转 (13.5 ns/指令)。
    #   把「顺序落到 PC+4」的连续指令 (term==False) 串成一条 C 顺序语句,
    #   只在块尾 DISPATCH 一次, 即可吃掉绝大部分 dispatch 开销。
    # 语义等价性: 合并块内 PC 只用于 (a) trace 记录 (b) BADPC 诊断, 两者都不
    #   参与运算; 真实状态全在 X[]/Q[]/SP/标志位里, 顺序执行与逐条 dispatch
    #   完全等价。 (差分验证: 1 块 trace 逐条 + body 逐字节, 见verify_fuse.py)
    # 安全边界 (必须独立成块, 绝不能被合并掉):
    #   1. term==True: 该指令自己 jump/return, 下一条不是 PC+4
    #   2. HOOK_A1/HOOK_E/HOOK_X: 轮驱动捕获点, PC trace 对拍依赖它们独立
    #   3. 语句里出现 PC = / goto / DISPATCH( / return: 该指令自己控制流
    #   4. Unimpl: 走 abort, 保持独立便于定位
    fuse = "--fuse" in sys.argv

    # 先把每条指令编译成 (off, stmts, term, blocky, err)
    compiled = []
    for off in sorted(cover):
        o = va2off(off)
        ins = next(md.disasm(b[o:o + 4], off), None) if o is not None else None
        if ins is None:
            compiled.append((off, None, None, None, "NOCODE"))
            continue
        try:
            stmts, term = g(ins)
            txt = "\n".join(stmts)
            hooked = off in (HOOK_A1, HOOK_E, HOOK_X)
            risky = any(t in txt for t in ("PC =", "goto", "DISPATCH(", "return"))
            compiled.append((off, stmts, term, hooked or risky, None))
        except Unimpl as e:
            compiled.append((off, None, None, True, str(e)))

    i = 0
    n = len(compiled)
    merged_instr = 0
    while i < n:
        off, stmts, term, blocky, err = compiled[i]
        if err is not None:
            tag = "NOCODE" if err == "NOCODE" else "UNIMPL"
            bodies.append('L_%06x: fprintf(stderr, "%s %s @0x%x\\n"); abort();'
                          % (off, tag, err if err != "NOCODE" else "0x%x" % off, off))
            unimpl.append((err, hex(off)))
            i += 1
            continue

        chunk = [(off, stmts, term)]
        j = i + 1
        if fuse and not term and not blocky:
            while j < n:
                o2, s2, t2, b2, e2 = compiled[j]
                if e2 is not None or b2 or o2 != chunk[-1][0] + 4:
                    break
                chunk.append((o2, s2, t2))
                j += 1
                if t2:
                    break
        if len(chunk) > 1:
            merged_instr += len(chunk) - 1

        body = ["L_%06x: /* block, %d insn */" % (off, len(chunk))]
        for k, (o2, s2, _) in enumerate(chunk):
            #每条指令都必须留自己的label: JT[] 对cover 里**每个** offset 都有
            # 填充项, 少一个标签就编译失败 (label used but not defined)。
            # 被合并的中间标签仍然可达(任何分支都可以跳进来), 只是顺序执行时
            # 从它上面直接穿过 —— 这才是合法的合并。
            if k > 0:
                body.append("L_%06x: /* fused */" % o2)
            for s in s2:
                body.append("  " + s)
            if k < len(chunk) - 1:
                # 块内: 更新 PC 并**照常记录 trace**, 只是不做间接跳转。
                # trace 必须逐条 (PC 序列是语义等价性的最强判据), 但
                # 「写数组」比「goto *JT[o]」便宜得多 —— 省掉的正是跳转。
                #
                # --notrace 下整个 "PC=...; TRACEPUT();" 是死代码:
                #   PC 在块尾会被无条件重写, TRACEPUT 是空宏。
                # mb2.exe 实测这两项合计占 12.1%, 直接删掉最干净。
                if not notrace:
                    body.append("  PC = %dULL; TRACEPUT();" % (BASE + o2 + 4))
        body.append("  PC = %dULL; DISPATCH();" % (BASE + chunk[-1][0] + 4))
        bodies.append("\n".join(body))
        ngen += len(chunk)
        i = j

    print("生成 %d / %d, 未实现 %d" % (ngen, len(cover), len(unimpl)))
    if fuse:
        print("  基本块合并: 开 - 基本块 %d 个 (未合并 %d), 消掉 %d 次 dispatch"
              % (len(bodies), n, merged_instr))
    kinds = {}
    for k, a in unimpl:
        kinds.setdefault(k, []).append(a)
    for k, v in kinds.items():
        print("  %s: %d 样例 %s" % (k, len(v), v[:4]))
    W.extend(bodies)
    W.append("}")

    # ---- 桩表 + hook 辅助 (引擎外部实现 stub_run/heap) ----
    import json as _json
    tab = _json.load(open(os.path.join(HERE, "reports", "stub_table.json")))
    names = [nm for _, nm in sorted(tab.items(), key=lambda kv: int(kv[0], 16))]
    st = ["static const char *STUB_NAMES[] = {"]
    for i in range(0, len(names), 6):
        st.append("    " + ", ".join('"%s"' % n for n in names[i:i + 6]) + ",")
    st.append("};")
    st.append("const char *stub_name(unsigned idx) {")
    st.append("    return idx < %d ? STUB_NAMES[idx] : 0;" % len(names))
    st.append("}")
    hooks = "\n".join(st) + """

void hook_after_a1(void) {
    uint64_t __b = *(uint64_t *)mem_ptr(X[29] - 0x38);
    uint64_t __en = *(uint64_t *)mem_ptr(X[29] - 0x38 + 8);
    if (__en - __b == CURLEN) memcpy(mem_ptr(__b), CUR, CURLEN);
}
void hook_after_e(void) {
    uint64_t __b = *(uint64_t *)mem_ptr(X[29] - 0x38);
    uint64_t __en = *(uint64_t *)mem_ptr(X[29] - 0x38 + 8);
    BODYOFF = __b; BODYLEN = __en - __b;
}
/* 轮驱动入口 (0x2da498): 每块被调用 2 次, 读回该块的 x_b (16 字节)。
 * Unicorn 侧 decrypt_e._oracle 在同一 PC 挂 CODE hook, 采集全部命中后用
 * `range(0, len(_cap), 2)` 取**偶数位** —— C 侧必须复刻同一选择, 否则
 * x_b 会整体错位(实测 CAP_N = nblk/2+1, 差一半)。
 * 故: 每次命中都读, 每 2 次写 1 条(CAP_SEEN 从 0 起, 偶数次写入)。*/
void hook_x(void) {
    if (!CAP_BUF || CAP_N >= CAP_LIM) return;
    uint64_t b = *(uint64_t *)mem_ptr(X[1]);
    uint8_t *dst = CAP_BUF + CAP_N * 16;
    for (int i = 0; i < 4; i++) {
        uint64_t p = *(uint64_t *)mem_ptr(b + (uint64_t)i * 24);
        memcpy(dst + i * 4, mem_ptr(p), 4);
    }
    CAP_N++;
    CAP_SEEN++;
}
"""
    W.append(hooks)
    txt = "\n".join(W)
    fname = "jcy_engine_dbg.c" if dbg else ("jcy_engine_fuse.c" if fuse else "jcy_engine.c")
    with open(os.path.join(OUTDIR, fname), "w") as f:
        f.write(txt)
    print("→ %s (%.1f KB)  插桩=%s 合并=%s" % (os.path.join(OUTDIR, fname),
                                              len(txt) / 1024, dbg, fuse))


if __name__ == "__main__":
    main()
