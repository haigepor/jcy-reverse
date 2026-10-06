# -*- coding: utf-8 -*-
"""gen_engine.py v2 — churn 窗口 ARM64→C 1:1 转译器.

窗口: 0x2c6000-0x2f2000; 基址 0x400024a00000 (镜像文件加载)
- computed-goto dispatch; 出窗 PC → 引擎返回
- 32 位算术的标志语义按 w 正确生成
"""
import os
import struct
import capstone

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "..", "libcore.so")
OUTDIR = os.path.join(HERE, "engine_c")
os.makedirs(OUTDIR, exist_ok=True)

WIN_LO, WIN_HI = 0x2c6000, 0x2f2000
BASE = 0x400024a00000
NSLOT = (WIN_HI - WIN_LO) // 4

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
    return name.startswith("x")


def rd(name):
    """读取(64 位上下文)"""
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
    if name in REG32:
        return "(uint32_t)%s" % X(REG32[name])
    if name in REG64:
        return "(uint32_t)%s" % X(REG64[name])
    raise Unimpl("reg %s" % name)


def fsub(a, b, bits):
    """subs 标志 + 结果"""
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


def op_imm(o):
    return o.imm


def op_shift(o, v):
    """对寄存器操作数应用 shift → C 表达式"""
    st = o.shift.type if o.shift.type else 0
    sv = o.shift.value if o.shift.type else 0
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
    if st == capstone.arm64.ARM64_SFT_UXTW:
        return "(uint64_t)(uint32_t)(%s)" % v
    if st == capstone.arm64.ARM64_SFT_SXTW:
        return "(uint64_t)(int64_t)(int32_t)(%s)" % v
    if st == capstone.arm64.ARM64_SFT_UXTX:
        return "(uint64_t)(%s)" % v
    if st == capstone.arm64.ARM64_SFT_SXTX:
        return "(uint64_t)(int64_t)(%s)" % v
    raise Unimpl("shift %d" % st)


def mem_addr(op):
    m = op.mem
    base = None
    if m.base:
        base = "SP" if m.base == 31 else X(m.base)
    parts = []
    if base:
        parts.append("(uint64_t)(%s)" % base)
    if m.index:
        iname = None
        for n, rr in list(REG64.items()) + list(REG32.items()):
            if rr == m.index:
                iname = n
                break
        v = rd(iname)
        if m.scale:
            v = "((uint64_t)(%s) << %d)" % (v, m.scale)
        parts.append("(uint64_t)(%s)" % v)
    if m.disp:
        if m.disp > 0:
            parts.append("%dULL" % m.disp)
        else:
            parts.append("-%dULL" % (-m.disp))
    if not parts:
        return "0ULL", False
    if len(parts) == 1:
        return parts[0], False
    return " + ".join(parts), False


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


def g(ins):
    """→ (C语句列表, terminal)"""
    mn = ins.mnemonic
    base = mn.split(".")[0]
    cond = mn.split(".", 1)[1] if "." in mn else None
    ops = ins.operands

    def rn(i):
        return ins.reg_name(ops[i].reg)

    out = []

    if base == "mov":
        d = rn(0)
        o = ops[1]
        if o.type == capstone.arm64.ARM64_OP_IMM:
            v = o.imm & 0xFFFFFFFFFFFFFFFF
            out.append(wr(d, "0x%xULL" % v))
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
        v <<= sh
        out.append(wr(d, "0x%xULL" % v))
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
            bex = op_shift(o, rd(rn(2)))
        if base in ("adds", "subs"):
            if bits == 64:
                av = rd(a) if is64(a) else "(uint64_t)%s" % rd32(a)
            else:
                av = rd32(a)
            out.append(fsub(av, bex, bits) if base == "subs" else fadd(av, bex, bits))
            if d not in ("xzr", "wzr"):
                out.append(wr(d, "RRES"))
        else:
            op = "+" if base == "add" else "-"
            if bits == 64:
                av = rd(a) if is64(a) else "(uint64_t)%s" % rd32(a)
                out.append(wr(d, "(uint64_t)((%s) %s (%s))" % (av, op, bex)))
            else:
                av = rd32(a)
                out.append(wr(d, "(uint32_t)((%s) %s (%s))" % (av, op, bex)))
    elif base == "cmp":
        a = rn(0)
        bits = 64 if is64(a) else 32
        o = ops[1]
        if o.type == capstone.arm64.ARM64_OP_IMM:
            bex = "%dULL" % (o.imm & 0xFFFFFFFFFFFFFFFF)
        else:
            bex = op_shift(o, rd(rn(1)))
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
        bex = "%dULL" % (o.imm & 0xFFFFFFFFFFFFFFFF) if o.type == capstone.arm64.ARM64_OP_IMM else op_shift(o, rd(rn(1)))
        out.append("{ uint64_t __r = (uint64_t)(%s) & (uint64_t)(%s); FLG_N=(int)((__r>>63)&1); FLG_Z=(int)(__r==0); }"
                   % (rd(a) if is64(a) else rd32(a), bex))
    elif base in ("and", "orr", "eor", "bic", "orn", "eon"):
        d, a = rn(0), rn(1)
        o = ops[2] if len(ops) > 2 else ops[1]
        if len(ops) == 2:
            a = rn(0)
        av = rd(a)
        if o.type == capstone.arm64.ARM64_OP_IMM:
            v = o.imm & 0xFFFFFFFFFFFFFFFF
            sh = o.shift.value if o.shift.type else 0
            if sh:
                r = o.imm
                v = 0
                for k in range(4):  # 32 位立即数模式在 64 位下重复
                    vv = ((r << sh) | (r >> (32 - sh))) & 0xFFFFFFFF if sh else r
                    v |= vv << (32 * k)
                    if sh:
                        r = vv
            bex = "0x%xULL" % v
        else:
            bex = op_shift(o, rd(rn(2)))
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
        out.append(wr(rn(0), "(uint64_t)((uint64_t)(%s)*(uint64_t)(%s)-(uint64_t)(%s))" % (rd(rn(1)), rd(rn(2)), rd(rn(3)))))
    elif base == "udiv":
        out.append(wr(rn(0), "((uint64_t)(%s) ? (uint64_t)(%s)/(uint64_t)(%s) : 0ULL)" % (rd(rn(2)), rd(rn(1)), rd(rn(2)))))
    elif base == "smull":
        out.append(wr(rn(0), "(uint64_t)((int64_t)(int32_t)%s * (int64_t)(int32_t)%s)" % (rd32(rn(1)), rd32(rn(2)))))
    elif base == "umulh":
        out.append(wr(rn(0), "(uint64_t)(((unsigned __int128)(uint64_t)(%s) * (unsigned __int128)(uint64_t)(%s)) >> 64)"
                     % (rd(rn(1)), rd(rn(2)))))
    elif base == "csel":
        d, n, m = rn(0), rn(1), rn(2)
        c = COND[ins.op_str.split(", ")[-1]]
        out.append("%s if(%s) %s else %s" % ("", c, wr(d, rd(n)), wr(d, rd(m))))
    elif base == "csneg":
        d, n, m = rn(0), rn(1), rn(2)
        c = COND[ins.op_str.split(", ")[-1]]
        out.append("if(%s) %s else %s" % (c, wr(d, "(uint64_t)(-(int64_t)%s)" % rd(n)),
                                          wr(d, "(uint64_t)(-(int64_t)%s)" % rd(m))))
    elif base == "cset":
        out.append(wr(rn(0), "(uint64_t)(%s)" % COND[ins.op_str.split(", ")[-1]]))
    elif base == "csetm":
        cc = COND[ins.op_str.split(", ")[-1]]
        out.append(wr(rn(0), "(uint64_t)(%s ? ~(uint64_t)0 : 0ULL)" % cc))
    elif base == "neg":
        out.append(wr(rn(0), "(uint64_t)(-(int64_t)%s)" % rd(rn(1))))
    elif base == "sxtw":
        out.append(wr(rn(0), "(uint64_t)(int64_t)(int32_t)%s" % rd32(rn(1))))
    elif base == "bfi":
        d, s = rn(0), rn(1)
        lsb, width = ops[2].imm, ops[3].imm
        mask = ((1 << width) - 1) << lsb
        out.append(wr(d, "((%s & ~0x%xULL) | (((uint64_t)(%s) << %d) & 0x%xULL))"
                      % (X(ridx(d)), mask, rd(s), lsb, mask)))
    elif base == "bfxil":
        d, s = rn(0), rn(1)
        lsb, width = ops[2].imm, ops[3].imm
        mask = ((1 << width) - 1)
        out.append(wr(d, "((%s & ~0x%xULL) | (((uint64_t)(%s) >> %d) & 0x%xULL))"
                      % (X(ridx(d)), mask, rd(s), lsb, mask)))
    elif base == "ubfiz":
        d, s = rn(0), rn(1)
        lsb, width = ops[2].imm, ops[3].imm
        mask = ((1 << width) - 1) << lsb
        out.append(wr(d, "((%s & ~0x%xULL) | (((uint64_t)(%s)) << %d) & 0x%xULL))"
                      % (X(ridx(d)), mask, rd(s), lsb, mask)))
    elif base in ("ldr", "ldur", "ldarb"):
        d = rn(0)
        bits = 8 if is64(d) else 4
        addr, _ = mem_addr(ops[1])
        out.append(wr(d, ldst_get(addr, bits)))
    elif base == "ldrsw":
        addr, _ = mem_addr(ops[1])
        out.append(wr(rn(0), ldst_get(addr, 4, signed=True)))
    elif base in ("str", "stur"):
        s = rn(0)
        bits = 8 if is64(s) else 4
        addr, _ = mem_addr(ops[1])
        out.append(ldst_set(addr, rd(s) if is64(s) else rd32(s), bits))
    elif base in ("ldrb", "ldurb"):
        addr, _ = mem_addr(ops[1])
        out.append(wr(rn(0), ldst_get(addr, 1)))
    elif base in ("strb", "sturb"):
        addr, _ = mem_addr(ops[1])
        out.append(ldst_set(addr, rd32(rn(0)), 1))
    elif base == "ldp":
        d1, d2 = rn(0), rn(1)
        addr, _ = mem_addr(ops[2])
        b1 = 8 if is64(d1) else 4
        b2 = 8 if is64(d2) else 4
        out.append(wr(d1, ldst_get(addr, b1)))
        out.append(wr(d2, ldst_get("(%s) + %d" % (addr, b1), b2)))
    elif base == "stp":
        d1, d2 = rn(0), rn(1)
        addr, _ = mem_addr(ops[2])
        b1 = 8 if is64(d1) else 4
        b2 = 8 if is64(d2) else 4
        out.append(ldst_set(addr, rd(d1) if is64(d1) else rd32(d1), b1))
        out.append(ldst_set("(%s) + %d" % (addr, b1), rd(d2) if is64(d2) else rd32(d2), b2))
    elif base == "adrp":
        d = rn(0)
        imm = ops[1].imm
        tgt = (ins.address & ~0xFFF) + imm
        out.append(wr(d, "0x%xULL" % (BASE + tgt)))
    elif base == "adr":
        d = rn(0)
        imm = ops[1].imm
        tgt = ins.address + imm
        out.append(wr(d, "0x%xULL" % (BASE + tgt)))
    elif base == "stlr":
        addr, _ = mem_addr(ops[1])
        out.append(ldst_set(addr, rd(rn(0)), 8))
    elif base == "ldar":
        addr, _ = mem_addr(ops[1])
        out.append(wr(rn(0), ldst_get(addr, 8)))
    elif base == "ldrsb":
        d = rn(0)
        addr, _ = mem_addr(ops[1])
        out.append(wr(d, ldst_get(addr, 1, signed=True)))
    elif base == "cinc":
        d, n = rn(0), rn(1)
        cc = COND[ins.op_str.split(", ")[-1]]
        out.append(wr(d, "(%s) ? ((uint64_t)%s + 1) : (uint64_t)%s" % (cc, rd(n), rd(n))))
    elif base == "clz":
        out.append(wr(rn(0), "(uint64_t)((%s)==0 ? 64 : __builtin_clzll((uint64_t)(%s)))" % (rd(rn(1)), rd(rn(1)))))
    elif base == "ccmp":
        # ccmp Xn, #imm, #nzcv, cond: cond? sets flags : flags = nzcv
        a = rn(0)
        o = ops[1]
        nzcv = ops[2].imm
        cc = ins.op_str.split(", ")[-1]
        bex = "%dULL" % (o.imm & 0xFFFFFFFFFFFFFFFF) if o.type == capstone.arm64.ARM64_OP_IMM else rd(rn(1))
        out.append("{ if (%s) { %s } else { FLG_N=(int)(!!(%d&8)); FLG_Z=(int)(!!(%d&4)); FLG_C=(int)(!!(%d&2)); FLG_V=(int)(!!(%d&1)); } }"
                   % (COND[cc], fsub(rd(a) if is64(a) else rd32(a), bex, 64 if is64(a) else 32).strip("{} "), nzcv, nzcv, nzcv, nzcv))
    elif base == "mrs":
        out.append(wr(rn(0), "TPIDR"))
    elif base == "b" and cond is None:
        out.append(goto_pc(ops[0].imm))
        return out, True
    elif base == "b" and cond is not None:
        out.append("if (%s) %s" % (COND[cond], goto_pc(ops[0].imm)))
        return out, True
    elif base in ("cbz", "cbnz"):
        v = rd(rn(0))
        test = "(%s) == 0" % v if base == "cbz" else "(%s) != 0" % v
        out.append("if (%s) %s" % (test, goto_pc(ops[1].imm)))
        return out, True
    elif base in ("tbz", "tbnz"):
        v = rd(rn(0))
        bit = ops[1].imm
        test = "(((%s) >> %d) & 1) == 0" % (v, bit) if base == "tbz" else "(((%s) >> %d) & 1)" % (v, bit)
        out.append("if (%s) %s" % (test, goto_pc(ops[2].imm)))
        return out, True
    elif base == "blr":
        out.append("X[30] = %dULL;" % (BASE + ins.address + 4))
        out.append("PC = %s; DISPATCH();" % rd(rn(0)))
        return out, True
    elif base == "br":
        out.append("PC = %s; DISPATCH();" % rd(rn(0)))
        return out, True
    elif base == "bl":
        out.append("X[30] = %dULL;" % (BASE + ins.address + 4))
        out.append(goto_pc(ops[0].imm))
        return out, True
    elif base == "ret":
        out.append("PC = X[30]; DISPATCH();")
        return out, True
    elif base == "nop":
        return out, False
    elif base in ("dup", "fmov", "adr"):
        raise Unimpl("%s" % base)
    else:
        raise Unimpl(mn)

    return out, False


def goto_pc(pc):
    if not (WIN_LO <= pc < WIN_HI):
        # 窗外目标(管道层返回) → 引擎退出, PC 供 Python 校验
        return "{ PC = %dULL; return PC; }" % (BASE + pc)
    return "goto *JT[%d];" % ((pc - WIN_LO) // 4)


HEADER = """/* jcy_engine.c — gen_engine.py v2 生成, 勿手改 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define NREG 9
#define WINLO 0x2c6000ULL
#define BASE  0x400024a00000ULL
static uint8_t *REGP[NREG];
static uint64_t RBASE[NREG], RSZ[NREG];

static inline uint8_t *mem_ptr(uint64_t a) {
    for (int i = 0; i < NREG; i++)
        if (a >= RBASE[i] && a < RBASE[i] + RSZ[i]) return REGP[i] + (a - RBASE[i]);
    fprintf(stderr, "ENG: unmapped 0x%llx\\n", (unsigned long long)a);
    abort();
}

uint64_t X[32];
uint64_t SP;
uint64_t PC;
uint64_t RRES;
uint64_t TPIDR = 0x737dd0000000ULL;
int FLG_N, FLG_Z, FLG_C, FLG_V;
static const void **JT;

static inline uint64_t rotr64(uint64_t v, int n) { return (v >> n) | (v << (64 - n)); }

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
    return 0;
}

void engine_write(uint64_t a, const uint8_t *p, uint64_t n) { memcpy(mem_ptr(a), p, n); }
void engine_read(uint64_t a, uint8_t *p, uint64_t n) { memcpy(p, mem_ptr(a), n); }

/* 运行: 从 entry 起执行, 出窗(返回管道层)时返回当时的 PC */
uint64_t engine_run(uint64_t entry, uint64_t a0, uint64_t a1, uint64_t a2) {
    X[0] = a0; X[1] = a1; X[2] = a2;
    PC = entry;
    { uint64_t __o = (PC - BASE) >> 2; if (__o >= 45056ULL) return PC; goto *JT[__o]; }
}
"""


def main():
    cover = set()
    pcfile = os.path.join(HERE, "reports", "pc_cover.txt")
    if os.path.exists(pcfile):
        cover = set(int(x, 16) for x in open(pcfile).read().split())
    W = []
    W.append(HEADER)
    W.append("/* ---- 指令体 ---- */")
    ngen, nunimpl = 0, 0
    unimpl_mn = {}
    for slot in range(NSLOT):
        va = WIN_LO + slot * 4
        off = va2off(va)
        if off is None:
            continue
        ins = next(md.disasm(b[off:off + 4], va), None)
        if ins is None:
            continue
        W.append("L_%06x: /* %s %s */" % (va, ins.mnemonic, ins.op_str))
        try:
            stmts, term = g(ins)
            for s in stmts:
                W.append("  " + s)
            if not term:
                W.append("  PC = %dULL; DISPATCH_SEQ();" % (BASE + va + 4))
        except Unimpl as e:
            W.append('  fprintf(stderr, "UNIMPL %s @0x%x\\n"); abort();' % (e, va))
            nunimpl += 1
            unimpl_mn[str(e)] = unimpl_mn.get(str(e), 0) + 1
        ngen += 1
    # DISPATCH 宏需要 JT 初始化; 用 goto 前缀宏定义放头部后 —— 这里补
    W.append("}")
    W.append("")
    W.append("void engine_init_jt(void) {")
    W.append("  JT = (const void **)calloc(%d, sizeof(void *));" % NSLOT)
    W.append("}")
    txt = "\n".join(W)
    # DISPATCH 宏: 放头部后 (对 SEQ: 顺序下一条直接 goto 标签由生成器决定 —— 简化统一走 dispatch)
    txt = txt.replace("static const void **JT;", """static const void **JT;
#define DISPATCH() do { uint64_t __o = (PC - BASE) >> 2; if (__o >= %dULL) return PC; goto *JT[__o]; } while (0)
#define DISPATCH_SEQ() do { uint64_t __o = (PC - BASE) >> 2; if (__o >= %dULL) return PC; goto *JT[__o]; } while (0)""" % (NSLOT, NSLOT))
    # JT 填充函数: 每个 L_ 标签地址
    fills = []
    for slot in range(NSLOT):
        va = WIN_LO + slot * 4
        if ("L_%06x:" % va) in txt:
            fills.append("  JT[%d] = &&L_%06x;" % (slot, va))
    W2 = []
    W2.append("int engine_fill_jt(void) {")
    W2.extend(fills)
    W2.append("  return 0;")
    W2.append("}")
    txt = txt.replace("/* ---- 指令体 ---- */", "/* ---- 指令体 ---- */\n/* fwd */") + "\n" + "\n".join(W2)
    with open(os.path.join(OUTDIR, "jcy_engine.c"), "w") as f:
        f.write(txt)
    crit = {}
    for k, v in unimpl_mn.items():
        if isinstance(v, list):
            crit[k] = v[:6]
    print("生成 %d 条, 覆盖内未实现 %d 类: %s" % (ngen, len(crit), crit))
    print("覆盖集 %d 个 PC" % len(cover))
    print("→ %s" % os.path.join(OUTDIR, "jcy_engine.c"))


if __name__ == "__main__":
    main()
