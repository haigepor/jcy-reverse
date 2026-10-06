# -*- coding: utf-8 -*-
# emu_v11.py — libcore.so Unicorn 模拟器 v11
#   关键改进: 以真机基址 (0x400024a00000) 映射, 并灌入真机运行时内存镜像,
#   从而获得完全初始化的全局态 (fmt 串 / std::string 常量 / 单例等)。
import struct, sys, os

from unicorn import *
from unicorn.arm64_const import *

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
import paths as _P
SO = _P.SO
IMG = _P.IMG

DEV_BASE = 0x400024a00000
IMG_SIZE = 0x800000
STACK = 0x70000000
STACK_SIZE = 0x200000
HEAP = 0x50000000
HEAP_SIZE = 0x4000000
STUBS = 0x60000000
TLS = 0x61000000
MAGIC_RET = 0x900000
CANARY = 0x5EED5EEDCAFEF00D


class VaList:
    """AAPCS64 __va_list: {__stack, __gr_top, __vr_top, int __gr_offs, int __vr_offs}"""

    def __init__(self, emu, ap):
        self.e = emu
        self.ap = ap
        self.stack = emu.rd_u64(ap)
        self.gr_top = emu.rd_u64(ap + 8)
        self.vr_top = emu.rd_u64(ap + 16)
        self.gr_offs = struct.unpack("<i", emu.rd(ap + 24, 4))[0]
        self.vr_offs = struct.unpack("<i", emu.rd(ap + 28, 4))[0]

    def gp(self):
        if self.gr_offs < 0:
            a = (self.gr_top + self.gr_offs) & ((1 << 64) - 1)
            self.gr_offs += 8
            return self.e.rd_u64(a)
        v = self.e.rd_u64(self.stack)
        self.stack += 8
        return v

    def fp(self):
        if self.vr_offs < 0:
            a = (self.vr_top + self.vr_offs) & ((1 << 64) - 1)
            self.vr_offs += 16
            return self.e.rd(a, 16)
        v = self.e.rd(self.stack, 16)
        self.stack += 16
        return v


class Emu:
    def __init__(self, so_path=SO, img_path=IMG, use_img=True):
        self.data = open(so_path, "rb").read()
        self.img = open(img_path, "rb").read() if (use_img and os.path.exists(img_path)) else None
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        self.uc.mem_map(STUBS, 0x10000, UC_PROT_ALL)
        self.uc.mem_map(TLS, 0x4000, UC_PROT_ALL)
        self.uc.mem_map(HEAP, HEAP_SIZE, UC_PROT_ALL)
        self.heap_ptr = HEAP
        self.alloc_map = {}
        self.backfills = []
        self.stub_syms = {}
        self.sym_stub = {}
        self.logs = []
        self.trace = []
        self.trace_on = False
        self.vsnprintf_calls = []
        self.mem_faults = []
        self._load()
        self._install_hooks()

    # ---------------- ELF ----------------
    def _parse_sections(self):
        d = self.data
        e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
        e_shnum = struct.unpack_from("<H", d, 0x3c)[0]
        e_shentsize = struct.unpack_from("<H", d, 0x3a)[0]
        secs = {}
        dynsym = None
        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            name, typ, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", d, sh)
            secs[i] = dict(typ=typ, addr=addr, off=offset, size=size, link=link, entsize=entsize)
            if typ == 11:
                dynsym = secs[i]
        return secs, dynsym

    def _load(self):
        d = self.data
        e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
        e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
        e_phnum = struct.unpack_from("<H", d, 0x38)[0]
        segs = []
        for i in range(e_phnum):
            p = e_phoff + i * e_phentsize
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz = struct.unpack_from("<IIQQQQQ", d, p)
            if p_type == 1:
                segs.append((p_vaddr, p_offset, p_filesz, p_memsz))
        # 以真机基址映射整段 0..0x800000
        self.uc.mem_map(DEV_BASE, IMG_SIZE, UC_PROT_ALL)
        for v, o, fs, m in segs:
            if v + fs <= IMG_SIZE:
                self.uc.mem_write(DEV_BASE + v, d[o:o + fs])
        if self.img:
            self.uc.mem_write(DEV_BASE, self.img)

        # 强制非 LSE 原子路径: Unicorn 不支持 ldadd/stadd 等 LSE 原子指令。
        # compiler-rt outline-atomics 通过该标志字节在 LSE 与 ldxr/stxr 之间选择。
        self.uc.mem_write(DEV_BASE + 0x6909E0, b"\x00")
        self.lse_flag_addr = 0x6909E0

        secs, dynsym = self._parse_sections()
        dynstr = secs[dynsym["link"]] if dynsym else None

        def sym_name(idx):
            if not dynsym or not dynstr or idx == 0:
                return None
            off = dynstr["off"] + struct.unpack_from("<I", d, dynsym["off"] + idx * 24)[0]
            e = d.index(b"\0", off)
            return d[off:e].decode("utf-8", "replace")

        self.relocs = []
        for i, sec in secs.items():
            if sec["typ"] != 4:
                continue
            for j in range(0, sec["size"], 24):
                r_off, r_info, r_add = struct.unpack_from("<QQq", d, sec["off"] + j)
                typ = r_info & 0xffffffff
                symidx = r_info >> 32
                self.relocs.append((r_off, typ, symidx, r_add))
        self.sym_name = sym_name
        self.dynsym = dynsym
        self._patch_imports()

    def _patch_imports(self):
        """重定位修正。

        关键: 本 so 的 RELA addend 本身携带混淆偏移 (-K2),
        调用点做 `target = [GOT] + K2`。故必须写 `S + addend`,
        而不是裸桩地址, 否则 `[GOT] + K2` 会跳到未映射地址。
        """
        n = 0
        ds = self.dynsym["off"]
        for r_off, typ, symidx, r_add in self.relocs:
            if typ not in (1025, 1026, 257):  # GLOB_DAT / JUMP_SLOT / ABS64
                continue
            nm = self.sym_name(symidx)
            S = None
            if symidx:
                st_value, st_shndx = struct.unpack_from("<QQ", self.data, ds + symidx * 24 + 8)
                st_shndx &= 0xFFFF
                if st_shndx != 0:
                    S = DEV_BASE + st_value
            if S is None:
                S = self._get_stub(nm) if nm else STUBS
            val = (S + r_add) & ((1 << 64) - 1)
            if symidx == 0:
                # 无符号绝对重定位: addend 即值 (经调用点 +K2 还原), 不该加 STUBS
                val = r_add & ((1 << 64) - 1)
            self.wr(DEV_BASE + r_off, struct.pack("<Q", val))
            n += 1
        self.import_patched = n

    def _get_stub(self, nm):
        if nm in self.sym_stub:
            return self.sym_stub[nm]
        addr = STUBS + len(self.sym_stub) * 8
        self.sym_stub[nm] = addr
        self.stub_syms[addr] = nm
        self.uc.mem_write(addr, struct.pack("<I", 0xD65F03C0))
        return addr

    # ---------------- hooks ----------------
    def _install_hooks(self):
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code, begin=STUBS, end=STUBS + 0x10000)
        self.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
        self.uc.mem_write(TLS + 0x28, struct.pack("<Q", CANARY))

    def _hook_code(self, uc, address, size, user_data):
        nm = self.stub_syms.get(address)
        if nm is None:
            return
        self._do_stub(nm, uc)

    def fix_long_string(self, off, content):
        """把真机堆上的长 std::string 缓冲区重建到模拟器堆内。"""
        b = content if isinstance(content, bytes) else content.encode()
        buf = self.alloc(len(b) + 1)
        self.wr(buf, b + b"\x00")
        cap = (len(b) + 1) | 1
        self.wr(DEV_BASE + off, struct.pack("<QQQ", cap, len(b), buf))
        return buf

    def rd(self, addr, n):
        try:
            return bytes(self.uc.mem_read(addr, n))
        except UcError:
            # V12: Python 侧读未映射段 → 快照回填映射后重试 (memcpy 桩拷真机堆数据依赖此路径)
            try:
                if self._map_backfill(addr, n):
                    return bytes(self.uc.mem_read(addr, n))
            except UcError:
                pass
            try:
                self.mem_faults.append(addr)
            except Exception:
                pass
            raise

    def rd_u64(self, addr):
        return struct.unpack("<Q", self.rd(addr, 8))[0]

    def wr(self, addr, b):
        try:
            self.uc.mem_write(addr, b)
        except UcError:
            # V12: 桩处理器写未映射段 → 按需映射后重试 (Python 侧写不走 MEM_UNMAPPED hook)
            self._ensure(addr, len(b))
            self.uc.mem_write(addr, b)

    def add_backfill(self, base, img):
        """V12: 注册真机内存快照区; Python 侧 rd() 未命中时按快照映射回填."""
        self.backfills.append((base, img))

    def _map_backfill(self, addr, n):
        for base, img in self.backfills:
            if base <= addr < base + len(img):
                pg = addr & ~0xFFF
                end = (addr + max(n, 1) - 1) & ~0xFFF
                while pg <= end:
                    try:
                        self.uc.mem_map(pg, 0x1000, UC_PROT_ALL)
                    except UcError:
                        pass
                    off = pg - base
                    if 0 <= off < len(img):
                        self.uc.mem_write(pg, bytes(img[off:off + 0x1000]))
                    pg += 0x1000
                return True
        return False

    def _ensure(self, addr, n):
        """V12: 桩内 Python 侧 mem_write 不走 UC_HOOK_MEM_UNMAPPED, 未映射段需先手工映射."""
        if n <= 0:
            n = 1
        pg = addr & ~0xFFF
        end = (addr + n - 1) & ~0xFFF
        while pg <= end:
            try:
                self.uc.mem_map(pg, 0x1000, UC_PROT_ALL)
            except UcError:
                pass
            pg += 0x1000

    def cstr(self, addr, maxn=4096):
        out = bytearray()
        for i in range(maxn):
            c = self.rd(addr + i, 1)[0]
            if c == 0:
                break
            out.append(c)
        return bytes(out)

    # ---- libc++ std::string 助手 ----
    def str_obj(self, addr):
        """读 libc++ std::string: 返回 (text, kind)"""
        b0 = self.rd_u64(addr)
        if b0 & 1:  # long
            size = self.rd_u64(addr + 8)
            data = self.rd_u64(addr + 16)
            return self.rd(data, size), "long"
        size = b0 >> 1
        return self.rd(addr + 1, size), "short"

    def mkstr(self, s, addr=None):
        """构造 libc++ std::string (短字符串内联, 长字符串用堆)"""
        b = s if isinstance(s, bytes) else s.encode()
        if addr is None:
            addr = self.alloc(0x20)
        if len(b) <= 22:
            self.wr(addr, struct.pack("<Q", len(b) << 1))
            self.wr(addr + 1, b)
            self.wr(addr + 1 + len(b), b"\x00")
        else:
            data = self.alloc(len(b) + 1)
            self.wr(data, b + b"\x00")
            cap = (len(b) + 1) | 1
            self.wr(addr, struct.pack("<QQQ", cap, len(b), data))
        return addr

    # ---- 堆 ----
    def alloc(self, size):
        size = (size + 0xF) & ~0xF
        addr = self.heap_ptr
        self.heap_ptr += size
        if self.heap_ptr > HEAP + HEAP_SIZE:
            raise RuntimeError("heap exhausted")
        return addr

    # ---- 执行 ----
    def call(self, fn_addr, args=(), timeout=120_000_000, sret=None):
        uc = self.uc
        for a, sz in ((STACK, STACK_SIZE), (STUBS, 0x10000), (MAGIC_RET, 0x1000)):
            try:
                uc.mem_map(a, sz, UC_PROT_ALL)
            except UcError:
                pass
        if sret is not None:
            uc.reg_write(UC_ARM64_REG_X8, sret)
        for i, a in enumerate(args):
            uc.reg_write(UC_ARM64_REG_X0 + i, a)
        uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE - 0x10000)
        uc.reg_write(UC_ARM64_REG_LR, MAGIC_RET)
        uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
        uc.mem_write(TLS + 0x28, struct.pack("<Q", CANARY))
        uc.emu_start(fn_addr, MAGIC_RET, timeout=timeout)
        return uc.reg_read(UC_ARM64_REG_X0)

    # ---------------- 桩实现 ----------------
    def _readvar(self, uc, idx):
        """读取第 idx 个参数 (0-based, 从 x0 起)"""
        if idx < 8:
            return uc.reg_read(UC_ARM64_REG_X0 + idx)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        return struct.unpack("<Q", uc.mem_read(sp + (idx - 8) * 8, 8))[0]

    def _fmt_va(self, uc, fmt_addr, va, maxn=8192):
        """printf 格式化, 参数从真实 va_list 读取 (AAPCS64 __va_list)"""
        f = self.cstr(fmt_addr, 512)
        out = bytearray()
        i = 0
        while i < len(f):
            c = f[i:i + 1]
            if c != b"%":
                out += c
                i += 1
                continue
            j = i + 1
            while j < len(f) and f[j:j + 1] in b"-+ #0'":
                j += 1
            while j < len(f) and f[j:j + 1].isdigit():
                j += 1
            if j < len(f) and f[j:j + 1] == b".":
                j += 1
                while j < len(f) and f[j:j + 1].isdigit():
                    j += 1
            while j < len(f) and f[j:j + 1] in b"lhLqjzt":
                j += 1
            if j >= len(f):
                break
            conv = f[j:j + 1]
            i = j + 1
            if conv == b"%":
                out += b"%"
                continue
            if conv in (b"f", b"F", b"g", b"G", b"e", b"E", b"a", b"A"):
                va.fp()
                out += b"0"
                continue
            v = va.gp()
            if conv == b"s":
                if v == 0:
                    out += b"(null)"
                else:
                    try:
                        out += self.cstr(v, 4096)
                    except UcError:
                        out += b"(badptr)"
            elif conv in (b"d", b"i"):
                sv = struct.unpack("<q", struct.pack("<Q", v))[0]
                out += str(sv).encode()
            elif conv == b"u":
                out += str(v).encode()
            elif conv == b"x":
                out += format(v, "x").encode()
            elif conv == b"X":
                out += format(v, "X").encode()
            elif conv == b"p":
                out += hex(v).encode()
            elif conv == b"c":
                out += bytes([v & 0xFF])
            else:
                out += b"?" + conv
        return bytes(out), 0

    def _fmt(self, uc, fmt_addr, first_arg_idx, maxn=8192):
        """printf 格式化: 正确解析 flags/width/precision/length/conversion"""
        f = self.cstr(fmt_addr, 512)
        out = bytearray()
        i = 0
        ai = first_arg_idx
        while i < len(f):
            c = f[i:i + 1]
            if c != b"%":
                out += c
                i += 1
                continue
            j = i + 1
            while j < len(f) and f[j:j + 1] in b"-+ #0'":
                j += 1
            while j < len(f) and f[j:j + 1].isdigit():
                j += 1
            if j < len(f) and f[j:j + 1] == b".":
                j += 1
                while j < len(f) and f[j:j + 1].isdigit():
                    j += 1
            while j < len(f) and f[j:j + 1] in b"lhLqjzt":
                j += 1
            if j >= len(f):
                break
            conv = f[j:j + 1]
            i = j + 1
            if conv == b"%":
                out += b"%"
                continue
            v = self._readvar(uc, ai)
            ai += 1
            if conv == b"s":
                if v == 0:
                    out += b"(null)"
                else:
                    out += self.cstr(v, 1024)
            elif conv in (b"d", b"i"):
                sv = struct.unpack("<q", struct.pack("<Q", v))[0]
                out += str(sv).encode()
            elif conv == b"u":
                out += str(v).encode()
            elif conv == b"x":
                out += format(v, "x").encode()
            elif conv == b"X":
                out += format(v, "X").encode()
            elif conv == b"p":
                out += hex(v).encode()
            elif conv in (b"c",):
                out += bytes([v & 0xFF])
            else:
                out += b"?" + conv
        return bytes(out), ai

    def _do_stub(self, nm, uc):
        a0 = uc.reg_read(UC_ARM64_REG_X0)
        a1 = uc.reg_read(UC_ARM64_REG_X1)
        a2 = uc.reg_read(UC_ARM64_REG_X2)
        a3 = uc.reg_read(UC_ARM64_REG_X3)
        a4 = uc.reg_read(UC_ARM64_REG_X4)
        ret = 0
        if nm in ("malloc", "_Znwm", "_Znam", "_ZNSt6__ndk17operator newEm"):
            size = a0
            ret = self.alloc(max(size, 0x20) + 0x20) + 0x10
            self.alloc_map[ret] = size
        elif nm in ("posix_memalign", "aligned_alloc", "memalign"):
            # V12: OpenSSL rand pool 用 posix_memalign; 失败(ret!=0)会抛 runtime_error
            if nm == "posix_memalign":
                mptr, align, sz = a0, a1, a2
                raw = self.alloc(max(sz, 0x20) + max(align, 8) + 0x20)
                aligned = (raw + align - 1) & ~(align - 1) if align else raw
                self.wr(mptr, struct.pack("<Q", aligned))
                self.alloc_map[aligned] = sz
                ret = 0
            else:
                align, sz = a0, a1
                raw = self.alloc(max(sz, 0x20) + max(align, 8) + 0x20)
                ret = (raw + align - 1) & ~(align - 1) if align else raw
                self.alloc_map[ret] = sz
        elif nm in ("calloc",):
            n, sz = a0, a1
            total = max(n * sz, 0x20) + 0x20
            ret = self.alloc(total) + 0x10
            self.wr(ret, b"\0" * min(total, 0x400000))
            self.alloc_map[ret] = total
        elif nm in ("realloc",):
            old, sz = a0, a1
            total = max(sz, 0x20) + 0x20
            ret = self.alloc(total) + 0x10
            if old:
                try:
                    self.wr(ret, self.rd(old, min(sz, 0x400000)))
                except UcError:
                    pass
            self.alloc_map[ret] = total
        elif nm in ("free", "_ZdlPv", "_ZdaPv"):
            ret = 0
        elif nm in ("memcpy", "memmove"):
            dst, src, n = a0, a1, a2
            if 0 < n < (1 << 24):
                try:
                    self._ensure(dst, n)
                    self.wr(dst, self.rd(src, n))
                except UcError as e:
                    self.logs.append("memcpy err %s" % e)
            ret = dst
        elif nm in ("memset", "__memset_chk"):
            dst, c, n = a0, a1, a2
            if 0 < n < (1 << 24):
                self._ensure(dst, n)
                self.wr(dst, bytes([c & 0xFF]) * n)
            ret = dst
        elif nm == "getentropy":
            # V12: OpenSSL rand_unix 种子源; 桩内给确定性伪随机 (保证 RSA 结果可复现)
            buf, ln = a0, a1
            if 0 < ln < 0x10000:
                self._ensure(buf, ln)
                seed = 0x243F6A8885A308D3
                out = bytearray()
                for _ in range(ln):
                    seed = (seed * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
                    out.append((seed >> 33) & 0xFF)
                self.wr(buf, bytes(out))
            ret = 0
        elif nm in ("strlen", "strnlen"):
            s, n = a0, 0
            while n < 0x100000 and self.rd(s + n, 1)[0] != 0:
                n += 1
            ret = n
        elif nm == "memchr":
            # V12: PEM 解析逐行扫描依赖 memchr; 未注册时 ret=0 导致 Invalid key
            s, c, n = a0, a1 & 0xFF, a2
            r = 0
            if 0 < n < (1 << 24):
                try:
                    buf = self.rd(s, n)
                    idx = buf.find(bytes([c]))
                    if idx >= 0:
                        r = s + idx
                except UcError:
                    r = 0
            ret = r
        elif nm == "memcmp":
            # V12: memcmp 必须按 a2 长度精确比较 (二进制 OID 无 NULL 结尾, 旧行为按
            # strcmp 越界比较导致 OBJ_obj2nid 查表失败 → Invalid key)
            s1, s2, lim = a0, a1, a2
            r = 0
            if lim > (1 << 24):
                lim = 1 << 24
            n = 0
            while n < lim:
                c1 = self.rd(s1 + n, 1)[0]
                c2 = self.rd(s2 + n, 1)[0]
                if c1 != c2:
                    r = 1 if c1 > c2 else -1
                    break
                n += 1
            ret = r & 0xFFFFFFFFFFFFFFFF
        elif nm in ("strcmp", "strncmp"):
            s1, s2 = a0, a1
            lim = a2 if nm == "strncmp" else (1 << 20)
            n, r = 0, 0
            while n < lim:
                c1 = self.rd(s1 + n, 1)[0]
                c2 = self.rd(s2 + n, 1)[0]
                if c1 != c2:
                    r = 1 if c1 > c2 else -1
                    break
                if c1 == 0:
                    break
                n += 1
            ret = r & 0xFFFFFFFFFFFFFFFF
        elif nm in ("__vsnprintf_chk", "vsnprintf", "snprintf", "__snprintf_chk"):
            # __vsnprintf_chk(dst, maxlen, flags, slen, fmt, va_list): 必须展开 va_list
            done = False
            if nm in ("__vsnprintf_chk", "__snprintf_chk"):
                f4 = self._readvar(uc, 4)
                if f4 and DEV_BASE <= f4 < DEV_BASE + IMG_SIZE:
                    try:
                        fstr = self.cstr(f4, 64)
                    except UcError:
                        fstr = b""
                    if b"%" in fstr:
                        try:
                            va = VaList(self, self._readvar(uc, 5))
                            s, _ = self._fmt_va(uc, f4, va)
                            done = True
                        except Exception as ex:
                            self.logs.append("va err %r" % (ex,))
            if done:
                dst = a0
                maxlen = a1 if a1 else 0x1000
                if len(s) >= maxlen:
                    s = s[:maxlen - 1]
                self.wr(dst, s + b"\x00")
                self.vsnprintf_calls.append(s)
                ret = len(s)
            else:
                # 通用回退: 在 x0..x5 中找指向含 '%' 的格式串的指针
                fi = None
                for k in range(0, 6):
                    v = self._readvar(uc, k)
                    if v and DEV_BASE <= v < DEV_BASE + IMG_SIZE:
                        try:
                            if b"%" in self.cstr(v, 64):
                                fi = k
                                break
                        except UcError:
                            pass
                if fi is None:
                    self.logs.append("vsnprintf: fmt not found")
                    ret = 0
                else:
                    s, _ = self._fmt(uc, self._readvar(uc, fi), fi + 1)
                    dst = a0
                    maxlen = a1 if a1 else 0x1000
                    if len(s) >= maxlen:
                        s = s[:maxlen - 1]
                    self.wr(dst, s + b"\x00")
                    self.vsnprintf_calls.append(s)
                    ret = len(s)
        elif nm in ("__errno", "__errno_location", "___errno", "__errno_location_"):
            ret = TLS + 0x100
        elif nm in ("localeconv", "__localeconv_l"):
            if getattr(self, "_lconv", None) is None:
                dot = self.alloc(2)
                self.wr(dot, b".\x00")
                empty = self.alloc(1)
                self.wr(empty, b"\x00")
                lc = self.alloc(0x60)
                self.wr(lc, b"\x00" * 0x60)
                for i in range(10):
                    self.wr(lc + i * 8, struct.pack("<Q", dot if i == 0 else empty))
                self._lconv = lc
            ret = self._lconv
        elif nm in ("setlocale",):
            ret = TLS + 0x200
            self.wr(TLS + 0x200, b"C\x00")
        elif nm in ("__ctype_get_mb_cur_max", "mb_cur_max"):
            ret = 1
        elif nm in ("time", "clock", "getpid"):
            ret = 0
        elif nm in ("clock_gettime", "gettimeofday"):
            if a0:
                self.wr(a0, b"\x00" * 16)
            if nm == "clock_gettime" and a1:
                self.wr(a1, b"\x00" * 16)
            ret = 0
        elif nm in ("atoi", "atol", "strtol", "strtoul"):
            s = self.cstr(a0, 64).decode("ascii", "ignore").strip()
            num = ""
            for ch in s:
                if ch.isdigit() or (ch == "-" and not num):
                    num += ch
                else:
                    break
            try:
                ret = int(num) & 0xFFFFFFFFFFFFFFFF if num else 0
            except Exception:
                ret = 0
        elif nm in ("getauxval", "getpid", "gettid", "getuid", "geteuid"):
            ret = 0
        elif nm in ("fopen", "fdopen", "freopen", "popen", "opendir", "dlopen"):
            ret = 0
        elif nm in ("fclose", "fread", "fwrite", "fseek", "fgets", "pclose", "closedir", "dlclose"):
            ret = 0
        elif nm in ("mmap", "mmap64", "mprotect"):
            ret = 0
        elif nm in ("munmap",):
            ret = 0
        elif nm in ("__system_property_get", "__android_log_print", "__android_log_write"):
            ret = 0
        elif nm in ("pthread_self",):
            ret = TLS
        elif nm == "__cxa_guard_acquire":
            g = a0
            cur = self.rd_u64(g)
            if cur == 0:
                self.wr(g, struct.pack("<Q", 0x100))
                ret = 1
            else:
                ret = 0
        elif nm == "__cxa_guard_release":
            self.wr(a0, struct.pack("<Q", 0x101))
            ret = 0
        elif nm in ("__stack_chk_fail", "__stack_chk_fail_local"):
            self.logs.append("STACK CHK FAIL at lr=%#x" % uc.reg_read(UC_ARM64_REG_LR))
            uc.emu_stop()
            ret = 0
        elif nm in ("abort", "__assert_fail", "__android_log_assert"):
            self.logs.append("ABORT %s at lr=%#x" % (nm, uc.reg_read(UC_ARM64_REG_LR)))
            uc.emu_stop()
            ret = 0
        elif nm == "sysconf":
            ret = 4096 if a0 in (30, 39) else 8
        elif nm in ("getenv",):
            ret = 0
        elif nm in ("pthread_mutex_lock", "pthread_mutex_unlock", "pthread_once", "pthread_key_create",
                    "pthread_getspecific", "pthread_setspecific", "pthread_rwlock_rdlock", "pthread_rwlock_unlock",
                    "pthread_rwlock_wrlock", "nanosleep", "usleep", "srand", "srandom", "setlocale",
                    "pthread_attr_init", "pthread_attr_destroy", "pthread_cond_init", "pthread_cond_destroy",
                    "pthread_mutex_init", "pthread_mutex_destroy", "pthread_cond_signal", "pthread_cond_wait",
                    "signal", "sigaction", "atexit", "__cxa_atexit"):
            if nm == "__cxa_atexit":
                pass
            ret = 0
        elif nm in ("strchr", "strrchr", "strstr"):
            s1, s2 = a0, a1
            try:
                hay = self.cstr(s1, 1 << 16)
            except Exception:
                hay = b""   # haystack 未映射 (如 VPN 接口状态未初始化) → 视为空串
            if nm == "strchr":
                ch = bytes([a1 & 0xFF])
                idx = hay.find(ch)
            elif nm == "strrchr":
                ch = bytes([a1 & 0xFF])
                idx = hay.rfind(ch)
            else:
                try:
                    needle = self.cstr(s2, 4096)
                except Exception:
                    needle = b""
                idx = hay.find(needle)
            ret = (s1 + idx) if idx >= 0 else 0
        else:
            self.logs.append("stub? %s" % nm)
            ret = 0
        uc.reg_write(UC_ARM64_REG_X0, ret)


if __name__ == "__main__":
    e = Emu()
    print("imports patched:", e.import_patched)
    print("relocs:", len(e.relocs))
    print("fmt 0x68977f:", e.cstr(DEV_BASE + 0x68977f, 64))
    print("str@0x689730:", e.cstr(DEV_BASE + 0x689730, 64))
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    print("str obj @0x688130:", e.str_obj(DEV_BASE + 0x688130))
    print("str obj @0x688148:", e.str_obj(DEV_BASE + 0x688148))
