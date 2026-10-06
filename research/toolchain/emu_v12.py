# -*- coding: utf-8 -*-
# emu_v12.py — 在 emu_v11 基础上增加: 内存故障时按需从真机拉取该段并映射
import os, sys, struct, subprocess, json
from unicorn import *
from unicorn.arm64_const import *

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from emu_v11 import Emu, DEV_BASE, IMG_SIZE, STUBS, TLS, HEAP, STACK, MAGIC_RET

ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
HERE = os.path.dirname(os.path.abspath(__file__))

RPC_JS = r"""
rpc.exports = {
  rangeof: function (a) {
    try {
      var r = Process.findRangeByAddress(ptr(a));
      if (!r) return null;
      return { base: r.base.toString(), size: r.size, prot: r.protection };
    } catch (e) { return null; }
  },
  readmem: function (a, n) {
    try {
      var buf = new Uint8Array(ptr(a).readByteArray(n));
      var s = '';
      for (var i = 0; i < buf.length; i++) s += ('0' + buf[i].toString(16)).slice(-2);
      return s;
    } catch (e) { return null; }
  }
};
"""


def adb(*a):
    return subprocess.run([ADB, "shell"] + list(a), capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout


class DevReader:
    def __init__(self):
        import frida
        ps = adb("ps -A -o PID,NAME")
        pid = None
        for line in ps.splitlines():
            if "com.tudou.tool" in line:
                pid = line.split()[0].strip()
        if not pid:
            raise RuntimeError("app not running")
        self.pid = int(pid)
        self.dev = frida.get_usb_device(timeout=15)
        self.ses = self.dev.attach(self.pid)
        self.sc = self.ses.create_script(RPC_JS)
        self.sc.load()
        self.cache = {}

    def rangeof(self, addr):
        return self.sc.exports_sync.rangeof(addr)

    def read(self, base, size, chunk=0x100000):
        out = bytearray()
        off = 0
        while off < size:
            n = min(chunk, size - off)
            h = self.sc.exports_sync.readmem(base + off, n)
            if h is None:
                out += b"\x00" * n
            else:
                out += bytes.fromhex(h)
            off += n
        return bytes(out)

    def close(self):
        try:
            self.ses.detach()
        except Exception:
            pass


class Emu2(Emu):
    def __init__(self, *a, **kw):
        self.dev = None
        self.lazy_log = []
        self.lazy_bytes = 0
        self.mapped = []
        super().__init__(*a, **kw)

    def attach_device(self):
        self.dev = DevReader()
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_unmapped)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_PROT, self._on_wprot)
        return self.dev.pid

    # ---- 惰性映射 ----
    def _map_region(self, addr):
        """从真机拉取包含 addr 的段并映射进来。返回 True 表示已处理。"""
        self.nmap = getattr(self, "nmap", 0) + 1
        if self.nmap > 60:
            print("  [lazy] 映射次数超过 60, 停止", flush=True)
            return False
        r = self.dev.rangeof(addr)
        print("  [lazy] #%d addr=%#x range=%s" % (self.nmap, addr, r), flush=True)
        if not r:
            # 真机也没映射: 建个零页
            base = addr & ~0xFFF
            try:
                self.uc.mem_map(base, 0x1000, UC_PROT_ALL)
            except UcError:
                pass
            self.lazy_log.append(("zero", hex(base), 0x1000))
            return True
        base = int(r["base"], 16)
        size = int(r["size"])
        prot = r["prot"]
        if size > 0x1000000:   # 16MB 上限
            self.lazy_log.append(("too-big", hex(base), size))
            print("  [lazy] too-big %#x %#x" % (base, size), flush=True)
            return False
        data = self.dev.read(base, size)
        try:
            self.uc.mem_map(base, (size + 0xFFF) & ~0xFFF, UC_PROT_ALL)
        except UcError:
            pass
        try:
            self.uc.mem_write(base, data)
        except UcError:
            pass
        self.lazy_log.append(("map", hex(base), size, prot))
        self.mapped.append((base, size))
        self.lazy_bytes += size
        print("  [lazy] map %#x size=%#x prot=%s (total %.1f MB)" % (base, size, prot, self.lazy_bytes / 1048576.0), flush=True)
        if self.lazy_bytes > 0x10000000:
            print("  [lazy] 超出 256MB 上限, 停止", flush=True)
            return False
        return True

    def _on_unmapped(self, uc, access, address, size, value, ud):
        if access == UC_MEM_FETCH_UNMAPPED:
            self.lazy_log.append(("fetch-fault", hex(address), 0))
            return False
        ok = self._map_region(address)
        return ok

    def _on_wprot(self, uc, access, address, size, value, ud):
        base = address & ~0xFFF
        try:
            self.uc.mem_protect(base, 0x1000, UC_PROT_ALL)
        except UcError:
            pass
        return True


if __name__ == "__main__":
    e = Emu2()
    print("pid", e.attach_device())
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr("1790618586109")
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148), sret=sret, timeout=120_000_000)
    except Exception as ex:
        print("ERR", repr(ex))
    print("lazy:", len(e.lazy_log), "bytes:", e.lazy_bytes)
    for t in e.lazy_log[:20]:
        print("  ", t)
    try:
        print("sret:", e.str_obj(sret))
    except Exception as ex:
        print("sret raw:", e.rd(sret, 0x30).hex())
    print("logs:", e.logs[-10:])
    e.dev.close()
