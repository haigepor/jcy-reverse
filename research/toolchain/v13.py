# -*- coding: utf-8 -*-
# v13.py — 离线分批方案
#   collect : 无 frida 跑模拟, 收集未映射故障地址 -> faults.json
#   dump    : 单次 frida 会话, 把 faults.json 涉及的段 dump 到 regions/
#   run     : 加载已 dump 的段, 跑模拟并输出结果
import os, sys, json, struct, subprocess, re, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
import paths as _P
from emu_v11 import Emu, DEV_BASE, IMG_SIZE

REG_JSON = _P.REGIONS_JSON
FAULT_JSON = os.path.join(HERE, "logs", "faults.json")
REG_DIR = _P.REGIONS_DIR
MAPS = _P.MAPS_TXT
ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"


def load_maps():
    out = []
    if not os.path.exists(MAPS):
        return out
    for line in open(MAPS, encoding="utf-8", errors="replace"):
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
        if not m:
            continue
        out.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4).strip()))
    return out


MAPS_L = load_maps()


def region_of(addr):
    for a, b, perm, path in MAPS_L:
        if a <= addr < b:
            return a, b, perm, path
    return None


class Emu3(Emu):
    def __init__(self, *a, **kw):
        self.regions = []
        self.faults = []
        self.trace = []
        self.trace_on = False
        self._h_code = None
        super().__init__(*a, **kw)
        self._load_regions()
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_unmapped)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_PROT, self._on_wprot)
        # 性能：默认**不装**全镜像 UC_HOOK_CODE。
        # 装上会让 QEMU 对每个 TB 插桩，实测标定从 ~0.25s/块 掉到 ~0.54s/块。
        # 仅诊断路径（v13 cmd_collect）经 enable_trace() 显式开启。
        if os.environ.get("JCY_TRACE_CODE") == "1":
            self.enable_trace()

    def enable_trace(self):
        self.trace_on = True
        if self._h_code is None:
            self._h_code = self.uc.hook_add(
                UC_HOOK_CODE, self._on_code, begin=DEV_BASE, end=DEV_BASE + IMG_SIZE)

    def _load_regions(self):
        if not os.path.exists(REG_JSON):
            return
        for r in json.load(open(REG_JSON)):
            p = os.path.join(REG_DIR, r["file"])
            if not os.path.exists(p):
                continue
            data = open(p, "rb").read()
            try:
                self.uc.mem_map(r["base"], (len(data) + 0xFFF) & ~0xFFF, UC_PROT_ALL)
            except UcError:
                pass
            self.uc.mem_write(r["base"], data)
            self.regions.append((r["base"], len(data)))

    def _on_code(self, uc, address, size, ud):
        # 性能：默认关闭逐指令 trace（Emu4 继承本 hook，全镜像覆盖，
        # 1M 指令/块 × Python 回调 ≈ 60% 运行时间）。仅诊断路径显式开启。
        if not self.trace_on:
            return
        if len(self.trace) < 400000:
            self.trace.append(address)

    def _on_unmapped(self, uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        self.faults.append((access, address, size, pc))
        return False

    def _on_wprot(self, uc, access, address, size, value, ud):
        try:
            self.uc.mem_protect(address & ~0xFFF, 0x1000, UC_PROT_ALL)
        except UcError:
            pass
        return True


TARGET = os.environ.get("TARGET", "304")


def run_once(verbose=True):
    e = Emu3()
    e.enable_trace()           # 诊断路径：保留逐指令 trace（cmd_collect 依赖）
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    err = None
    if TARGET == "305":
        arg = e.mkstr(os.environ.get("ARG1", "default"))
        try:
            e.call(DEV_BASE + 0x305d94, (1790618586109, arg), sret=sret, timeout=120_000_000)
        except Exception as ex:
            err = "%r args=%r errno=%r addr=%r" % (ex, getattr(ex, "args", None), getattr(ex, "errno", None), getattr(ex, "address", None))
    else:
        inp = e.mkstr(os.environ.get("INPUT", "1790618586109"))
        try:
            e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148), sret=sret, timeout=120_000_000)
        except Exception as ex:
            err = "%r args=%r errno=%r addr=%r" % (ex, getattr(ex, "args", None), getattr(ex, "errno", None), getattr(ex, "address", None))
    out = None
    try:
        out = e.str_obj(sret)
    except Exception:
        pass
    return e, err, out, sret


def cmd_collect():
    e, err, out, sret = run_once()
    print("err:", err)
    print("faults:", len(e.faults))
    print("trace tail:", [hex(x - DEV_BASE) for x in e.trace[-16:]])
    print("vsnprintf:", e.vsnprintf_calls)
    print("mem_faults:", [hex(a) for a in e.mem_faults[:20]])
    for a in set(e.mem_faults):
        e.faults.append((19, a, 1, 0))
    seen = set()
    need = []
    for access, addr, size, pc in e.faults:
        print("  fault access=%d addr=%#x size=%d pc=%#x (off %#x)" % (access, addr, size, pc, pc - DEV_BASE))
        r = region_of(addr)
        key = (r[0], r[1]) if r else (addr & ~0xFFF, (addr & ~0xFFF) + 0x1000)
        if key in seen:
            continue
        seen.add(key)
        need.append({"base": key[0], "size": key[1] - key[0],
                     "access": access, "addr": hex(addr),
                     "perm": r[2] if r else "-", "path": r[3] if r else "-"})
    for n in need:
        print("  need base=%#x size=%#x perm=%s path=%s (fault %s access=%d)" %
              (n["base"], n["size"], n["perm"], n["path"][:50], n["addr"], n["access"]))
    json.dump(need, open(FAULT_JSON, "w"), indent=1)
    print("saved", FAULT_JSON, "out:", out)


RPC_JS = r"""
rpc.exports = {
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


def sh(cmd, timeout=180):
    return subprocess.run([ADB, "shell"] + cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def cmd_dump():
    """用 root + toybox dd 直读 /proc/pid/mem, 无 frida 依赖。"""
    need = json.load(open(FAULT_JSON))
    if not os.path.isdir(REG_DIR):
        os.makedirs(REG_DIR)
    regs = json.load(open(REG_JSON)) if os.path.exists(REG_JSON) else []
    have = {(r["base"], r["size"]) for r in regs}
    todo = [n for n in need if (n["base"], n["size"]) not in have]
    print("todo:", len(todo))
    if not todo:
        print("无需 dump")
        return
    ps = sh(["ps", "-A", "-o", "PID,NAME"]).stdout
    pid = None
    for line in ps.splitlines():
        if "com.tudou.tool" in line:
            pid = line.split()[0].strip()
    print("pid", pid)
    for n in todo:
        base, size = n["base"], n["size"]
        if size <= 0 or size > 0x4000000:
            print("  跳过 %#x size=%#x" % (base, size))
            continue
        pages = size // 4096
        remote = "/data/local/tmp/r_%016x.bin" % base
        inner = "/system/bin/toybox dd if=/proc/%s/mem of=%s bs=4096 skip=%d count=%d" % (
            pid, remote, base // 4096, pages)
        r = sh(["su", "-c", inner])
        fn = "r_%016x.bin" % base
        local = os.path.join(REG_DIR, fn)
        pr = subprocess.run([ADB, "pull", remote, local], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=180)
        ok = os.path.exists(local) and os.path.getsize(local) == size
        print("  %#x size=%#x -> %s ok=%s (dd:%s)" % (base, size, fn, ok, r.stdout.strip().splitlines()[-1:] or ""), flush=True)
        if ok:
            regs.append({"base": base, "size": size, "file": fn})
        sh(["su", "-c", "rm -f " + remote])
    json.dump(regs, open(REG_JSON, "w"), indent=1)
    print("regions.json 现有", len(regs), "段")


def cmd_auto():
    for it in range(8):
        e, err, out, sret = run_once()
        for a in set(e.mem_faults):
            e.faults.append((19, a, 1, 0))
        print("=== iter %d: err=%s faults=%d out=%r ===" % (it, err, len(e.faults), out), flush=True)
        if e.mem_faults:
            print("   mem_faults:", [hex(a) for a in set(e.mem_faults)][:10], flush=True)
        if not e.faults:
            print("sret raw:", e.rd(sret, 0x30).hex())
            print("vsnprintf:", e.vsnprintf_calls)
            print("logs:", e.logs[-10:])
            return
        seen = set()
        need = []
        for access, addr, size, pc in e.faults:
            print("  fault access=%d addr=%#x size=%d pc=%#x (off %#x)" % (access, addr, size, pc, pc - DEV_BASE))
            r = region_of(addr)
            key = (r[0], r[1]) if r else (addr & ~0xFFF, (addr & ~0xFFF) + 0x1000)
            if key in seen:
                continue
            seen.add(key)
            need.append({"base": key[0], "size": key[1] - key[0], "access": access,
                         "addr": hex(addr), "perm": r[2] if r else "-", "path": r[3] if r else "-"})
        for n in need:
            print("   need %#x size=%#x perm=%s path=%s" % (n["base"], n["size"], n["perm"], n["path"][:40]), flush=True)
        json.dump(need, open(FAULT_JSON, "w"), indent=1)
        cmd_dump()


def cmd_run():
    e, err, out, sret = run_once()
    print("err:", err)
    print("faults:", len(e.faults))
    print("sret:", out)
    print("sret raw:", e.rd(sret, 0x30).hex())
    print("logs:", e.logs[-10:])


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "collect"
    {"collect": cmd_collect, "dump": cmd_dump, "run": cmd_run, "auto": cmd_auto}[cmd]()
