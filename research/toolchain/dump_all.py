# -*- coding: utf-8 -*-
# dump_all.py — 转储进程全部 rw 内存区域 (批量脚本, 一次 adb 调用)
import os, re, sys, json, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
MAPS = os.path.join(HERE, "maps2.txt")
OUT = _P.REGIONS_ALL_DIR
MAXSZ = int(os.environ.get("MAXSZ", str(64 * 1024 * 1024)))


def adb(args, timeout=3600, binary=False):
    return subprocess.run([ADB] + args, capture_output=True, text=not binary, timeout=timeout)


def main():
    pid = None
    ps = adb(["shell", "ps", "-A", "-o", "PID,NAME"]).stdout
    for line in ps.splitlines():
        if "com.tudou.tool" in line:
            pid = line.split()[0].strip()
    print("pid", pid, flush=True)
    regs = []
    for line in open(MAPS, encoding="utf-8", errors="replace"):
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
        if not m:
            continue
        a, b = int(m.group(1), 16), int(m.group(2), 16)
        perm, path = m.group(3), m.group(4).strip()
        if "rw" not in perm:
            continue
        sz = b - a
        if sz <= 0 or sz > MAXSZ:
            continue
        regs.append((a, sz, perm, path))
    tot = sum(r[1] for r in regs)
    print("regions to dump:", len(regs), "total %.1f MB" % (tot / 1048576), flush=True)

    lines = ["#!/system/bin/sh", "rm -rf /data/local/tmp/d", "mkdir -p /data/local/tmp/d"]
    for i, (a, sz, perm, path) in enumerate(regs):
        pages = sz // 4096
        if pages <= 0:
            continue
        lines.append("/system/bin/toybox dd if=/proc/%s/mem of=/data/local/tmp/d/%04d.bin "
                     "bs=4096 skip=%d count=%d 2>/dev/null" % (pid, i, a // 4096, pages))
    lines.append("cd /data/local/tmp/d && tar -cf /data/local/tmp/d.tar .")
    lines.append("echo DONE_$?")
    script = "\n".join(lines) + "\n"
    sp = os.path.join(HERE, "_dump.sh")
    open(sp, "w", newline="\n").write(script)
    r = adb(["push", sp, "/data/local/tmp/do.sh"])
    print("push:", r.stdout.strip()[-120:], r.stderr.strip()[-120:], flush=True)
    t0 = time.time()
    r = adb(["shell", "su", "-c", "sh /data/local/tmp/do.sh"])
    print("dd+tar done in %.0fs" % (time.time() - t0), r.stdout.strip()[-200:], flush=True)
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    r = adb(["pull", "/data/local/tmp/d.tar", os.path.join(HERE, "d.tar")])
    print("pull %.0fs" % (time.time() - t0), r.stdout.strip()[-160:], r.stderr.strip()[-160:], flush=True)
    adb(["shell", "su", "-c", "rm -rf /data/local/tmp/d /data/local/tmp/d.tar /data/local/tmp/do.sh"])
    subprocess.run(["tar", "-xf", os.path.join(HERE, "d.tar"), "-C", OUT], check=False)
    manifest = []
    miss = 0
    for i, (a, sz, perm, path) in enumerate(regs):
        fn = "%04d.bin" % i
        p = os.path.join(OUT, fn)
        if os.path.exists(p) and os.path.getsize(p) == sz:
            manifest.append({"base": a, "size": sz, "file": fn, "perm": perm, "path": path})
        else:
            miss += 1
    json.dump(manifest, open(_P.REGIONS_ALL_JSON, "w"), indent=1)
    print("manifest entries:", len(manifest), "/", len(regs), "miss", miss, flush=True)


if __name__ == "__main__":
    main()
