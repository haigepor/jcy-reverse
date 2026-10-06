#!/usr/bin/env python3
"""dump_mem.py - 按_maps 把 com.tudou.tool 进程可读内存区 dump 到本地.

用法: python dump_mem.py [--out DIR] [--min-size 4096] [--max-region 1073741824]
产出: DIR/NNN_STARTHEX.bin + DIR/regions.json + DIR/maps_raw.txt
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
PKG = "com.tudou.tool"
DEV_TMP = "/data/local/tmp/memdump"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def adb(*args, timeout=120, binary=False):
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    r = subprocess.run([ADB, "-s", "emulator-5554"] + list(args),
                       capture_output=True, timeout=timeout, env=env)
    noise = ("doesn't match", "daemon started successfully", "* daemon")
    out = "\n".join(l for l in r.stdout.decode("utf-8", "replace").splitlines()
                    if not any(n in l for n in noise))
    err = "\n".join(l for l in r.stderr.decode("utf-8", "replace").splitlines()
                    if not any(n in l for n in noise))
    if err.strip():
        print("[adb:err]", err.strip()[:300], file=sys.stderr)
    return out.encode() if binary else out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "research/captures/rsa_scan/memdump"))
    ap.add_argument("--max-region", type=int, default=1 << 30)
    ap.add_argument("--max-total", type=int, default=4 << 30)
    a = ap.parse_args()

    pid = adb("shell", "su -c 'pidof %s'" % PKG).strip().split()
    if not pid:
        sys.exit("App 未运行")
    pid = pid[0]
    print("pid =", pid)

    maps = adb("shell", "su -c 'cat /proc/%s/maps'" % pid, timeout=60)
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, "maps_raw.txt"), "w").write(maps)

    regions = []
    total = 0
    for line in maps.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 2:
            continue
        addr, perms = parts[0], parts[1]
        path = parts[5].strip() if len(parts) > 5 else ""
        if not perms.startswith("r"):
            continue
        if path and not (path.startswith("[") and path not in ("[vdso]", "[vvar]", "[vsyscall]")):
            continue
        if path in ("[vdso]", "[vvar]", "[vsyscall]"):
            continue
        s, e = (int(x, 16) for x in addr.split("-"))
        size = e - s
        if size > a.max_region:
            continue
        if total + size > a.max_total:
            continue
        total += size
        regions.append({"start": s, "end": e, "perms": perms, "path": path, "size": size})
    print("region 数=%d 总量=%.2f GB" % (len(regions), total / (1 << 30)))

    # 生成设备端脚本: dd 逐区拷到 /data/local/tmp/memdump
    lines = ["#!/system/bin/sh", "mkdir -p %s" % DEV_TMP,
             "rm -f %s/*.bin %s/err.log" % (DEV_TMP, DEV_TMP)]
    for i, rg in enumerate(regions):
        blocks = rg["size"] // 4096
        name = "%03d_%x.bin" % (i, rg["start"])
        rg["file"] = name
        lines.append(
            "/data/adb/magisk/busybox dd if=/proc/%s/mem of=%s/%s bs=4194304"
            " skip=%d count=%d iflag=skip_bytes,count_bytes 2>>%s/err.log"
            % (pid, DEV_TMP, name, rg["start"], rg["size"], DEV_TMP))
    lines += ["echo DUMP_DONE", "ls -l %s | tail -3" % DEV_TMP, "df /data/local/tmp | tail -1"]
    script = "\n".join(lines) + "\n"
    open(os.path.join(a.out, "device_dump.sh"), "w", newline="\n").write(script)

    # push 偶发静默失败(adb daemon 重启窗口): 重试并校验设备端文件大小
    local_sz = os.path.getsize(os.path.join(a.out, "device_dump.sh"))
    for attempt in range(3):
        adb("push", os.path.join(a.out, "device_dump.sh"), "/data/local/tmp/device_dump.sh")
        chk = adb("shell", "stat -c %s /data/local/tmp/device_dump.sh 2>/dev/null || echo -1").strip()
        try:
            if int(chk.splitlines()[-1]) == local_sz:
                break
        except (ValueError, IndexError):
            pass
        time.sleep(2)
    else:
        sys.exit("device_dump.sh push 校验失败 3 次")
    t0 = time.time()
    out = adb("shell", "su -c 'sh /data/local/tmp/device_dump.sh'", timeout=1800)
    print(out.strip()[-500:])
    print("设备端耗时 %.0fs" % (time.time() - t0))

    manifest = {"pid": pid, "total": total, "regions": regions}
    json.dump(manifest, open(os.path.join(a.out, "regions.json"), "w"), indent=1)

    t0 = time.time()
    adb("pull", DEV_TMP, a.out + ".pull", timeout=3600)
    print("pull 完成 %.0fs" % (time.time() - t0))
    src = a.out + ".pull"
    if os.path.isdir(src):
        import glob
        for f in glob.glob(os.path.join(src, "**", "*.bin"), recursive=True):
            os.replace(f, os.path.join(a.out, os.path.basename(f)))
        try:
            os.rmdir(src)
        except OSError:
            pass
    bins = [f for f in os.listdir(a.out) if f.endswith(".bin")]
    got = sum(os.path.getsize(os.path.join(a.out, f)) for f in bins)
    print("本地 %d 个 region 文件, 共 %.2f GB" % (len(bins), got / (1 << 30)))


if __name__ == "__main__":
    main()
