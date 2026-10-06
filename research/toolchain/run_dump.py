# -*- coding: utf-8 -*-
# run_dump.py — dump 真机 libcore 完整映像 (base .. base+total)
import sys, os, time, json, subprocess
import frida

ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
JS = os.path.join(HERE, "dump_libcore.js")
OUT = _P.IMG
IDX = _P.IMG_JSON

TOTAL = 0x800000  # vaddr 0 .. 0x800000 (含匿名 bss 至 0x800000)

def adb(*a):
    return subprocess.run([ADB, "shell"] + list(a), capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout

def find_pid_base():
    ps = adb("ps -A -o PID,NAME")
    pid = None
    for line in ps.splitlines():
        if "com.tudou.tool" in line:
            pid = line.split()[0].strip()
    if not pid:
        return None, None
    maps = adb("su -c 'grep libcore.so /proc/%s/maps'" % pid)
    base = None
    for line in maps.splitlines():
        if "libcore.so" in line:
            base = line.split("-")[0]
            break
    return pid, ("0x" + base) if base else None

def main():
    pid, base = find_pid_base()
    print("pid:", pid, "base:", base, flush=True)
    dev = frida.get_usb_device(timeout=15)
    ses = dev.attach(int(pid))
    img = bytearray(b"\x00" * TOTAL)
    got = [0]
    chunks = {}
    def on_message(msg, data):
        if msg["type"] != "send":
            print("[ERR]", str(msg)[:300], flush=True); return
        p = msg["payload"]
        ev = p.get("ev")
        if ev == "chunk":
            off, n, hexs = p["off"], p["n"], p["hex"]
            b = bytes.fromhex(hexs)
            img[off:off + len(b)] = b
            got[0] += 1
            if got[0] % 16 == 0:
                print("  %d chunks, %d bytes" % (got[0], off + n), flush=True)
        elif ev == "done":
            print("== dump done ==", flush=True)
        elif ev == "start":
            print("start:", p, flush=True)
        else:
            print(json.dumps(p, ensure_ascii=False)[:300], flush=True)
    script = ses.create_script(open(JS, encoding="utf-8").read())
    script.on("message", on_message)
    script.load()
    script.post({"type": "go", "base": base, "total": TOTAL})
    time.sleep(45)
    try: ses.detach()
    except Exception: pass
    with open(OUT, "wb") as f:
        f.write(bytes(img))
    json.dump({"base": base, "total": TOTAL, "chunks": got[0]}, open(IDX, "w"))
    print("saved", OUT, len(img), "bytes; chunks =", got[0])

main()
