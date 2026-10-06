# -*- coding: utf-8 -*-
# run_rd.py — 读真机 libcore 指定偏移
import sys, os, json, time, subprocess
import frida

ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
HERE = os.path.dirname(os.path.abspath(__file__))

def adb(*a):
    return subprocess.run([ADB, "shell"] + list(a), capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout

def find_pid_base():
    ps = adb("ps -A -o PID,NAME")
    pid = None
    for line in ps.splitlines():
        if "com.tudou.tool" in line:
            pid = line.split()[0].strip()
    maps = adb("su -c 'grep libcore.so /proc/%s/maps'" % pid)
    base = None
    for line in maps.splitlines():
        if "libcore.so" in line:
            base = line.split("-")[0]
            break
    return pid, ("0x" + base) if base else None

def main():
    offs = json.loads(sys.argv[1]) if len(sys.argv) > 1 else [[0x66efe0, 16]]
    pid, base = find_pid_base()
    print("pid", pid, "base", base, flush=True)
    dev = frida.get_usb_device(timeout=15)
    ses = dev.attach(int(pid))
    done = [False]
    def on_message(msg, data):
        if msg["type"] == "send":
            p = msg["payload"]
            for v in p.get("vals", []):
                print("  %#x (%d): %s" % (v["off"], v["n"], v["hex"]), flush=True)
            done[0] = True
        else:
            print("[ERR]", str(msg)[:300], flush=True)
    sc = ses.create_script(open(os.path.join(HERE, "rd.js"), encoding="utf-8").read())
    sc.on("message", on_message)
    sc.load()
    sc.post({"type": "go", "base": base, "offs": offs})
    for _ in range(40):
        if done[0]:
            break
        time.sleep(0.25)
    try: ses.detach()
    except Exception: pass

main()
