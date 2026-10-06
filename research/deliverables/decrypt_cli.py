# -*- coding: utf-8 -*-
"""decrypt_cli.py — 独立进程里的响应解密器（供 authgen_server 以子进程方式调用）。

为什么要单独一个进程：
    E 的解密靠 Unicorn 仿真 libcore.so，长响应要跑几分钟。Unicorn 的 emu_start
    在 C 扩展里长时间不释放 GIL，若放在服务进程的线程里执行，会把整个 HTTP 服务
    卡死（连 /health 之外的所有端点都无响应）。放到独立进程就互不影响。

用法::

    echo "<P0>.<P1>" | python decrypt_cli.py                    # stdout
    echo "<P0>.<P1>" | python decrypt_cli.py out.json           # 写文件（原子）
    echo "<P0>.<P1>" | python decrypt_cli.py - 64               # 只解前 64 块（秒级）

给了输出路径时**原子写**（先写 `.tmp` 再 `os.replace`），避免读到半截 JSON。
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def main() -> int:
    args = sys.argv[1:]
    out_path = args[0] if args and args[0] != "-" else None
    blocks = int(args[1]) if len(args) > 1 and args[1].isdigit() else None
    body = sys.stdin.read()
    try:
        from authgen_server import decrypt_response
        out = decrypt_response(body, blocks)
    except Exception as exc:  # noqa: BLE001
        out = {"ok": False, "error": repr(exc)}
    txt = json.dumps(out, ensure_ascii=False)
    if out_path:
        tmp = out_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(txt)
        os.replace(tmp, out_path)
    else:
        sys.stdout.write(txt)
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
