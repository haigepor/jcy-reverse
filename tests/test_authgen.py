# -*- coding: utf-8 -*-
"""tests/test_authgen.py — authentication 生成算法回归测试。

用法::

    ./.venv/Scripts/python.exe tests/test_authgen.py

判据（与 tests/fixtures/authgen_vector.json 固化向量比对）:
  1. authentication 头长度 = 152
  2. 解码后 body 长度 = 112
  3. body[0:16] == ct0          （恒定前缀）
  4. body[16:48] == O[0:32]     （服务端实际校验的 32 字节）
  5. 头前 20 字符与真机抓包一致

依赖 research/artifacts/ 下的 libcore.so 与设备内存镜像；缺失时以退出码 77
表示"跳过"（SKIP），不算失败。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DELIVERABLES = os.path.join(ROOT, "research", "deliverables")
FIXTURE = os.path.join(HERE, "fixtures", "authgen_vector.json")

sys.path.insert(0, DELIVERABLES)

SKIP = 77


def main():
    vec = json.load(open(FIXTURE, encoding="utf-8"))

    try:
        import authgen
    except Exception as exc:  # 依赖缺失（unicorn / artifacts）
        print("SKIP: 无法导入 authgen: %r" % exc)
        return SKIP

    try:
        auth = authgen.gen(vec["ts"])
    except FileNotFoundError as exc:
        print("SKIP: %s" % exc)
        return SKIP

    body = authgen.custom_b64d(auth)
    checks = [
        ("auth 长度 = %d" % vec["auth_len"], len(auth) == vec["auth_len"]),
        ("body 长度 = %d" % vec["body_len"], len(body) == vec["body_len"]),
        ("body[0:16] == ct0", body[0:16].hex() == vec["ct0_hex"]),
        ("body[16:48] == O[0:32]", body[16:48].hex() == vec["o32_hex"]),
        ("头前 24 字符一致", auth[:24] == vec["auth_prefix24"]),
    ]

    failed = 0
    for name, ok in checks:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
        failed += 0 if ok else 1

    if failed:
        print("\n[test_authgen] 失败 %d 项" % failed)
        print("  实际 body[0:16]  = %s" % body[0:16].hex())
        print("  实际 body[16:48] = %s" % body[16:48].hex())
        return 1

    print("\n[test_authgen] 通过（5/5）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
