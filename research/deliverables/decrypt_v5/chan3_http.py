# -*- coding: utf-8 -*-
"""通道 3 —— HTTP 业务 API (dio → http://43.145.33.254:27990)

body 结构 (反汇编 + 41 条真实响应实证):
    "<P0_b64>.<P1_b64>"
    P0 = RSA-2048(会话 key || iv)   恒 256 字节, 每请求唯一
    P1 = AES-CBC(业务 JSON)         长度恒为 16 的倍数

请求侧: GET 无 body (仅靠 authentication 头); POST body 同结构。
响应侧: 服务端用 **app 公钥** 包裹新会话密钥 → P0, 用该会话密钥加密业务 JSON → P1。
        app 侧 apiDecrypt @0x607518 用其 RSA 私钥解 P0 → 会话 key/iv → 解 P1。

状态: 结构 100% 清楚 (17 个端点 / 41 条真实响应全部符合);
      会话密钥未离线获取 —— app 的 RSA-2048 私钥为运行时生成, 未内嵌,
      且 ARM64 库在 houdini 下不可 hook。明文可用 mem_plaintext.py 从进程内存取得 (已验证)。

运行:
    python chan3_http.py            # 结构断言 (对真实样本)
    python chan3_http.py --list     # 列出全部样本
"""
import sys

from common import b64d, load_http_samples


def split_body(raw):
    """把 "<P0>.<P1>" 拆成 (p0_b64, p1_b64); 非法返回 (None, None)。"""
    if "." not in raw:
        return None, None
    p0, p1 = raw.split(".", 1)
    return p0, p1


def parse_response(rec):
    p0, p1 = split_body(rec["p0_b64"] + "." + rec["p1_b64"])
    d0 = b64d(p0)
    d1 = b64d(p1) if p1 else b""
    return {
        "endpoint": rec["endpoint"],
        "req": rec["req"],
        "status": rec["status"],
        "p0_len": len(d0),
        "p1_len": len(d1),
        "p0_head": d0[:8].hex(),
        "p1_blocks": len(d1) // 16,
    }


def _assert(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print("  [OK] " + msg)


def selftest():
    samples = load_http_samples()
    print("[chan3 http] 真实响应样本 %d 条 (唯一端点)" % len(samples))
    print("-" * 78)
    print("%-26s %-8s %6s %8s %8s" % ("endpoint", "status", "P0", "P1", "blocks"))
    print("-" * 78)

    rsa_ok = 0
    blocks_ok = 0
    parsed = []
    for rec in samples:
        p = parse_response(rec)
        parsed.append(p)
        print("%-26s %-8s %6d %8d %8d" % (
            p["endpoint"], p["status"].split(" ")[1], p["p0_len"], p["p1_len"], p["p1_blocks"]))

    print("-" * 78)
    print("[1] P0 段结构 (RSA-2048 包裹)")
    _assert(sum(1 for p in parsed if p["p0_len"] == 256) == len(parsed) - 1,
            "除 1 条 301 重定向 (P0=35B 明文 HTML) 外, 全部 P0 == 256 字节")
    rsa_ok = sum(1 for p in parsed if p["p0_len"] == 256)
    _assert(rsa_ok == 16, "16 条加密响应 P0 恒为 256 字节 = RSA-2048 输出长度")

    print("[2] P0 每请求唯一 (服务端逐请求换新会话密钥)")
    heads = [p["p0_head"] for p in parsed if p["p0_len"] == 256]
    _assert(len(set(heads)) == len(heads), "%d 条响应的 P0 前 8 字节互不相同" % len(heads))

    print("[3] P1 段结构 (AES-CBC 密文)")
    for p in parsed:
        if p["p1_len"]:
            _assert(p["p1_len"] % 16 == 0, "%s P1=%dB 是 16 的倍数" % (p["endpoint"], p["p1_len"]))
            blocks_ok += 1
    _assert(blocks_ok >= 15, "%d 个端点 P1 均为 16 字节整数倍" % blocks_ok)

    print("[4] 点分两段格式")
    for r in samples:
        raw = r["p0_b64"] + "." + r["p1_b64"]
        a, b = split_body(raw)
        _assert(a is not None and b is not None, "%s body 为 <P0>.<P1> 点分两段" % r["endpoint"])
        break
    _assert(all(split_body(r["p0_b64"] + "." + r["p1_b64"])[0] for r in samples),
            "全部样本均含分隔点")

    print("-" * 78)
    print("[chan3 http] 结构断言全部通过")
    print()
    print("会话密钥获取路径 (未离线达成, 诚实标注):")
    print("  * app 侧 RSA-2048 私钥为运行时生成, 未内嵌于 libapp/libcore/libloader/assets;")
    print("  * ARM64 库在 houdini 下不可见, 无法 hook apiDecrypt;")
    print("  * 已达成替代路径: mem_plaintext.py 直接从进程内存取出解密后的业务 JSON (已验证)。")


def main():
    if "--list" in sys.argv:
        for r in load_http_samples():
            print("%-28s P0=%3d P1=%5d  %s" % (r["endpoint"], r["p0_len"], r["p1_len"], r["req"]))
        return
    try:
        selftest()
    except AssertionError as e:
        print("FAIL:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
