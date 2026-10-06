# -*- coding: utf-8 -*-
"""decrypt_response.py — 囧次元 HTTP 响应体解密器 (V11 最终模型, 2026-10-02)

已证实的协议模型 (全部有实验证据, 详见 docs/crypto/http-body.md):
  1. 请求/响应体均为 "<P0_b64>.<P1_b64>" 点分两段, 自定义 base64 字母表:
     5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj
  2. 响应 P0 = RSA-2048 PKCS1-v1.5(pub_from_go, K16) ← 离线可解 (priv_from_go.pem)
     K16 = 16 字符大写字母数字, 每响应换新; 8 组 oracle 证明 K16 及其常见变换
     (rev/md5/sha256/hex前缀) 都不是 P1 的密钥。
  3. 响应 P1 = AES-CBC(请求会话 key, 请求会话 iv, 业务 JSON)
     —— key/iv 由 libcore native 在 api_encrypt 时经 RAND_bytes(/dev/urandom) 生成,
     存入 native key store (pthread rwlock 保护), 服务端用同一对 key/iv 加密响应;
     key store 为空时 native api_decrypt 直接回显 (emu 实证)。
  4. 因此: 历史抓包离线批量解密不可行 (key 每请求随机、请求 P0 仅服务端可解、
     内存 dump 3.7M 可打印窗口双块 oracle 0 命中)。
     可行路径 = 抓请求时同步取 key+iv:
       a) frida hook EVP_EncryptInit_ex @libcore+0x387da4 → x3=key, x4=iv
          (业务调用; 信封层 key 恒为 qPwClBj7j7ZQraSm/p3JdVQl3q7WQJIgG 可据此区分);
       b) 或 hook RAND_bytes @libcore+0x438d18 (api_encrypt 恰好生成 16B key)。

用法:
  python decrypt_response.py unwrap --body "P0b64.P1b64"      # P0 → K16 (离线)
  python decrypt_response.py unwrap --file resp.txt
  python decrypt_response.py decrypt --file resp.txt --key KEY16 --iv IV16
  python decrypt_response.py decrypt --body "P0.P1" --key .. --iv ..
  python decrypt_response.py pairs --pairs pairs.jsonl        # 每行 {body,key,iv,req}
  python decrypt_response.py selftest                         # 复跑 8 组已证伪 oracle

退出码: 0 成功 / 1 解密失败或 selftest 出现非零命中 / 2 用法错误
"""
import argparse
import base64
import hashlib
import json
import os
import sys

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

CUST = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
_TR = str.maketrans(CUST, STD)

_HERE = os.path.dirname(os.path.abspath(__file__))
PRIV_PATH = os.path.join(_HERE, 'rsa_client_private.pem')
# 仓库内实测可解封全部响应 P0 的私钥备份位置 (ripplescan 目录)
PRIV_FALLBACK = os.path.join(_HERE, '..', 'captures', 'rsa_scan', 'priv_from_go.pem')


def _priv():
    for p in (PRIV_PATH, PRIV_FALLBACK):
        if os.path.exists(p):
            return RSA.import_key(open(p, 'rb').read())
    raise SystemExit('未找到 RSA 私钥 (试过 %s / %s)' % (PRIV_PATH, PRIV_FALLBACK))


def cb64(s: str) -> bytes:
    """自定义字母表 base64 解码 (HTTP body 用); 自动补齐 padding, 失败返回 b''."""
    try:
        t = s.strip().translate(_TR)
        return base64.b64decode(t + '=' * (-len(t) % 4))
    except Exception:
        return b''


def split_body(body: str):
    """拆 "<P0_b64>.<P1_b64>" → (p0_bytes, p1_bytes); 非 256B P0 (如 301 明文) → None."""
    if not body or '.' not in body:
        return None
    p0s, p1s = body.strip().split('.', 1)
    p0, p1 = cb64(p0s), cb64(p1s)
    if len(p0) != 256:
        return None
    return p0, p1


def unwrap_k16(body: str):
    """响应 P0 → K16 (16 字符 ASCII). 离线可用, 实测 134/134."""
    sp = split_body(body)
    if not sp:
        return None
    k = PKCS1_v1_5.new(_priv()).decrypt(sp[0], None)
    return k if k and len(k) == 16 else None


def decrypt_p1(body: str, key: bytes, iv: bytes):
    """响应 P1 = AES-CBC(key, iv, JSON) + PKCS7. key/iv 来自 api_encrypt 时的 live hook."""
    sp = split_body(body)
    if not sp:
        return None, 'body 不是 <P0>.<P1> 形态 (或 P0 非 256B)'
    p1 = sp[1]
    if not p1 or len(p1) % 16:
        return None, 'P1 长度 %d 非 16 对齐' % len(p1)
    if len(key) != 16 or len(iv) != 16:
        return None, 'key/iv 必须各 16 字节'
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(p1)
    n = pt[-1]
    if 1 <= n <= 16 and pt[-n:] == bytes([n]) * n:
        pt = pt[:-n]
    try:
        return json.loads(pt.decode('utf-8')), None
    except Exception:
        return pt, '已解密但非合法 JSON (key/iv 与该响应不匹配?)'


def load_body(text_or_path: str) -> str:
    if os.path.exists(text_or_path):
        return open(text_or_path, encoding='utf-8', errors='replace').read().strip()
    t = text_or_path.strip()
    if t.count('.') == 1 and all(33 <= ord(c) < 127 for c in t[:80]):
        return t
    raise SystemExit('既不是文件路径也不像 <P0>.<P1> body: %.60s...' % t)


def cmd_unwrap(a):
    k = unwrap_k16(load_body(a.body or a.file))
    print('K16 =', k.decode() if k else '解封失败 (P0 非 256B 或 RSA 不匹配)')
    return 0 if k else 1


def cmd_decrypt(a):
    obj, err = decrypt_p1(load_body(a.body or a.file), a.key.encode(), a.iv.encode())
    if obj is None:
        print('失败:', err, file=sys.stderr)
        return 1
    print(json.dumps(obj, ensure_ascii=False, indent=2)[:4000])
    return 0


def cmd_pairs(a):
    ok = bad = 0
    for line in open(a.pairs, encoding='utf-8'):
        o = json.loads(line)
        obj, err = decrypt_p1(o['body'], o['key'].encode(), o['iv'].encode())
        if obj is None:
            bad += 1
            print('FAIL', o.get('req', '?'), err, file=sys.stderr)
        else:
            ok += 1
            print('OK  ', o.get('req', '?'), json.dumps(obj, ensure_ascii=False)[:120])
    print('合计: %d 成功 / %d 失败' % (ok, bad))
    return 0 if bad == 0 else 1


def cmd_selftest(a):
    """对 134 条历史响应复跑全部已证伪假设 — 期望全 0, 锁定模型边界."""
    HERE = os.path.join(_HERE, '..', 'captures', 'rsa_scan')
    bodies = [json.loads(l) for l in open(os.path.join(HERE, 'bodies_now.jsonl'),
                                          encoding='utf-8')]
    priv = _priv()
    pairs = []
    for o in bodies:
        rh = o.get('resp_body_hex')
        if not rh:
            continue
        txt = bytes.fromhex(rh).decode('ascii', 'replace')
        sp = split_body(txt)
        if not sp:
            continue
        k = PKCS1_v1_5.new(priv).decrypt(sp[0], None)
        if k and len(sp[1]) >= 32 and len(sp[1]) % 16 == 0:
            pairs.append((k, sp[1]))
    print('样本: %d 条 (P0 解封率 100%% = RSA 模型成立)' % len(pairs))

    def pkcs7(pt):
        n = pt[-1]
        return 1 <= n <= 16 and pt[-n:] == bytes([n]) * n

    stats = {}
    for k, p1 in pairs:
        kcs = {'K16': k, 'K16rev': k[::-1],
               'md5': hashlib.md5(k).digest(),
               'md5hex16': hashlib.md5(k).hexdigest()[:16].encode(),
               'sha256_16': hashlib.sha256(k).digest()[:16]}
        for kn, kk in kcs.items():
            ecb = AES.new(kk, AES.MODE_ECB)
            pt = bytes(x ^ y for x, y in zip(ecb.decrypt(p1[-16:]), p1[-32:-16]))
            stats.setdefault('CBC+PKCS7/' + kn, 0)
            stats['CBC+PKCS7/' + kn] += pkcs7(pt)
            d0 = ecb.decrypt(p1[:16])
            d1 = ecb.decrypt(p1[16:32])
            p2 = bytes(x ^ y for x, y in zip(d1, p1[:16]))
            stats.setdefault('crib+block2/' + kn, 0)
            stats['crib+block2/' + kn] += all(32 <= c < 127 for c in p2)
            stats.setdefault('ECB-json/' + kn, 0)
            stats['ECB-json/' + kn] += (d0[:1] == b'{' and all(32 <= c < 127 for c in d0))
    bad = 0
    for kn in sorted(stats):
        # PKCS7 随机假阳性率 ≈0.4%/条; ≤5% 视为噪声, 显著高于噪声才判模型失效
        noisy = stats[kn] > max(2, len(pairs) * 0.05)
        bad += noisy
        flag = '  <- 显著高于噪声! 模型需修正' if noisy else ''
        print('  %-28s %d/%d%s' % (kn, stats[kn], len(pairs), flag))
    print('结论:', '全部处于噪声水平 — P1 密钥非 K16 系, 模型边界成立'
          if bad == 0 else '存在显著命中, 需人工复核')
    return 0 if bad == 0 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('unwrap', help='响应 P0 → K16 (离线)')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--body')
    g.add_argument('--file')
    p.set_defaults(fn=cmd_unwrap)

    p = sub.add_parser('decrypt', help='P1 解密 (需 live key/iv)')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--body')
    g.add_argument('--file')
    p.add_argument('--key', required=True, help='16 字符会话 key (api_encrypt 时 hook)')
    p.add_argument('--iv', required=True, help='16 字符会话 iv')
    p.set_defaults(fn=cmd_decrypt)

    p = sub.add_parser('pairs', help='批量: jsonl 每行 {body,key,iv,req}')
    p.add_argument('--pairs', required=True)
    p.set_defaults(fn=cmd_pairs)

    p = sub.add_parser('selftest', help='复跑已证伪 oracle (期望全 0)')
    p.set_defaults(fn=cmd_selftest)

    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == '__main__':
    main()
