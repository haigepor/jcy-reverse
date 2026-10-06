# -*- coding: utf-8 -*-
# crib 自验证扫描: 响应 P1 = AES-CBC(key=K16, iv=?, JSON)?
# 已知: JSON 响应首块 16B 高度可预测 → IV = D_k(C0) ^ crib
# 自验证: P1_block2 = D_k(C1) ^ IV 必须可打印 ASCII (且与 block1 拼成合法 JSON 延续)
import json, base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

HERE = 'C:/Users/haige/Desktop/instruct/囧次元/research/captures/rsa_scan'
CUST = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
TR = str.maketrans(CUST, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')

def cb64(s):
    t = s.translate(TR)
    return base64.b64decode(t + '=' * (-len(t) % 4))

priv = RSA.import_key(open(HERE + '/priv_from_go.pem', 'rb').read())
cp = PKCS1_v1_5.new(priv)

# crib 候选: 常见 code 开头的 16B 首块
codes = ['20000', '200', '30000', '40000', '403501', '403502', '500', '401', '0', '10000']
cribs = set()
for c in codes:
    s = '{"code":' + c + ','
    for tail in ['"m', '"me', '"mes', '"mess', '"data', '"d']:
        if len(s + tail) == 16:
            cribs.add((s + tail).encode())
    if len(s) <= 16:
        cribs.add((s + 'x' * (16 - len(s))).encode())
# 兜底: 模板 {"code":NNNNN," 后接任意 → 枚举 '"m' 前缀不足则不加
cribs.add(b'{"code":20000,"m')
cribs.add(b'{"code":200,"mes')
cribs.add(b'{"code":30000,"m')

bodies = [json.loads(l) for l in open(HERE + '/bodies_now.jsonl', encoding='utf-8')]

hits = []
n_p0p1 = 0; n_k16 = 0
for i, o in enumerate(bodies):
    rh = o.get('resp_body_hex')
    if not rh: continue
    rb = bytes.fromhex(rh)
    try:
        txt = rb.decode('ascii')
    except Exception:
        continue
    if '.' not in txt: continue
    p0s, p1s = txt.split('.', 1)
    try:
        p0 = cb64(p0s); p1 = cb64(p1s)
    except Exception:
        continue
    if len(p0) != 256 or len(p1) < 32 or len(p1) % 16: continue
    n_p0p1 += 1
    k = cp.decrypt(p0, None)
    if not k or len(k) != 16:
        continue
    n_k16 += 1
    ecb = AES.new(k, AES.MODE_ECB)
    d0 = ecb.decrypt(p1[:16])
    d1 = ecb.decrypt(p1[16:32])
    for crib in cribs:
        iv = bytes(a ^ b for a, b in zip(d0, crib))
        # CBC 链: P2 = D(C2) ^ C1  (C1 = p1[:16])
        p1b = bytes(a ^ b for a, b in zip(d1, p1[:16]))
        if all(32 <= c < 127 for c in p1b):
            hits.append((i, o['req'][:45], k, crib, iv, p1b))
            break

print(f'P0.P1 响应: {n_p0p1}  K16 unwrap OK: {n_k16}  crib hits: {len(hits)}')
for i, req, k, crib, iv, p1b in hits[:20]:
    print(f'rec{i} {req}\n  K16={k!r} crib={crib!r}\n  IV={iv!r}\n  block2={p1b!r}')
if not hits:
    # 失败也输出 d0 结构供诊断: 看 d0^d1 或直接看任意一条
    for i, o in enumerate(bodies[:40]):
        rh = o.get('resp_body_hex')
        if not rh: continue
        rb = bytes.fromhex(rh)
        try: txt = rb.decode('ascii')
        except Exception: continue
        if '.' not in txt: continue
        p0s, p1s = txt.split('.', 1)
        try: p0 = cb64(p0s); p1 = cb64(p1s)
        except Exception: continue
        if len(p0) != 256 or len(p1) < 32 or len(p1) % 16: continue
        k = cp.decrypt(p0, None)
        if not k: continue
        ecb = AES.new(k, AES.MODE_ECB)
        print('sample rec%d K16=%r d0=%r' % (i, k, ecb.decrypt(p1[:16])))
        break
