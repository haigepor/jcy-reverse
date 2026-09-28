# -*- coding: utf-8 -*-
"""Offline: try every scanned AES master key against captured ciphertexts."""
import json, base64, sys
from Crypto.Cipher import AES

def pr(b):
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / max(1, len(b))

def load_ks():
    out = []
    try:
        data = json.load(open('out/mem_ks_hits.json'))
    except FileNotFoundError:
        return out
    for h in data:
        hx = h.get('hex')
        if not hx:
            continue
        try:
            b = bytes.fromhex(hx)
        except Exception:
            continue
        if h['kind'] == 1 and len(b) >= 16:
            out.append(('AES128', b[:16], h['addr']))
        elif h['kind'] == 2 and len(b) >= 32:
            out.append(('AES256', b[:32], h['addr']))
    # dedup
    seen, res = set(), []
    for kind, k, addr in out:
        if k not in seen:
            seen.add(k)
            res.append((kind, k, addr))
    return res

TARGETS = {
    's16_req_p1_48B': open('out/flows/s16_req_p1.bin', 'rb').read(),
    's16_resp_p1_208B': open('out/flows/s16_resp_p1.bin', 'rb').read() if __import__('os').path.exists('out/flows/s16_resp_p1.bin') else None,
    's10_req_p1_48B': open('out/flows/s10_req_p1.bin', 'rb').read() if __import__('os').path.exists('out/flows/s10_req_p1.bin') else None,
    'auth_128B': base64.b64decode('6MsfEg71pCxZ4ipNACeen/YcbGKv51uaewOqy2a2+Z+8vby1NEC5NVlU18ZG9s12CpTvfxx+9c2mm0CjgJj+7SHEH8FgfJL4SAzTwtm3ns4kEFpvoUSVOxlr5KWjQmCSsl7n5tRCTKdhXG6w6T9ONI=='),
    'config_host_112B': base64.b64decode('O4c/fgQ3eVMNwnJvk5ManP4+pDSmIOTsTTiLyFvvZch0c3TFk0h61lT9/I+FQf9pTx0JnWQp+R17sdvckU0wCtMESUz+EvjS0zvLtKwEsSKOKUMF34MEHL2yRav5lZ7G'),
}

def ivs_for(ct):
    return [
        ('ct[:16]', ct[:16]),
        ('zeros', b'\x00' * 16),
        ('appid', b'4150439554430529'),
        ('ct[-16:]?no', b'\x00' * 16),
    ]

def main():
    keys = load_ks()
    print(f"{len(keys)} unique master keys")
    for name, ct in TARGETS.items():
        if not ct:
            continue
        print(f"=== {name} ({len(ct)}B) ===")
        best = []
        for kind, k, addr in keys:
            for ivname, iv in ivs_for(ct):
                try:
                    pt = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
                except Exception:
                    continue
                s = pr(pt)
                if s > 0.9:
                    best.append((s, kind, k.hex(), addr, ivname, pt))
        best.sort(key=lambda t: -t[0])
        for s, kind, kh, addr, ivname, pt in best[:6]:
            print(f"  score={s:.2f} {kind} key={kh} @ {addr} iv={ivname}")
            print(f"    pt: {pt[:96]!r}")
        if not best:
            print("  no printable decrypt")
        # also try: ct[:16] as IV, decrypt rest
        for kind, k, addr in keys:
            try:
                pt = AES.new(k, AES.MODE_CBC, ct[:16]).decrypt(ct[16:])
                if pr(pt) > 0.9:
                    print(f"  IV-embedded variant: {kind} key={k.hex()} pt={pt[:96]!r}")
            except Exception:
                pass

if __name__ == '__main__':
    main()
