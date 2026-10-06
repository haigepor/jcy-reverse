# -*- coding: utf-8 -*-
"""tmp_g1_step5a.py — 批量收割: 32 键 × preSB0/rk1..rk8/golden1 → gen_rks2.json"""
import sys
import os
import json
import random

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import EDecryptor, ISBOX, xr, T  # noqa: E402
from tmp_g1_step4t import harvest, cols_of, extract_rks  # noqa: E402

out_path = os.path.join(HERE, "reports", "gen_rks2.json")
data = json.load(open(out_path)) if os.path.exists(out_path) else {}

random.seed(20261005)
keys = [bytes(range(0x30, 0x40))]
gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))
keys += [bytes.fromhex(k) for k in gold]
while len(keys) < 32:
    k = bytes(random.randrange(256) for _ in range(16))
    if k not in keys:
        keys.append(k)

for idx, K in enumerate(keys):
    kh = K.hex()
    if kh in data:
        continue
    d = EDecryptor()
    _C, _rk, CONST_, _Cb = d.calibrate(K, 2)   # 2 块 → CONST[0..1]
    golden1 = CONST_[1].hex() if len(CONST_) > 1 else None
    tr = harvest(K, 1)
    cols = cols_of(tr, 0)
    preSB0 = bytes(ISBOX[v] for col in cols[0:4] for v in col).hex()
    rks = extract_rks(tr, 0)
    data[kh] = {"preSB0": preSB0, "golden1": golden1,
                "rks": {str(r): rks[r].hex() for r in sorted(rks)}}
    json.dump(data, open(out_path, "w"), indent=1)
    print("[%d/32] K=%s preSB0=%s rk1=%s"
          % (idx + 1, kh[:8], preSB0[:8], rks[1].hex()), flush=True)

print("完成: %d 键" % len(data))
