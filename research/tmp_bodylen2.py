import json, base64, sys, os, collections
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
from jcy_protocol.auth import ALPHABET, STD_B64
T = str.maketrans(ALPHABET, STD_B64)
rows = [json.loads(l) for l in open(os.path.join(ROOT, "research", "captures",
        "proxy_bodies.jsonl"), encoding="utf-8") if l.strip()]


def dec(s):
    t = s.translate(T)
    t += "=" * (-len(t) % 4)
    return base64.b64decode(t)


agg = collections.defaultdict(collections.Counter)
for d in rows:
    p = d.get("req", "").split(" HTTP")[0]
    parts = p.split(" ")
    m, path = parts[0], parts[-1].split("?")[0]
    b = d.get("req_body_ascii") or ""
    if not b:
        continue
    if "." in b:
        a, _, c = b.partition(".")
        try:
            p1 = dec(c)
            agg[(m, path)]["P0=%dB P1=%dB(%d块)" % (len(dec(a)), len(p1), len(p1) // 16)] += 1
        except Exception:
            agg[(m, path)]["P0/P1解码失败"] += 1
    else:
        try:
            raw = dec(b)
            agg[(m, path)]["单体=%dB mod16=%d" % (len(raw), len(raw) % 16)] += 1
        except Exception:
            agg[(m, path)]["单体解码失败"] += 1
for (m, path), c in sorted(agg.items()):
    print("%-5s %-30s %s" % (m, path, dict(c)))
