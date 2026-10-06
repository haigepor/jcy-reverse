import json, base64, sys, os, collections
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
from jcy_protocol.auth import ALPHABET, STD_B64
T = str.maketrans(ALPHABET, STD_B64)
rows = [json.loads(l) for l in open(os.path.join(ROOT, "research", "captures",
        "proxy_bodies.jsonl"), encoding="utf-8") if l.strip()]
agg = collections.defaultdict(collections.Counter)
for d in rows:
    p = d.get("req", "").split(" HTTP")[0]
    parts = p.split(" ")
    m, path = parts[0], parts[-1].split("?")[0]
    b = d.get("req_body_ascii") or ""
    if not b:
        continue
    best = None
    for tr in (None, T):
        t = b if tr is None else b.translate(tr)
        t += "=" * (-len(t) % 4)
        try:
            raw = base64.b64decode(t)
            if best is None or len(raw) % 16 == 0:
                best = raw
        except Exception:
            pass
    agg[(m, path)][len(best) if best else -1] += 1
for (m, path), c in sorted(agg.items()):
    dist = {}
    for k, v in c.items():
        dist[("%d块(%dB)" % (k // 16, k)) if k > 0 else str(k)] = v
    print("%-5s %-30s %s" % (m, path, dist))
