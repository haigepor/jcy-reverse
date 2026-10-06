# -*- coding: utf-8 -*-
"""tmp_batch.py — 批量拉真实端点并离线解密, 结果落盘。"""
import os, sys, json, time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
sys.path.insert(0, os.path.join(ROOT, 'research', 'deliverables'))
sys.path.insert(0, os.path.join(ROOT, 'research', 'captures', 'rsa_scan'))
sys.path.insert(0, os.path.join(ROOT, 'src'))
import jcy_client as J  # noqa

EPS = [
    ('GET', '/app/task/sign_rule'),
    ('GET', '/app/video/detail?id=113354'),
    ('GET', '/app/config'),
    ('GET', '/app/banners/0'),
    ('GET', '/app/channel?top-level=true'),
    ('GET', '/app/video/list?channel=1&sort=weight&limit=6&page=1'),
    ('GET', '/app/video_update_list/2026-10-04'),
    ('POST', '/app/video/device-base'),
]

cli = J.JcyClient()
out = {}
for method, path in EPS:
    t0 = time.time()
    try:
        res = cli.request(method, path, {})
    except Exception as e:
        print('[ERR] %s %s -> %r' % (method, path, e)); continue
    if res['encrypted']:
        txt = res['plain'].decode('utf-8', 'replace')
        out[path] = {'method': method, 'http': res['http'], 'k16resp': res['k16resp'],
                     'plain_len': len(res['plain']), 'json': res['json'], 'plain': txt}
        print('[OK ] %-4s %-52s %6.1fs K16resp=%s %dB json=%s' % (
            method, path, time.time() - t0, res['k16resp'], len(res['plain']),
            res['json'] is not None))
        print('      %s' % txt[:120].replace('\n', ' '))
    else:
        out[path] = {'method': method, 'http': res['http'], 'raw': res['raw']}
        print('[RAW] %-4s %-52s %6.1fs %r' % (method, path, time.time() - t0, res['raw'][:90]))
    json.dump(out, open(os.path.join(HERE, 'tmp_batch_out.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
print('done')
