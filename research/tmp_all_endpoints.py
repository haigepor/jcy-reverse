# -*- coding: utf-8 -*-
"""tmp_all_endpoints.py — 遍历 apipost 录入的全部 35 个接口，真实请求 + 离线解密。"""
import os, sys, json, time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
sys.path.insert(0, os.path.join(ROOT, 'research', 'deliverables'))
sys.path.insert(0, os.path.join(ROOT, 'research', 'captures', 'rsa_scan'))
sys.path.insert(0, os.path.join(ROOT, 'src'))
import jcy_client as J  # noqa

VID = '113354'
DATE = '2026-10-04'
EPS = [
    # (method, path, params)
    ('GET', '/app/config', None),
    ('GET', '/app/channel?top-level=true', None),
    ('GET', '/app/channel/', None),
    ('POST', '/app/config/channel', {}),
    ('POST', '/app/config/video', {}),
    ('GET', '/app/banners/0', None),
    ('GET', '/app/banners/1', None),
    ('GET', '/app/banners/2', None),
    ('GET', '/app/video/list?channel=1&sort=weight&limit=6&page=1', None),
    ('GET', '/app/video/detail?id=' + VID, None),
    ('GET', '/app/video/search?keyword=%E7%81%AB%E5%BD%B1&page=1', None),
    ('GET', '/app/video/key?id=' + VID, None),
    ('GET', '/app/video_update_list/' + DATE, None),
    ('POST', '/app/video/record', {}),
    ('POST', '/app/video/play-connect', {}),
    ('POST', '/app/video/play', {}),
    ('POST', '/app/video/device-base', {}),
    ('GET', '/app/danmu?vid=' + VID + '&play=mp4', None),
    ('GET', '/app/vod_comment/gettop?vid=' + VID, None),
    ('GET', '/app/vod_comment/gethitstop?vid=' + VID, None),
    ('GET', '/app/vod_comment/getlist?vid=' + VID + '&page=1', None),
    ('POST', '/app/users/clearimg', {}),
    ('POST', '/app/users/task', {}),
    ('POST', '/app/history', {}),
    ('POST', '/app/history/localcahce', {}),
    ('GET', '/app/task/sign_rule', None),
    ('POST', '/app/messagebox/give_me', {}),
    ('POST', '/app/messagebox/dynamic', {}),
    ('POST', '/app/upgrade', {}),
    ('GET', '/app/v2/config/host', None),
    ('GET', '/app/users/info', None),
    ('GET', '/app/vip_price/list', None),
    ('POST', '/app/task/task', {}),
    ('GET', '/app/playaddr/v4/client?vid=' + VID, None),
    ('POST', '/app/login/smscode', {}),
]

cli = J.JcyClient()
res_all = {}
for method, path, params in EPS:
    t0 = time.time()
    try:
        r = cli.request(method, path, params, timeout=20)
    except Exception as e:
        res_all[path] = {'method': method, 'error': repr(e)}
        print('[ERR] %-4s %-56s %s' % (method, path, e), flush=True)
        continue
    dt = time.time() - t0
    if r['encrypted']:
        txt = r['plain'].decode('utf-8', 'replace')
        rec = {'method': method, 'http': r['http'], 'k16resp': r['k16resp'],
               'plain_len': len(r['plain']), 'json': r['json'], 'plain': txt, 'secs': round(dt, 1)}
        code = (r['json'] or {}).get('code') if isinstance(r['json'], dict) else None
        print('[OK ] %-4s %-56s %6.1fs %5dB code=%s' % (method, path, dt, len(r['plain']), code), flush=True)
        print('      %s' % txt[:110].replace('\n', ' '), flush=True)
    else:
        rec = {'method': method, 'http': r['http'], 'raw': r['raw'], 'secs': round(dt, 1)}
        print('[RAW] %-4s %-56s %6.1fs %r' % (method, path, dt, r['raw'][:90]), flush=True)
    res_all[path] = rec
    json.dump(res_all, open(os.path.join(HERE, 'tmp_all_endpoints.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
print('DONE total=%d' % len(res_all))
