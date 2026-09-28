# -*- coding: utf-8 -*-
"""Reassemble pcap TCP streams via tshark follow,raw; parse HTTP messages; split dot-bodies."""
import subprocess, re, base64, json, os, sys

PCAP = 'out/ggcap.pcap'

def follow_raw(stream):
    r = subprocess.run(['tshark', '-q', '-r', PCAP, '-z', f'follow,tcp,raw,{stream}'],
                       capture_output=True, text=True)
    out = r.stdout
    cur = None
    blocks = {'c': [], 's': []}
    for l in out.splitlines():
        ls = l.strip()
        if ls.startswith('Node 0:'): pass
        if ls.startswith('From client') or ls.startswith('Node 0'): pass
        # tshark follow,raw: client lines unindented, server lines indented with tab
        if re.fullmatch(r'[0-9a-f]{2,}', ls):
            blocks['c' if not l.startswith('\t') else 's'].append(ls)
    return bytes.fromhex(''.join(blocks['c'])), bytes.fromhex(''.join(blocks['s']))

def parse_http(data, direction):
    """yield (headers_dict, body_bytes) for each HTTP message"""
    msgs = []
    off = 0
    while off < len(data):
        hend = data.find(b'\r\n\r\n', off)
        if hend < 0: break
        head = data[off:hend].decode('ascii', 'replace')
        lines = head.split('\r\n')
        try:
            hdrs = {}
            for ln in lines[1:]:
                if ':' in ln:
                    k, v = ln.split(':', 1)
                    hdrs[k.strip().lower()] = v.strip()
        except Exception:
            break
        p = hend + 4
        if 'content-length' in hdrs:
            n = int(hdrs['content-length'])
            body = data[p:p+n]
            off = p + n
        elif hdrs.get('transfer-encoding', '').lower() == 'chunked':
            body = b''
            q = p
            while q < len(data):
                e = data.find(b'\r\n', q)
                if e < 0: break
                try: sz = int(data[q:e].split(b';')[0], 16)
                except Exception: break
                if sz == 0:
                    q = e + 4; break
                body += data[e+2:e+2+sz]
                q = e + 2 + sz + 2
            off = q
        else:
            body = b''
            off = p
        msgs.append((lines[0], hdrs, body))
    return msgs

def b64d(s):
    s = re.sub(r'[^A-Za-z0-9+/=]', '', s)
    s = s.rstrip('=')
    pad = (-len(s)) % 4
    try:
        return base64.b64decode(s + '=' * pad)
    except Exception:
        return None

def analyze(stream, label):
    c, s = follow_raw(stream)
    print(f"===== stream {stream} ({label}) client={len(c)}B server={len(s)}B =====")
    for msg in parse_http(c, 'req'):
        start, hdrs, body = msg
        print(f"[REQ] {start[:60]}")
        for k in ('ts', 'nonce', 'appid', 'authentication', 'content-type'):
            if k in hdrs: print(f"    {k}: {hdrs[k][:60]}")
        if body:
            parts = body.split(b'.')
            print(f"    body {len(body)}B -> parts: {[len(p) for p in parts]}")
            for i, p in enumerate(parts):
                d = b64d(p.decode('ascii', 'replace'))
                if d is not None:
                    print(f"      part{i}: b64 {len(p)} -> {len(d)}B mod16={len(d)%16}")
                    open(f'out/flows/s{stream}_req_p{i}.bin', 'wb').write(d)
                else:
                    print(f"      part{i}: b64 decode FAIL: {p[:40]}")
    for msg in parse_http(s, 'resp'):
        start, hdrs, body = msg
        if not body: continue
        print(f"[RESP] {start[:40]} len={len(body)}")
        parts = body.split(b'.')
        print(f"    parts: {[len(p) for p in parts]}")
        for i, p in enumerate(parts):
            d = b64d(p.decode('ascii', 'replace'))
            if d is not None:
                print(f"      part{i}: b64 {len(p)} -> {len(d)}B mod16={len(d)%16}")
                open(f'out/flows/s{stream}_resp_p{i}.bin', 'wb').write(d)

if __name__ == '__main__':
    for stream, label in [(4, 'config/host'), (16, 'config+record'), (10, 'users/task'),
                          (18, 'video/detail'), (24, 'play-connect'), (25, 'video/play')]:
        try:
            analyze(stream, label)
        except Exception as e:
            print(f"stream {stream}: {e}")
