# -*- coding: utf-8 -*-
"""cb_decode.py — 从 emu_unwind_run.log 提取 app_cb 回调串并解信封。"""
import base64
import json
import re

from Crypto.Cipher import AES

log = open('research/captures/rsa_scan/emu_unwind_run.log', encoding='utf-8',
           errors='replace').read()
# 回调串 = b' 开头到 \x00 前（repr 里的 \x00）
i = log.find("[app_cb] x0 dump 4KB: b'")
j = log.find('\\x00', i)
s = log[i + len("[app_cb] x0 dump 4KB: b'"):j]
print('回调串长度:', len(s))

b = base64.b64decode(s + '=' * ((-len(s)) % 4))
print('密文:', len(b), 'B')
KEY = b'qPwClBj7j7ZQraSm'
IV = b'p3JdVQl3q7WQJIgG'
p = AES.new(KEY, AES.MODE_CBC, IV).decrypt(b)
pad = p[-1]
ok = 1 <= pad <= 16 and all(x == pad for x in p[-pad:])
print('PKCS7 pad:', pad, '合法:', ok)
jstr = p[:-pad].decode('utf-8', 'replace') if ok else p.decode('utf-8', 'replace')
print('明文长度:', len(jstr))
try:
    o = json.loads(jstr)
    print(json.dumps(o, ensure_ascii=False, indent=1)[:2000])
except Exception as ex:
    print('非整体 JSON:', ex)
    print(jstr[:1000])
    print('...')
    print(jstr[-300:])
