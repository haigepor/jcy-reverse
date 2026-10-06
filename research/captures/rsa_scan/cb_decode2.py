# -*- coding: utf-8 -*-
# 从 emu 日志提取 app_cb x0 字符串并解码信封
import re, sys, base64
from Crypto.Cipher import AES

log = open(sys.argv[1] if len(sys.argv) > 1 else
           'research/captures/rsa_scan/emu_enc_dk2.log',
           encoding='utf-8', errors='replace').read()
m = re.search(r"\[app_cb\] x0 dump 4KB: b'(.{20,8000}?)\\x00", log, re.S)
s = m.group(1)
# python repr 里的转义还原
s = s.encode().decode('unicode_escape')
print('cb 串 len:', len(s), 'head:', s[:60])
r = base64.b64decode(s + '=' * (-len(s) % 4))
d = AES.new(b'qPwClBj7j7ZQraSm', AES.MODE_CBC, b'p3JdVQl3q7WQJIgG').decrypt(r[:len(r) // 16 * 16])
print('解封:', repr(d[:800]))
