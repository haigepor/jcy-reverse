# -*- coding: utf-8 -*-
"""Assemble gadget APK: device_pulled.apk (installed build) + patched classes.dex + libgadget.so + config"""
import zipfile, shutil, sys

SRC = 'out/device_pulled.apk'          # exact installed build (patched classes2.dex)
REBUILT = 'out/gadget_build.apk'       # apktool b output (new classes.dex only)
OUT = 'out/base_gadget_unsigned.apk'

shutil.copy(SRC, OUT)
with zipfile.ZipFile(REBUILT) as zr:
    new_classes = zr.read('classes.dex')
    print('rebuilt classes.dex:', len(new_classes), 'bytes')

with zipfile.ZipFile(OUT, 'a', zipfile.ZIP_DEFLATED) as z:
    # replace classes.dex (zipfile can't replace in place -> rewrite)
    pass

# zipfile cannot replace entries: rebuild manually
with zipfile.ZipFile(SRC) as zi, zipfile.ZipFile(OUT + '.tmp', 'w') as zo:
    for info in zi.infolist():
        if info.filename == 'classes.dex':
            continue
        ni = zipfile.ZipInfo(info.filename, date_time=info.date_time)
        ni.compress_type = info.compress_type
        ni.external_attr = info.external_attr
        ni.create_system = info.create_system
        zo.writestr(ni, zi.read(info.filename))
    # patched classes.dex
    zo.writestr('classes.dex', new_classes)
    # gadget + config
    zo.write('tools/libgadget.so', 'lib/arm64-v8a/libgadget.so')
    cfg = b'{"interaction":{"type":"listen","address":"127.0.0.1","port":27042,"on_load":"resume"}}'
    zo.writestr('lib/arm64-v8a/libgadget.config.so', cfg)
shutil.move(OUT + '.tmp', OUT)
print('wrote', OUT)
with zipfile.ZipFile(OUT) as z:
    names = z.namelist()
    print('entries:', len(names))
    print('has gadget:', 'lib/arm64-v8a/libgadget.so' in names, 'has config:', 'lib/arm64-v8a/libgadget.config.so' in names)
