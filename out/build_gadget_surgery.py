# -*- coding: utf-8 -*-
"""Combo APK: pristine base.apk entries + reFlutter patched libflutter.so
+ gadget-loader classes.dex + libgadget.so + config. Single install, both capabilities."""
import zipfile

SRC = 'apk/base.apk'                                # pristine entries
RE = 'reflutter_work/release.RE.apk'                # reFlutter patched engine
GADGET = 'out/gadget_build.apk'                     # patched classes.dex (gadget loader)
OUT = 'reflutter_work/combo.RE-gadget.apk'

with zipfile.ZipFile(RE) as z:
    flutter_so = z.read('lib/arm64-v8a/libflutter.so')
with zipfile.ZipFile(GADGET) as z:
    classes_dex = z.read('classes.dex')

with zipfile.ZipFile(SRC) as zi, zipfile.ZipFile(OUT + '.tmp', 'w') as zo:
    for info in zi.infolist():
        ni = zipfile.ZipInfo(info.filename, date_time=info.date_time)
        ni.compress_type = info.compress_type
        ni.external_attr = info.external_attr
        ni.create_system = info.create_system
        if info.filename == 'lib/arm64-v8a/libflutter.so':
            zo.writestr(ni, flutter_so)
        elif info.filename == 'classes.dex':
            zo.writestr(ni, classes_dex)
        else:
            zo.writestr(ni, zi.read(info.filename))
    zo.write('tools/libgadget.so', 'lib/arm64-v8a/libgadget.so')
    cfg = b'{"interaction":{"type":"listen","address":"127.0.0.1","port":27042,"on_load":"resume"}}'
    zo.writestr('lib/arm64-v8a/libgadget.config.so', cfg)
shutil_move_done = None
import shutil
shutil.move(OUT + '.tmp', OUT)

with zipfile.ZipFile(OUT) as z:
    names = z.namelist()
    print('wrote', OUT, 'entries:', len(names))
    print('flutter:', z.getinfo('lib/arm64-v8a/libflutter.so').file_size)
    print('dex:', z.getinfo('classes.dex').file_size)
    print('gadget:', 'lib/arm64-v8a/libgadget.so' in names)
