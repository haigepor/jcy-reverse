# -*- coding: utf-8 -*-
# Rebuild patched APK with byte-exact original base:
#   final = original base.apk, all entries preserved, except:
#     - classes2.dex  <- patched build (ad-free smali)
#     - META-INF/CERT.RSA, CERT.SF, MANIFEST.MF removed (old v1 signer files)
# uber-apk-signer then re-signs v1+v2+v3.
import zipfile, sys, shutil, os

ORIG = sys.argv[1] if len(sys.argv) > 1 else r'apk\base.apk'
PATCHED_APK = sys.argv[2] if len(sys.argv) > 2 else r'out\base_adfree_final-aligned-debugSigned.apk'
OUT = sys.argv[3] if len(sys.argv) > 3 else r'out\base_adfree_v2_unsigned.apk'

DROP = {'META-INF/CERT.RSA', 'META-INF/CERT.SF', 'META-INF/MANIFEST.MF'}

with zipfile.ZipFile(PATCHED_APK) as zp:
    patched_classes2 = zp.read('classes2.dex')

with zipfile.ZipFile(ORIG) as zi, zipfile.ZipFile(OUT, 'w') as zo:
    kept = swapped = dropped = 0
    for info in zi.infolist():
        name = info.filename
        if name in DROP:
            dropped += 1
            continue
        data = zi.read(name)
        if name == 'classes2.dex':
            data = patched_classes2
            swapped += 1
        ni = zipfile.ZipInfo(name, date_time=info.date_time)
        ni.compress_type = info.compress_type
        ni.external_attr = info.external_attr
        ni.create_system = info.create_system
        zo.writestr(ni, data)
        kept += 1
print(f'kept={kept} swapped_classes2={swapped} dropped_signer={dropped}')
print('OUT=' + os.path.abspath(OUT))
