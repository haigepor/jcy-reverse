# -*- coding: utf-8 -*-
# Minimal DEX class-list parser: compare class sets between two dex files.
import struct, sys, zipfile, io


def _uleb(buf, off):
    result = 0
    shift = 0
    while True:
        b = buf[off]
        result |= (b & 0x7F) << shift
        off += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, off


def parse_dex(data):
    if data[0:4] != b'dex\n':
        raise ValueError('not a dex')
    string_ids_size, string_ids_off = struct.unpack_from('<II', data, 0x38)
    type_ids_size, type_ids_off = struct.unpack_from('<II', data, 0x40)
    class_defs_size, class_defs_off = struct.unpack_from('<II', data, 0x60)
    strings = []
    for i in range(string_ids_size):
        (off,) = struct.unpack_from('<I', data, string_ids_off + i * 4)
        _, off = _uleb(data, off)
        end = data.index(b'\x00', off)
        strings.append(data[off:end].decode('utf-8', 'replace'))
    types = []
    for i in range(type_ids_size):
        (idx,) = struct.unpack_from('<I', data, type_ids_off + i * 4)
        types.append(strings[idx])
    classes = set()
    for i in range(class_defs_size):
        (cidx,) = struct.unpack_from('<I', data, class_defs_off + i * 32)
        classes.add(types[cidx])
    return classes


def dex_from_apk(apk_path, name):
    with zipfile.ZipFile(apk_path) as z:
        return parse_dex(z.read(name))


def main():
    orig_apk, new_apk, dexname = sys.argv[1], sys.argv[2], sys.argv[3]
    a = dex_from_apk(orig_apk, dexname)
    b = dex_from_apk(new_apk, dexname)
    print(f'ORIG {dexname} classes: {len(a)}')
    print(f'NEW  {dexname} classes: {len(b)}')
    missing = sorted(a - b)
    added = sorted(b - a)
    print(f'--- MISSING in NEW ({len(missing)}):')
    for c in missing:
        print('  - ' + c)
    print(f'--- ADDED in NEW ({len(added)}):')
    for c in added:
        print('  + ' + c)


if __name__ == '__main__':
    main()
