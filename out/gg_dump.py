# out/gg_dump.py — stream memory ranges from device to host file via frida
import frida, sys, time, json

JS = r'''
(function(){
  function dumpRange(baseStr, size, tag) {
    var CH = 512 * 1024;
    var base = ptr(baseStr);
    var off = 0;
    function chunk() {
      var t0 = Date.now();
      while (off < size && Date.now() - t0 < 150) {
        var n = Math.min(CH, size - off);
        var buf = null;
        try { buf = base.add(off).readByteArray(n); } catch (e) { send({t:'ERR', tag:tag, off:off, n:n, e:''+e}); off += n; continue; }
        send({t:'CHUNK', tag:tag, off:off, n:n}, buf);
        off += n;
      }
      if (off < size) { setTimeout(chunk, 0); }
      else { send({t:'DONE', tag:tag, size:size}); }
    }
    chunk();
  }
  recv('DUMP', function (m) {
    dumpRange(m.base, m.size, m.tag);
  });
})();
'''

def dump(sections, outfile):
    # pre-assign file offsets
    fbase = {}
    cur = 0
    for base, size, tag in sections:
        fbase[tag] = cur
        cur += size
    outf = open(outfile, 'wb')
    outf.truncate(cur)
    pending = {s[2] for s in sections}
    done_at = {}

    def on_msg(msg, data):
        if msg['type'] != 'send':
            print('[ERR]', msg.get('description')); return
        r = msg['payload']
        t = r.get('t')
        if t == 'CHUNK':
            tag = r['tag']; off = r['off']
            outf.seek(fbase[tag] + off)
            outf.write(data)
        elif t == 'ERR':
            print('[skip]', r['tag'], hex(r['off']), r['e'])
        elif t == 'DONE':
            print('[done]', r['tag'], r['size'])
            pending.discard(r['tag'])

    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    session = dev.attach('Gadget')
    script = session.create_script(JS)
    script.on('message', on_msg)
    script.load()

    t0 = time.time()
    total = 0
    for base, size, tag in sections:
        script.post({'type': 'DUMP', 'base': base, 'size': size, 'tag': tag})
        total += size
        time.sleep(0.5)
    while pending and time.time() - t0 < 900:
        time.sleep(2)
    elapsed = time.time() - t0
    outf.close()
    print('[*] dumped %d bytes in %.1fs (%.1f MB/s)' % (total, elapsed, total / 1024 / 1024 / max(elapsed, 0.1)))
    json.dump([{'tag': t, 'base': b, 'size': s, 'file_off': fbase[t]} for b, s, t in sections],
              open(outfile + '.idx', 'w'))

if __name__ == '__main__':
    MB = 1024 * 1024
    sections = [
        ('0x7100000000', 21 * MB, 'dart_7100'),
        ('0x722de00000', 56 * MB, 'anon_722de'),
        ('0x7232e01000', 19 * MB, 'anon_7232e'),
        ('0x72e3eac000', 11 * MB, 'anon_72e3e'),
        ('0x7232400000', 10 * MB, 'anon_72324'),
        ('0x72351ba000', 9 * MB, 'anon_72351'),
        ('0x17f00000', 44302336, 'javah_17f0'),
        ('0x1a980000', 2 * MB, 'javah_1a98'),
    ]
    dump(sections, 'out/mem_dump.bin')
