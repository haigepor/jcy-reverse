// out/liveneedle.js — fast needle scan over Dart/Java/anon heap regions, repeated
(function () {
  var NEEDLES = [
    ['tsjson', '{"ts":"'],
    ['authb64', '6MsfEg71'],
    ['epoch', '17905'],
    ['magic', '\u00e8\u00cb\u001f\u0012\u000e\u00f5\u00a4,\u0059\u00e2*'].length === 15 ? null : null
  ].filter(function (x) { return x; });
  var MAGIC = [0xe8,0xcb,0x1f,0x12,0x0e,0xf5,0xa4,0x2c,0x59,0xe2,0x2a,0x4d,0x00,0x27,0x9e];

  function findMagic(buf) {
    var res = [];
    var lim = buf.length - 15;
    for (var i = 0; i <= lim; i++) {
      if (buf[i] === 0xe8 && buf[i+1] === 0xcb && buf[i+2] === 0x1f && buf[i+3] === 0x12) {
        var ok = true;
        for (var j = 4; j < 15; j++) { if (buf[i+j] !== MAGIC[j]) { ok = false; break; } }
        if (ok) res.push(i);
      }
    }
    return res;
  }
  function bufIndexOf(buf, s, from) {
    var first = s.charCodeAt(0);
    var limit = buf.length - s.length;
    for (var i = from; i <= limit; i++) {
      if (buf[i] !== first) continue;
      var ok = true;
      for (var j = 1; j < s.length; j++) { if (buf[i + j] !== s.charCodeAt(j)) { ok = false; break; } }
      if (ok) return i;
    }
    return -1;
  }

  function scanOnce(round) {
    var ranges = [];
    Process.enumerateRanges('rw-').forEach(function (r) {
      // only Dart heap (0x7100000000 4GB-aligned compressed heap) + mid anon + java main spaces
      var b = r.base.toString(16);
      if (r.size < 1024 * 1024) return;
      if (r.size > 100 * 1024 * 1024) return;
      var isDart = b.indexOf('7100000000') === 0;
      var isJava = r.file && r.file.path && r.file.path.indexOf('dalvik-main') >= 0;
      var isAnon = !r.file;
      if (isDart || isJava || isAnon) ranges.push(r);
    });
    var found = 0;
    ranges.forEach(function (r) {
      var buf = null;
      try { buf = new Uint8Array(r.base.readByteArray(r.size)); } catch (e) { return; }
      NEEDLES.forEach(function (nd) {
        var idx = 0;
        while (true) {
          idx = bufIndexOf(buf, nd[1], idx);
          if (idx < 0) break;
          var ctx = '';
          var lo = Math.max(0, idx - 24), hi = Math.min(buf.length, idx + 160);
          for (var i = lo; i < hi; i++) {
            var c = buf[i];
            ctx += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
          }
          send({ t: 'N', which: nd[0], round: round, addr: r.base.add(idx).toString(), ctx: ctx });
          found++;
          idx += 1;
          if (found > 300) return;
        }
      });
      // magic binary
      var mres = findMagic(buf);
      mres.forEach(function (i) {
        var hexs = '';
        for (var j = 0; j < Math.min(112, buf.length - i); j++) {
          hexs += ('0' + buf[i + j].toString(16)).slice(-2);
        }
        send({ t: 'MAGIC', round: round, addr: r.base.add(i).toString(), hex: hexs });
        found++;
      });
    });
    send({ t: 'ROUND_DONE', round: round, found: found, ranges: ranges.length });
  }

  var round = 0;
  function loop() {
    try { scanOnce(round); } catch (e) { send({ t: 'ERR', e: '' + e }); }
    round++;
    if (round < 40) setTimeout(loop, 1200);
    else send({ t: 'ALL_DONE' });
  }
  setTimeout(loop, 0);
})();
