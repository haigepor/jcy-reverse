// out/dartscan.js — scan rw memory for AES key schedules (AES-128/256) + plaintext needles
(function () {
  var SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];
  var RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

  function subword(w) {
    return (SBOX[(w >>> 24) & 0xff] << 24) | (SBOX[(w >>> 16) & 0xff] << 16) |
           (SBOX[(w >>> 8) & 0xff] << 8) | SBOX[w & 0xff];
  }
  function rotword(w) { return ((w << 8) | (w >>> 24)) >>> 0; }

  // verify AES-128 expansion: words[0..43]
  function check128(w) {
    for (var i = 4; i < 44; i++) {
      var t = w[i - 1];
      if ((i & 3) === 0) t = (subword(rotword(t)) ^ (RCON[(i >> 2) - 1] << 24)) >>> 0;
      if (((w[i - 4] ^ t) >>> 0) !== (w[i] >>> 0)) return false;
    }
    return true;
  }
  // verify AES-256 expansion: words[0..59]
  function check256(w) {
    for (var i = 8; i < 60; i++) {
      var t = w[i - 1];
      if ((i & 7) === 0) t = (subword(rotword(t)) ^ (RCON[(i >> 3) - 1] << 24)) >>> 0;
      else if ((i & 7) === 4) t = subword(t);
      if (((w[i - 8] ^ t) >>> 0) !== (w[i] >>> 0)) return false;
    }
    return true;
  }

  function w2hex(w, n) {
    var s = '';
    for (var i = 0; i < n; i++) {
      s += ('00000000' + (w[i] >>> 0).toString(16)).slice(-8);
    }
    return s;
  }

  var NEEDLES = [
    ['appid', '4150439554430529'],
    ['authb64', '6MsfEg71'],
    ['xver', '2020-09-17']
  ];

  var ranges = [];
  Process.enumerateRanges('rw-').forEach(function (r) {
    if (r.size >= 4096 && r.size < 1200 * 1024 * 1024) ranges.push(r);
  });
  send({ t: 'RANGES', n: ranges.length, total: ranges.reduce(function (a, r) { return a + r.size; }, 0) });

  function bufIndexOf(buf, s, from) {
    var b = [];
    for (var i = 0; i < s.length; i++) b.push(s.charCodeAt(i));
    var first = b[0];
    var limit = buf.length - b.length;
    for (var i = from; i <= limit; i++) {
      if (buf[i] !== first) continue;
      var ok = true;
      for (var j = 1; j < b.length; j++) { if (buf[i + j] !== b[j]) { ok = false; break; } }
      if (ok) return i;
    }
    return -1;
  }

  var CH = 1024 * 1024;
  var hits = 0;
  function scanRange(ri) {
    if (ri >= ranges.length) { send({ t: 'DONE' }); return; }
    var r = ranges[ri];
    var off = 0;
    function chunk() {
      var t0 = Date.now();
      while (off < r.size && Date.now() - t0 < 200) {
        var n = Math.min(CH, r.size - off);
        var buf = null;
        try { buf = new Uint8Array(r.base.add(off).readByteArray(n)); } catch (e) { off += n; continue; }
        var dv = new DataView(buf.buffer);
        // needles
        for (var ni = 0; ni < NEEDLES.length; ni++) {
          var needle = NEEDLES[ni][1];
          var idx = 0;
          while (true) {
            idx = bufIndexOf(buf, needle, idx);
            if (idx < 0) break;
            send({ t: 'NEEDLE', which: NEEDLES[ni][0], addr: r.base.add(off + idx).toString() });
            idx += 1;
            if (++hits > 400) break;
          }
        }
        // raw stride-4 AES-128
        var lim = n - 176;
        for (var o = 0; o <= lim; o += 4) {
          var w0 = dv.getUint32(o, false), w3 = dv.getUint32(o + 12, false), w4 = dv.getUint32(o + 16, false);
          var tt = (subword(rotword(w3)) ^ 0x01000000) >>> 0;
          if (((w0 ^ tt) >>> 0) === w4) {
            var w = [];
            for (var i = 0; i < 44; i++) w.push(dv.getUint32(o + 4 * i, false));
            if (check128(w)) send({ t: 'KS128_RAW4', addr: r.base.add(off + o).toString(), key: w2hex(w, 4) });
          }
        }
        // AES-256 raw stride-4
        lim = n - 240;
        for (var o = 0; o <= lim; o += 4) {
          var w0 = dv.getUint32(o, false), w4 = dv.getUint32(o + 16, false);
          var w7 = dv.getUint32(o + 28, false), w8 = dv.getUint32(o + 32, false);
          var tt = (subword(rotword(w7)) ^ 0x01000000) >>> 0;
          if (((w0 ^ tt) >>> 0) !== w8) continue;
          var w11 = dv.getUint32(o + 44, false), w12 = dv.getUint32(o + 48, false);
          if ((w4 ^ (subword(w11) >>> 0)) !== w12) continue;
          var w = [];
          for (var i = 0; i < 60; i++) w.push(dv.getUint32(o + 4 * i, false));
          if (check256(w)) send({ t: 'KS256_RAW4', addr: r.base.add(off + o).toString(), key: w2hex(w, 8) });
        }
        off += n;
      }
      if (off < r.size) {
        setTimeout(chunk, 0);
      } else {
        if ((ri & 63) === 0) send({ t: 'PROG', ri: ri, total: ranges.length });
        setTimeout(function () { scanRange(ri + 1); }, 0);
      }
    }
    chunk();
  }
  setTimeout(function () { scanRange(0); }, 0);
})();
