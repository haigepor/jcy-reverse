// out/evp_hook.js — frida17-safe EVP/AES hooks, both directions, with onLeave output capture
(function () {
  var SYMS = ['EVP_EncryptInit_ex', 'EVP_DecryptInit_ex',
              'EVP_EncryptUpdate', 'EVP_DecryptUpdate', 'EVP_EncryptFinal_ex', 'EVP_DecryptFinal_ex',
              'AES_set_encrypt_key', 'AES_set_decrypt_key', 'AES_cbc_encrypt'];

  var core = null, klenFn = null;
  Process.enumerateModules().forEach(function (m) { if (m.name === 'libcore.so') core = m; });
  if (core) {
    try {
      var klen = core.findExportByName('EVP_CIPHER_key_length');
      if (klen) klenFn = new NativeFunction(klen, 'int', ['pointer']);
    } catch (e) {}
  }

  function hx(p, n) {
    try {
      var b = new Uint8Array(p.readByteArray(n));
      var s = '';
      for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
      return s;
    } catch (e) { return null; }
  }
  function hstr(p, n) {
    try {
      var b = new Uint8Array(p.readByteArray(n));
      var s = '';
      for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
      return s;
    } catch (e) { return null; }
  }

  var mods = Process.enumerateModules();
  var hooked = 0;
  mods.forEach(function (m) {
    SYMS.forEach(function (sym) {
      var addr = null;
      try { addr = m.findExportByName(sym); } catch (e) {}
      if (!addr) return;
      try {
        Interceptor.attach(addr, (function (symName, modName) {
          return {
            onEnter: function (args) {
              var line = { t: symName, mod: modName, tid: this.threadId };
              try {
                if (symName.indexOf('Init') >= 0) {
                  var kl = null;
                  if (klenFn && !args[1].isNull()) { try { kl = klenFn(args[1]); } catch (e) {} }
                  line.keylen = kl;
                  line.key = args[3].isNull() ? null : hx(args[3], kl || 32);
                  line.iv = args[4].isNull() ? null : hx(args[4], 16);
                  line.ctx = args[0].toString();
                } else if (symName.indexOf('Update') >= 0) {
                  var inl = args[4].toInt32();
                  line.inl = inl;
                  line.ctx = args[0].toString();
                  if (inl > 0 && inl < 65536) {
                    line.hex = hx(args[3], Math.min(inl, 2048));
                    if (inl <= 1024) line.str = hstr(args[3], inl);
                  }
                  // capture output after the call
                  this._out = args[1];
                  this._outl = args[2];
                  this._isDec = symName.indexOf('Dec') >= 0;
                } else if (symName === 'AES_set_encrypt_key' || symName === 'AES_set_decrypt_key') {
                  line.bits = args[1].toInt32();
                  line.key = hx(args[0], 32);
                } else if (symName === 'AES_cbc_encrypt') {
                  var len = args[2].toInt32();
                  line.len = len; line.enc = args[5].toInt32();
                  line.iv = hx(args[4], 16);
                  if (len > 0 && len < 65536) line.hex = hx(args[0], Math.min(len, 2048));
                }
              } catch (e) { line.err = '' + e; }
              this._line = line;
              send(line);
            },
            onLeave: function (rv) {
              try {
                if (this._out && this._outl) {
                  var n = this._outl.readU32 ? this._outl.readU32() : this._outl.readUInt();
                  if (n > 0 && n < 65536) {
                    var out = { t: this._isDec ? 'DecOut' : 'EncOut', ctx: this._line ? this._line.ctx : null, outl: n };
                    out.str = hstr(this._out, Math.min(n, 2048));
                    out.hex = hx(this._out, Math.min(n, 2048));
                    send(out);
                  }
                }
              } catch (e) {}
            }
          };
        })(sym, m.name));
        hooked++;
      } catch (e) {}
    });
  });
  send({ t: 'INFO', msg: 'modules: ' + mods.length + ' hooks: ' + hooked + ' core: ' + (core ? '' + core.base : 'none') });
})();
