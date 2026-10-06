// frida_vmplugin_hook.js
// 用法: frida -U -f com.tudou.tool -l frida_vmplugin_hook.js
// 目的: 挂住 Lua -> Flutter 的 MethodChannel, 打印 utils_md5 / utils_timestamp /
//       utils_aes128cbc_{en,de}crypt / httpGet 的全部入出参, 还原签名原文与密钥
Java.perform(function () {
  try {
    var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
    MethodChannel.invokeMethod.overload("java.lang.String", "java.lang.Object").implementation = function (a, b) {
      var s = String(a);
      var want = (s === "httpGet") || (s.indexOf("utils_") === 0) || (s.indexOf("sign") >= 0) || (s.indexOf("aes") >= 0);
      if (want) {
        console.log("\n[vmplugin] " + s);
        try { console.log("  ARGS=" + String(b)); } catch (e) {}
      }
      var r = this.invokeMethod(a, b);
      if (want) {
        console.log("  RET=" + String(r));
      }
      return r;
    };
    console.log("[*] hooked MethodChannel.invokeMethod");
  } catch (e) {
    console.log("hook error: " + e);
  }
});
