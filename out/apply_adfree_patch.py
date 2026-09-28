# -*- coding: utf-8 -*-
"""囧次元 base.apk 去广告 + 激励免看 smali 补丁
按 (文件, 方法签名) 定位方法块, 整体替换方法体.
广告链路: Dart -> com.windmill.ad 通道 -> windmill_ad_plugin 五类广告
  - RewardVideoAd.load/isReady/showAd  -> 伪装加载成功并直接发放奖励
  - Splash/Interstitial/Banner/Native  -> 加载即失败, 永不展示
"""
import io
import os
import re
import sys

ROOT = sys.argv[1]
ADPKG = os.path.join(ROOT, "smali_classes2", "com", "windmill", "windmill_ad_plugin")

FAIL_LOAD = """    .locals 4

    # ad-free patch: fail-fast load so the UI never waits on ad network
    const/4 p1, 0x0

    iput-object p1, p0, {SELF}->adInfo:Lcom/windmill/sdk/models/AdInfo;

    iget-object v0, p0, {SELF}->adChannel:Lio/flutter/plugin/common/MethodChannel;

    if-eqz v0, :patched_done

    new-instance v1, Ljava/util/HashMap;

    invoke-direct {{v1}}, Ljava/util/HashMap;-><init>()V

    const/4 v2, -0x1

    invoke-static {{v2}}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    const-string v3, "code"

    invoke-virtual {{v1, v3, v2}}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-string v2, "message"

    const-string v3, "ad disabled"

    invoke-virtual {{v1, v2, v3}}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-string v2, "onAdFailedToLoad"

    invoke-virtual {{v0, v2, v1}}, Lio/flutter/plugin/common/MethodChannel;->invokeMethod(Ljava/lang/String;Ljava/lang/Object;)V

    :patched_done
    return-object p1"""

NOT_READY = """    .locals 1

    # ad-free patch: always report not-ready
    const/4 p1, 0x0

    invoke-static {{p1}}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1"""

ALWAYS_READY = """    .locals 1

    # ad-free patch: always report ready so Dart proceeds instantly
    const/4 p1, 0x1

    invoke-static {{p1}}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1"""

NOOP_OBJ = """    .locals 1

    # ad-free patch: no-op show
    const/4 p1, 0x0

    return-object p1"""

NOOP_VOID = """    .locals 0

    # ad-free patch: no-op show
    return-void"""

REWARD_LOAD = """    .locals 3

    # ad-free patch: fake load success, skip ad network
    const/4 p1, 0x0

    iput-object p1, p0, {SELF}->adInfo:Lcom/windmill/sdk/models/AdInfo;

    iget-object v0, p0, {SELF}->adChannel:Lio/flutter/plugin/common/MethodChannel;

    if-eqz v0, :patched_done

    const-string v1, "onAdLoaded"

    const/4 v2, 0x0

    invoke-virtual {{v0, v1, v2}}, Lio/flutter/plugin/common/MethodChannel;->invokeMethod(Ljava/lang/String;Ljava/lang/Object;)V

    :patched_done
    return-object p1"""

REWARD_SHOW = """    .locals 4

    # ad-free patch: grant reward immediately without playing an ad
    iget-object v0, p0, {SELF}->adChannel:Lio/flutter/plugin/common/MethodChannel;

    if-nez v0, :patched_rew

    const-string v1, "onAdVideoPlayFinished"

    const/4 v2, 0x0

    invoke-virtual {{v0, v1, v2}}, Lio/flutter/plugin/common/MethodChannel;->invokeMethod(Ljava/lang/String;Ljava/lang/Object;)V

    new-instance v1, Ljava/util/HashMap;

    invoke-direct {{v1}}, Ljava/util/HashMap;-><init>()V

    const-string v2, "trans_id"

    const-string v3, "ad_free"

    invoke-virtual {{v1, v2, v3}}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-string v2, "user_id"

    const-string v3, ""

    invoke-virtual {{v1, v2, v3}}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-string v2, "onAdReward"

    invoke-virtual {{v0, v2, v1}}, Lio/flutter/plugin/common/MethodChannel;->invokeMethod(Ljava/lang/String;Ljava/lang/Object;)V

    const-string v1, "onAdClosed"

    const/4 v2, 0x0

    invoke-virtual {{v0, v1, v2}}, Lio/flutter/plugin/common/MethodChannel;->invokeMethod(Ljava/lang/String;Ljava/lang/Object;)V

    :patched_rew
    const/4 p1, 0x0

    return-object p1"""

METHOD_SIG = ".method {vis} {name}(Lio/flutter/plugin/common/MethodCall;)Ljava/lang/Object;"
VOID_SHOW_SIG = ".method public {name}(Landroid/view/ViewGroup;{extra})V"

REWARD = "Lcom/windmill/windmill_ad_plugin/reward/RewardVideoAd;"
SPLASH = "Lcom/windmill/windmill_ad_plugin/splashAd/SplashAd;"
INTER  = "Lcom/windmill/windmill_ad_plugin/interstitial/InterstitialAd;"
BANNER = "Lcom/windmill/windmill_ad_plugin/banner/BannerAd;"
NATIVE = "Lcom/windmill/windmill_ad_plugin/feedAd/NativeAd;"

PATCHES = [
    # (文件相对 ADPKG, 方法行前缀, 新方法体模板, 模板 SELF)
    (os.path.join("reward", "RewardVideoAd.smali"),
     METHOD_SIG.format(vis="public", name="load"), REWARD_LOAD, REWARD),
    (os.path.join("reward", "RewardVideoAd.smali"),
     METHOD_SIG.format(vis="public", name="isReady"), ALWAYS_READY, REWARD),
    (os.path.join("reward", "RewardVideoAd.smali"),
     METHOD_SIG.format(vis="private", name="showAd"), REWARD_SHOW, REWARD),

    (os.path.join("splashAd", "SplashAd.smali"),
     METHOD_SIG.format(vis="public", name="load"), FAIL_LOAD, SPLASH),
    (os.path.join("splashAd", "SplashAd.smali"),
     METHOD_SIG.format(vis="public", name="isReady"), NOT_READY, SPLASH),
    (os.path.join("splashAd", "SplashAd.smali"),
     METHOD_SIG.format(vis="public", name="showAd"), NOOP_OBJ, SPLASH),

    (os.path.join("interstitial", "InterstitialAd.smali"),
     METHOD_SIG.format(vis="public", name="load"), FAIL_LOAD, INTER),
    (os.path.join("interstitial", "InterstitialAd.smali"),
     METHOD_SIG.format(vis="public", name="isReady"), NOT_READY, INTER),
    (os.path.join("interstitial", "InterstitialAd.smali"),
     METHOD_SIG.format(vis="private", name="showAd"), NOOP_OBJ, INTER),

    (os.path.join("banner", "BannerAd.smali"),
     METHOD_SIG.format(vis="public", name="load"), FAIL_LOAD, BANNER),
    (os.path.join("banner", "BannerAd.smali"),
     METHOD_SIG.format(vis="public", name="isReady"), NOT_READY, BANNER),
    (os.path.join("banner", "BannerAd.smali"),
     VOID_SHOW_SIG.format(name="showAd", extra=""), NOOP_VOID, BANNER),

    (os.path.join("feedAd", "NativeAd.smali"),
     METHOD_SIG.format(vis="public", name="load"), FAIL_LOAD, NATIVE),
    (os.path.join("feedAd", "NativeAd.smali"),
     METHOD_SIG.format(vis="public", name="isReady"), NOT_READY, NATIVE),
    (os.path.join("feedAd", "NativeAd.smali"),
     VOID_SHOW_SIG.format(name="showAd", extra="Lorg/json/JSONObject;"), NOOP_VOID, NATIVE),
]

ok = True
for rel, sig, body_tpl, self_cls in PATCHES:
    path = os.path.join(ADPKG, rel)
    with io.open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    body = body_tpl.format(SELF=self_cls)
    pattern = re.compile(
        re.escape(sig) + r"\n.*?\n\.end method", re.DOTALL)
    new_block = sig + "\n" + body + "\n.end method"
    new_text, n = pattern.subn(lambda m: new_block, text, count=1)
    if n != 1:
        print("[FAIL] not found:", rel, sig)
        ok = False
        continue
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(new_text)
    print("[ OK ]", rel, "->", sig.split()[-1].split("(")[0])

if not ok:
    sys.exit(1)
print("ALL PATCHES APPLIED:", len(PATCHES))
