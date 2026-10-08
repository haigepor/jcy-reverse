# 保留 JNI 桥的原生方法名，避免被混淆
-keepclasseswithmembernames class app.video.guoguo.JcyCore {
    native <methods>;
}
-keep class app.video.guoguo.JcyCorePlugin { *; }
-keep class app.video.guoguo.MainActivity { *; }
