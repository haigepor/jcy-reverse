# CMakeLists.txt — 把 JNI 桥编成 libjcy_core.so
#
# libcore.so 不参与编译，仅作为运行时依赖由 dlopen 加载
# （它已在 jniLibs/arm64-v8a 下，会被打进 APK）。

cmake_minimum_required(VERSION 3.22.1)
project(jcy_core C)

add_library(jcy_core SHARED jcy_core_jni.c)

find_library(log-lib log)
find_library(dl-lib dl)

target_link_libraries(jcy_core ${log-lib} ${dl-lib})
