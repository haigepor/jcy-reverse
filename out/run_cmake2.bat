@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\VSBuildTools2022\VC\Auxiliary\Build\vcvarsall.bat" x64
set PATH=C:\blutter_w\bin;%PATH%
cd C:\blutter_w\blutter
cmake -GNinja -B C:\blutter_w\build\blutter_dartvm3.6.0_android_arm64 -DDARTLIB=dartvm3.6.0_android_arm64 -DNAME_SUFFIX= -DCMAKE_BUILD_TYPE=Release --log-level=NOTICE -DHAS_RECORD_TYPE=1 -DNO_METHOD_EXTRACTOR_STUB=1 -DUNIFORM_INTEGER_ACCESS=1
echo CMAKE_EXIT=%ERRORLEVEL%
