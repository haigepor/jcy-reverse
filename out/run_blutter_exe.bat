@echo off
set PATH=C:lutter_win;C:lutter_wxternal\capstone;C:lutter_w\dartsdk\src\out\ReleaseARM64;%PATH%
C:lutter_winlutter_dartvm3.6.0_android_arm64.exe -i C:lutter_run\libapp.so -o C:lutter_run\out
echo EXIT=%ERRORLEVEL%
