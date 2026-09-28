@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\VSBuildTools2022\VC\Auxiliary\Build\vcvarsall.bat" x64
set PATH=%CD%\tools\blutter\bin;%PATH%
python tools\blutter\blutter.py out\blutter_lib out\blutter_out
echo EXITCODE=%ERRORLEVEL%
