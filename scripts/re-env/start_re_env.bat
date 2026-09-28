@echo off
REM 雷电14 逆向环境一键拉起（frida-server + 端口转发）
setlocal
set LD=C:\leidian\LDPlayer14
set PY=%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe

echo [1/3] 检查模拟器 ...
"%LD%\adb.exe" devices | findstr emulator-5554 || (echo   [!] 模拟器未运行，请先启动雷电模拟器 & exit /b 1)

echo [2/3] 启动 frida-server ...
"%LD%\adb.exe" shell "su -c 'pkill -f frida-server; nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"
timeout /t 4 /nobreak >nul

echo [3/3] 建立端口转发 ...
"%LD%\adb.exe" forward tcp:27042 tcp:27042

"%LD%\adb.exe" shell "su -c 'ps -A -o PID,USER,NAME | grep frida-server'"
echo.
echo 完成。验证： %PY% -c "import frida;d=frida.get_device_manager().add_remote_device('127.0.0.1:27042');print(len(d.enumerate_processes()),'procs')"
endlocal
