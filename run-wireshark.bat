@echo off
echo ============================================
echo 启动自编译的Wireshark
echo ============================================

REM 设置MSYS2环境路径
set PATH=C:\msys64\ucrt64\bin;%PATH%

REM 切换到编译的可执行文件目录
cd /d "D:\mss\wireshark\build-msys2\run"

REM 检查Wireshark.exe是否存在
if not exist "wireshark.exe" (
    echo 错误：找不到wireshark.exe文件
    echo 请确保编译已成功完成
    pause
    exit /b 1
)

echo 正在启动Wireshark...
echo.
echo 可执行文件路径: %CD%\wireshark.exe
echo.

REM 启动Wireshark
start "Wireshark" wireshark.exe

echo Wireshark已启动！
echo 您可以关闭此窗口。
timeout /t 3 >nul 