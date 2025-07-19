@echo off
echo ============================================
echo 启动自编译的TShark (命令行Wireshark)
echo ============================================

REM 设置MSYS2环境路径
set PATH=C:\msys64\ucrt64\bin;%PATH%

REM 切换到编译的可执行文件目录
cd /d "D:\mss\wireshark\build-msys2\run"

REM 检查tshark.exe是否存在
if not exist "tshark.exe" (
    echo 错误：找不到tshark.exe文件
    echo 请确保编译已成功完成
    pause
    exit /b 1
)

echo TShark已准备就绪！
echo.
echo 常用命令示例：
echo   tshark --version           - 显示版本信息
echo   tshark -D                  - 列出可用网络接口
echo   tshark -i 1 -c 10          - 从接口1捕获10个包
echo   tshark -r sample.pcap      - 读取pcap文件
echo.
echo 可执行文件路径: %CD%\tshark.exe
echo.

REM 启动交互式命令行
cmd /k "echo 您现在可以使用tshark命令。输入 exit 退出。" 