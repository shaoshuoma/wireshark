@echo off
echo ============================================
echo Wireshark 二次开发环境设置
echo ============================================

REM 设置MSYS2环境路径
set PATH=C:\msys64\ucrt64\bin;%PATH%

REM 切换到项目根目录
cd /d "D:\mss\wireshark"

echo 项目目录: %CD%
echo.

echo 可用的开发命令：
echo.
echo == 编译相关 ==
echo   重新编译：      cd build-msys2 ^&^& ninja
echo   清理编译：      cd build-msys2 ^&^& ninja clean
echo   重新配置：      cd build-msys2 ^&^& cmake ..
echo.
echo == 代码相关 ==
echo   源代码目录：    %CD%
echo   主要代码：      epan\dissectors\   (协议解析器)
echo   UI代码：        ui\qt\             (Qt界面)
echo   工具代码：      tools\             (开发工具)
echo.
echo == 测试相关 ==
echo   运行测试：      cd build-msys2 ^&^& ctest
echo   启动程序：      cd build-msys2\run ^&^& wireshark.exe
echo.

echo 开发环境已设置完成！
echo 您现在可以开始Wireshark的二次开发。
echo.

REM 启动开发者命令行
cmd /k "echo === Wireshark开发环境 === & echo 当前目录: %CD% & echo 使用 'exit' 退出开发环境" 