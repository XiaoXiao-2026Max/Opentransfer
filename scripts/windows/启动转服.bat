@echo off
chcp 65001 >nul
setlocal
title 转服服务
pushd "%~dp0"
if errorlevel 1 exit /b 1
"%~dp0connect.exe" %*
set "connectExitCode=%errorlevel%"
echo.
if not "%connectExitCode%"=="0" echo 启动或运行失败，请查看上方错误及“使用说明.txt”。
pause
popd
exit /b %connectExitCode%
