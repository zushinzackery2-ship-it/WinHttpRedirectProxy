@echo off
set PROJECT_NAME=WinHttpRedirectProxy
set TOOLS_ROOT=%~dp0..
set TARGET_DIR=%~1
set SRC_DIR=%TOOLS_ROOT%\bin\%PROJECT_NAME%

if "%TARGET_DIR%"=="" set TARGET_DIR=F:\Program Files\Endfield Game

if not exist "%TARGET_DIR%" exit /b 1
if not exist "%SRC_DIR%\winhttp.dll" exit /b 2
if not exist "%SRC_DIR%\RuntimeCaptureProbe.dll" exit /b 3
if not exist "%SRC_DIR%\winhttp_original.dll" exit /b 4

copy /Y "%SRC_DIR%\winhttp.dll" "%TARGET_DIR%\winhttp.dll"
if errorlevel 1 exit /b 6

copy /Y "%SRC_DIR%\RuntimeCaptureProbe.dll" "%TARGET_DIR%\RuntimeCaptureProbe.dll"
if errorlevel 1 exit /b 7

copy /Y "%SRC_DIR%\winhttp_original.dll" "%TARGET_DIR%\winhttp_original.dll"
if errorlevel 1 exit /b 8
