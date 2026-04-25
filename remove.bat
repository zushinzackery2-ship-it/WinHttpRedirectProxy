@echo off
set TARGET_DIR=%~1

if "%TARGET_DIR%"=="" set TARGET_DIR=F:\Program Files\Endfield Game

if not exist "%TARGET_DIR%" exit /b 1

if exist "%TARGET_DIR%\winhttp.dll" del /F /Q "%TARGET_DIR%\winhttp.dll"
if exist "%TARGET_DIR%\winhttp_original.dll" del /F /Q "%TARGET_DIR%\winhttp_original.dll"
