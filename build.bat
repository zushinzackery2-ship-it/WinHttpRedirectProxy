@echo off
call "D:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64

set PROJECT_NAME=WinHttpRedirectProxy
set TOOLS_ROOT=%~dp0..
set WORKSPACE_ROOT=%TOOLS_ROOT%\..
set SRC=%TOOLS_ROOT%\%PROJECT_NAME%
set OBJ=%TOOLS_ROOT%\obj\%PROJECT_NAME%
set BIN=%TOOLS_ROOT%\bin\%PROJECT_NAME%
set PROBE_DLL=%WORKSPACE_ROOT%\bin\RuntimeCapture\RuntimeCaptureProbe.dll
set SYSTEM_WINHTTP=%SystemRoot%\System32\winhttp.dll

if not exist "%OBJ%" mkdir "%OBJ%"
if not exist "%BIN%" mkdir "%BIN%"

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\pch.obj" ^
    /Fp"%OBJ%\winhttp_redirect_proxy.pch" ^
    /Yc"pch.h" ^
    /c "%SRC%\pch.cpp"
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\dllmain.obj" ^
    /Fp"%OBJ%\winhttp_redirect_proxy.pch" ^
    /Yu"pch.h" ^
    /c "%SRC%\dllmain.cpp"
if errorlevel 1 exit /b 1

link /nologo /DLL /MACHINE:X64 /OUT:"%BIN%\winhttp.dll" "%OBJ%\pch.obj" "%OBJ%\dllmain.obj" Psapi.lib
if errorlevel 1 exit /b 1

if exist "%PROBE_DLL%" copy /Y "%PROBE_DLL%" "%BIN%\RuntimeCaptureProbe.dll"
if errorlevel 1 exit /b 1

copy /Y "%SYSTEM_WINHTTP%" "%BIN%\winhttp_original.dll"
if errorlevel 1 exit /b 1
