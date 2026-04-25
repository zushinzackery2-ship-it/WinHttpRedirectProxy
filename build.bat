@echo off
call "D:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64

set PROJECT_ROOT=%~dp0
set OBJ=%PROJECT_ROOT%..\..\obj\WinHttpRedirectProxy
set BIN=%PROJECT_ROOT%..\..\bin\WinHttpRedirectProxy
set SYSTEM_WINHTTP=%SystemRoot%\System32\winhttp.dll
set PCH=%OBJ%\winhttp_redirect_proxy.pch

if not exist "%OBJ%" mkdir "%OBJ%"
if not exist "%BIN%" mkdir "%BIN%"

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\pch.obj" ^
    /Fp"%PCH%" ^
    /Yc"pch.h" ^
    /c "%PROJECT_ROOT%pch.cpp"
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\dllmain.obj" ^
    /Fp"%PCH%" ^
    /Yu"pch.h" ^
    /c "%PROJECT_ROOT%dllmain.cpp"
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\winhttp_memory_access_core.obj" ^
    /Fp"%PCH%" ^
    /Yu"pch.h" ^
    /c "%PROJECT_ROOT%winhttp_memory_access_core.cpp"
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\winhttp_memory_access_requests.obj" ^
    /Fp"%PCH%" ^
    /Yu"pch.h" ^
    /c "%PROJECT_ROOT%winhttp_memory_access_requests.cpp"
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\winhttp_memory_server.obj" ^
    /Fp"%PCH%" ^
    /Yu"pch.h" ^
    /c "%PROJECT_ROOT%winhttp_memory_server.cpp"
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\winhttp_controller_state.obj" ^
    /Fp"%PCH%" ^
    /Yu"pch.h" ^
    /c "%PROJECT_ROOT%winhttp_controller_state.cpp"
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\winhttp_controller_window.obj" ^
    /Fp"%PCH%" ^
    /Yu"pch.h" ^
    /c "%PROJECT_ROOT%winhttp_controller_window.cpp"
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\winhttp_controller_gui.obj" ^
    /Fp"%PCH%" ^
    /Yu"pch.h" ^
    /c "%PROJECT_ROOT%winhttp_controller_gui.cpp"
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\winhttp_controller.obj" ^
    /Fp"%PCH%" ^
    /Yu"pch.h" ^
    /c "%PROJECT_ROOT%winhttp_controller.cpp"
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE ^
    /Fo"%OBJ%\winhttp_memory_client.obj" ^
    /Fp"%PCH%" ^
    /Yu"pch.h" ^
    /c "%PROJECT_ROOT%winhttp_memory_client.cpp"
if errorlevel 1 exit /b 1

link /nologo /SUBSYSTEM:WINDOWS /MACHINE:X64 /OUT:"%BIN%\winhttp_controller.exe" "%OBJ%\pch.obj" "%OBJ%\winhttp_controller_state.obj" "%OBJ%\winhttp_controller_window.obj" "%OBJ%\winhttp_controller_gui.obj" "%OBJ%\winhttp_controller.obj" Comctl32.lib Comdlg32.lib Advapi32.lib User32.lib Gdi32.lib UxTheme.lib
if errorlevel 1 exit /b 1

link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X64 /OUT:"%BIN%\winhttp_memory_client.exe" "%OBJ%\pch.obj" "%OBJ%\winhttp_memory_client.obj"
if errorlevel 1 exit /b 1

link /nologo /DLL /IGNORE:4222 /MACHINE:X64 /OUT:"%BIN%\winhttp.dll" "%OBJ%\pch.obj" "%OBJ%\dllmain.obj" "%OBJ%\winhttp_memory_access_core.obj" "%OBJ%\winhttp_memory_access_requests.obj" "%OBJ%\winhttp_memory_server.obj" Advapi32.lib
if errorlevel 1 exit /b 1

copy /Y "%SYSTEM_WINHTTP%" "%BIN%\winhttp_original.dll"
if errorlevel 1 exit /b 1

echo Output directory: "%BIN%"
echo Built: "%BIN%\winhttp.dll"
echo Built: "%BIN%\winhttp_original.dll"
echo Built: "%BIN%\winhttp_controller.exe"
echo Built: "%BIN%\winhttp_memory_client.exe"
