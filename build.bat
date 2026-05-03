@echo off
call "D:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64

cd /d "%~dp0"

set OBJ=obj
set BIN=bin
set PCH=%OBJ%\pch.pch

if not exist "%OBJ%" mkdir "%OBJ%"
if not exist "%BIN%" mkdir "%BIN%"

set INC=/I"." /I"common" /I"controller" /I"memory" /I"proxy"

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\pch.obj" /Fp"%PCH%" /Yc"pch.h" /c pch.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\proxy_dllmain.obj" /Fp"%PCH%" /Yu"pch.h" /c proxy\dllmain.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\proxy_redirect_runtime.obj" /Fp"%PCH%" /Yu"pch.h" /c proxy\redirect_runtime.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\memory_access_core.obj" /Fp"%PCH%" /Yu"pch.h" /c memory\memory_access_core.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\memory_access_requests.obj" /Fp"%PCH%" /Yu"pch.h" /c memory\memory_access_requests.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\memory_shared.obj" /Fp"%PCH%" /Yu"pch.h" /c memory\memory_shared.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\memory_module_enum.obj" /Fp"%PCH%" /Yu"pch.h" /c memory\memory_module_enum.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\memory_server.obj" /Fp"%PCH%" /Yu"pch.h" /c memory\memory_server.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\controller_pipe_discovery.obj" /Fp"%PCH%" /Yu"pch.h" /c controller\controller_pipe_discovery.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\controller_view_model.obj" /Fp"%PCH%" /Yu"pch.h" /c controller\controller_view_model.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\controller_state.obj" /Fp"%PCH%" /Yu"pch.h" /c controller\controller_state.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\controller_session.obj" /Fp"%PCH%" /Yu"pch.h" /c controller\controller_session.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\controller_window.obj" /Fp"%PCH%" /Yu"pch.h" /c controller\controller_window.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\controller_window_layout.obj" /Fp"%PCH%" /Yu"pch.h" /c controller\controller_window_layout.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\controller_gui.obj" /Fp"%PCH%" /Yu"pch.h" /c controller\controller_gui.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\controller_entry.obj" /Fp"%PCH%" /Yu"pch.h" /c controller\controller.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\memory_client.obj" /Fp"%PCH%" /Yu"pch.h" /c memory\memory_client.cpp
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DUNICODE /D_UNICODE %INC% /Fo"%OBJ%\cli_controller.obj" /Fp"%PCH%" /Yu"pch.h" /c controller\cli_controller.cpp
if errorlevel 1 exit /b 1

link /nologo /SUBSYSTEM:WINDOWS /MACHINE:X64 /OUT:"%BIN%\winhttp_controller.exe" "%OBJ%\pch.obj" "%OBJ%\controller_pipe_discovery.obj" "%OBJ%\controller_view_model.obj" "%OBJ%\controller_state.obj" "%OBJ%\controller_session.obj" "%OBJ%\controller_window.obj" "%OBJ%\controller_window_layout.obj" "%OBJ%\controller_gui.obj" "%OBJ%\controller_entry.obj" Comctl32.lib Comdlg32.lib Advapi32.lib User32.lib Gdi32.lib UxTheme.lib
if errorlevel 1 exit /b 1

link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X64 /OUT:"%BIN%\winhttp_memory_client.exe" "%OBJ%\pch.obj" "%OBJ%\memory_client.obj"
if errorlevel 1 exit /b 1

link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X64 /OUT:"%BIN%\winhttp_cli_controller.exe" "%OBJ%\pch.obj" "%OBJ%\cli_controller.obj" Advapi32.lib
if errorlevel 1 exit /b 1

link /nologo /DLL /IGNORE:4222 /MACHINE:X64 /OUT:"%BIN%\winhttp.dll" "%OBJ%\pch.obj" "%OBJ%\proxy_dllmain.obj" "%OBJ%\proxy_redirect_runtime.obj" "%OBJ%\memory_access_core.obj" "%OBJ%\memory_access_requests.obj" "%OBJ%\memory_shared.obj" "%OBJ%\memory_module_enum.obj" "%OBJ%\memory_server.obj" Advapi32.lib
if errorlevel 1 exit /b 1

copy /Y "%SystemRoot%\System32\winhttp.dll" "%BIN%\winhttp_original.dll"
if errorlevel 1 exit /b 1

echo.
echo === BUILD SUCCESSFUL ===
